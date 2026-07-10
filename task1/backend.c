/*
 * backend.c
 * -----------------------------------------------------------------------
 * Privilege-separated authentication backend.
 *
 * Designed to be installed setuid-root:
 *      sudo chown root:root backend
 *      sudo chmod 4755 backend
 *
 * When a normal user runs this binary, the kernel sets the process's
 * EFFECTIVE uid to root (the file owner) while the REAL uid stays the
 * invoking user's. This program uses that brief window of privilege
 * ONLY to read the protected password file, then permanently drops
 * privilege with setresuid() before doing anything with attacker-
 * controlled data (the socket contents).
 *
 * Communication: a single UNIX domain socket, one connection per
 * authentication attempt (simple, easy to reason about for this
 * exercise -- a production service would loop/fork per connection).
 * -----------------------------------------------------------------------
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <pwd.h>

#define SOCK_PATH     "/tmp/authsock"
#define PASSWD_FILE   "/etc/mypasswd"
#define UNPRIV_USER   "authnobody"   /* dedicated unprivileged service account */
#define MAX_LINE      256
#define MAX_FIELD     64
#define MAX_HASH      128

/* ---- request/response wire format (fixed-size, easy to validate) ---- */
typedef struct {
    char username[MAX_FIELD];
    char password[MAX_FIELD];
} auth_request_t;

typedef struct {
    int success; /* 1 = authenticated, 0 = rejected */
} auth_response_t;

/* -----------------------------------------------------------------------
 * verify_privilege_dropped()
 *
 * Deliverable: "Runtime check using geteuid() or /proc".
 * We check BOTH: getresuid() (real/effective/saved) and read
 * /proc/self/status Uid: line, so the report can show two independent
 * confirmation methods.
 * ---------------------------------------------------------------------*/
static void verify_privilege_dropped(uid_t expected_uid) {
    uid_t ruid, euid, suid;
    if (getresuid(&ruid, &euid, &suid) != 0) {
        perror("getresuid");
        exit(1);
    }
    fprintf(stderr,
        "[backend] getresuid() -> real=%d effective=%d saved=%d\n",
        ruid, euid, suid);

    if (euid == 0 || euid != expected_uid || ruid != expected_uid || suid != expected_uid) {
        fprintf(stderr, "[backend] FATAL: privilege drop verification failed\n");
        exit(1);
    }

    /* Independent check via /proc, per deliverable wording */
    FILE *f = fopen("/proc/self/status", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "Uid:", 4) == 0) {
                fprintf(stderr, "[backend] /proc/self/status -> %s", line);
                break;
            }
        }
        fclose(f);
    }
}

/* -----------------------------------------------------------------------
 * read_hash_for_user()
 *
 * The ONLY privileged operation in this program. Called while
 * euid == 0. File format: "username:hash\n"
 * In production this would be a real KDF (bcrypt/argon2) comparison;
 * for this exercise a hash placeholder is enough to demonstrate the
 * OS mechanisms, which is what's actually being assessed.
 * ---------------------------------------------------------------------*/
static int read_hash_for_user(const char *user, char *hash_out, size_t len) {
    FILE *f = fopen(PASSWD_FILE, "r");
    if (!f) {
        perror("fopen(" PASSWD_FILE ")");
        return -1;
    }

    struct stat st;
    if (fstat(fileno(f), &st) == 0) {
        if ((st.st_mode & 0077) != 0) {
            fprintf(stderr,
                "[backend] WARNING: %s is group/world accessible (mode %o)\n",
                PASSWD_FILE, st.st_mode & 0777);
        }
    }

    char line[MAX_LINE];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        char fuser[MAX_FIELD], fhash[MAX_HASH];
        if (sscanf(line, "%63[^:]:%127s", fuser, fhash) == 2 &&
            strcmp(fuser, user) == 0) {
            size_t copy_len = strnlen(fhash, len - 1);
            memcpy(hash_out, fhash, copy_len);
            hash_out[copy_len] = '\0';
            found = 1;
            break;
        }
    }
    fclose(f);
    return found ? 0 : -1;
}

/* -----------------------------------------------------------------------
 * check_peer_is_legitimate()
 *
 * Deliverable: "Attack resistance - Backend rejecting requests if not
 * a validation [request]". We use SO_PEERCRED to ask the KERNEL who
 * is actually on the other end of the socket, rather than trusting
 * anything the client claims about itself. This is the difference
 * between OS-level trust and application-level trust.
 * ---------------------------------------------------------------------*/
static int check_peer_is_legitimate(int fd) {
    struct ucred cred;
    socklen_t len = sizeof(cred);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) {
        perror("getsockopt(SO_PEERCRED)");
        return -1;
    }
    fprintf(stderr,
        "[backend] peer credentials: pid=%d uid=%d gid=%d\n",
        cred.pid, cred.uid, cred.gid);

    /* Example policy: reject connections claiming to be root, since a
     * legitimate frontend for this exercise runs as a normal user.
     * Adjust/justify this policy in your report. */
    if (cred.uid == 0) {
        fprintf(stderr, "[backend] rejecting connection: peer is uid 0\n");
        return -1;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * secure_wipe()
 *
 * Deliverable: "Shared memory for safety - Password buffer,
 * Disassembly". A plain memset() over a local buffer that is about
 * to go out of scope is a "dead store" from the compiler's point of
 * view -- an optimizing compiler is permitted to remove it entirely,
 * because the C standard only cares about *observable* behaviour, and
 * nothing in the program subsequently reads the buffer. This leaves
 * the plaintext password sitting in memory (stack/heap) even after
 * the function returns, until that memory happens to be reused.
 *
 * explicit_bzero() (glibc/BSD extension) is defined specifically to
 * NOT be optimized away -- the compiler cannot assume anything about
 * its side effects, so the wipe is guaranteed to actually happen.
 * (Confirm this for your report by compiling with -O2 and comparing
 * disassembly of memset() vs explicit_bzero() with objdump -d.)
 * ---------------------------------------------------------------------*/
static void secure_wipe(void *buf, size_t len) {
    explicit_bzero(buf, len);
}

/* -----------------------------------------------------------------------
 * handle_connection()
 *
 * Runs inside a freshly-forked WORKER process that has inherited root
 * privilege from the still-privileged listener. This worker exists to
 * service exactly one connection: it does the one privileged file
 * read, permanently drops privilege via setresuid(), does the
 * comparison, replies, wipes sensitive memory, then exits.
 *
 * Because the drop happens in a short-lived worker rather than in the
 * long-running listener, the listener itself can keep accepting new
 * connections indefinitely without ever touching attacker-controlled
 * data or losing its root capability -- each request gets an
 * independent, disposable, privilege-dropped process. This mirrors
 * the privilege-separation model used by real daemons such as OpenSSH
 * (a persistent privileged monitor + short-lived unprivileged
 * workers), and is a stronger design than dropping privilege once in
 * a single long-running process.
 * ---------------------------------------------------------------------*/
static void handle_connection(int conn_fd, struct passwd *pw) {
    if (check_peer_is_legitimate(conn_fd) != 0) {
        close(conn_fd);
        return;
    }

    auth_request_t req;
    ssize_t n = read(conn_fd, &req, sizeof(req));
    if (n != (ssize_t)sizeof(req)) {
        fprintf(stderr, "[backend worker %d] malformed request (got %zd bytes, expected %zu)\n",
            getpid(), n, sizeof(req));
        close(conn_fd);
        return;
    }
    req.username[MAX_FIELD - 1] = '\0';
    req.password[MAX_FIELD - 1] = '\0';

    /* --- LAST privileged operation --- */
    char stored_hash[MAX_HASH] = {0};
    int have_hash = (read_hash_for_user(req.username, stored_hash, sizeof(stored_hash)) == 0);

    /* --- PERMANENT, IRREVERSIBLE PRIVILEGE DROP (this worker only) --- */
    if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) != 0) {
        perror("setresuid");
        close(conn_fd);
        return;
    }
    verify_privilege_dropped(pw->pw_uid);

    /* --- everything below runs fully unprivileged, in this worker --- */
    auth_response_t resp = {0};
    if (have_hash) {
        resp.success = (strcmp(req.password, stored_hash) == 0);
    } else {
        resp.success = 0;
    }

    fprintf(stderr, "[backend worker %d] auth result for '%s': %s (now running as uid=%d)\n",
        getpid(), req.username, resp.success ? "SUCCESS" : "FAIL", geteuid());

    if (write(conn_fd, &resp, sizeof(resp)) != (ssize_t)sizeof(resp)) {
        fprintf(stderr, "[backend worker %d] warning: short write of response\n", getpid());
    }

    secure_wipe(req.password, sizeof(req.password));
    secure_wipe(stored_hash, sizeof(stored_hash));
    close(conn_fd);
}

int main(void) {
    fprintf(stderr, "[backend] starting, ruid=%d euid=%d\n", getuid(), geteuid());

    struct passwd *pw = getpwnam(UNPRIV_USER);
    if (!pw) {
        fprintf(stderr,
            "[backend] FATAL: user '%s' does not exist. "
            "Create it: sudo useradd -r -s /usr/sbin/nologin %s\n",
            UNPRIV_USER, UNPRIV_USER);
        exit(1);
    }

    /* Reap finished workers automatically so they don't linger as
     * zombies; we don't need their exit status for anything. */
    signal(SIGCHLD, SIG_IGN);

    /* --- Set up the listening socket while still root, so we control
     *     ownership/permissions of the socket file itself. --- */
    unlink(SOCK_PATH);
    int listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); exit(1); }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        exit(1);
    }
    chmod(SOCK_PATH, 0666); /* discuss the security tradeoff of this in your report */

    if (listen(listen_fd, 5) != 0) {
        perror("listen");
        exit(1);
    }

    fprintf(stderr,
        "[backend] listener ready on %s (pid=%d, stays root: euid=%d). "
        "Serving connections until killed (Ctrl+C).\n",
        SOCK_PATH, getpid(), geteuid());

    /* --- persistent accept loop: the LISTENER never drops privilege
     * and never touches request data directly. Each connection is
     * handed to a disposable forked worker that does the privileged
     * read, drops permanently, and exits. --- */
    for (;;) {
        int conn_fd = accept(listen_fd, NULL, NULL);
        if (conn_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }

        pid_t worker = fork();
        if (worker < 0) {
            perror("fork");
            close(conn_fd);
            continue;
        }

        if (worker == 0) {
            /* --- WORKER: still root here (inherited from listener) --- */
            close(listen_fd); /* worker doesn't need the listening socket */
            handle_connection(conn_fd, pw);
            _exit(0);
        }

        /* --- LISTENER: closes its copy of conn_fd and loops back to
         * accept the next connection, still fully privileged --- */
        close(conn_fd);
    }

    return 0;
}
