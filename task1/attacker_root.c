/*
 * attacker_root.c
 * -----------------------------------------------------------------------
 * Attack-resistance test #2: connects to the backend's UNIX domain
 * socket while running AS ROOT (run this one with sudo), sending an
 * otherwise well-formed request. Demonstrates that backend.c's
 * SO_PEERCRED check rejects the connection based on the KERNEL-
 * reported identity of the caller, regardless of what data is sent,
 * and regardless of the fact that the payload itself is well-formed.
 *
 * Expected backend-side result: "rejecting connection: peer is uid 0"
 * logged, connection closed before any privileged file access.
 * -----------------------------------------------------------------------
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCK_PATH "/tmp/authsock"
#define MAX_FIELD 64

typedef struct {
    char username[MAX_FIELD];
    char password[MAX_FIELD];
} auth_request_t;

int main(void) {
    printf("[attacker_root] connecting to %s as uid=%d (should be 0)...\n", SOCK_PATH, getuid());

    if (getuid() != 0) {
        printf("[attacker_root] WARNING: not running as root -- rerun with sudo to actually test this case\n");
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("connect (is backend running?)");
        return 1;
    }

    /* A perfectly well-formed request -- the point is that this
     * doesn't matter, because the rejection happens based on kernel-
     * verified peer identity (SO_PEERCRED) before the payload is
     * even read. */
    auth_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.username, "alice", sizeof(req.username) - 1);
    strncpy(req.password, "hunter2", sizeof(req.password) - 1);

    ssize_t sent = write(fd, &req, sizeof(req));
    printf("[attacker_root] sent %zd bytes of a WELL-FORMED request (username=alice)\n", sent);

    char resp[64];
    ssize_t n = read(fd, resp, sizeof(resp));
    if (n <= 0) {
        printf("[attacker_root] connection closed by backend with no response -- rejected based on peer uid, as expected\n");
    } else {
        printf("[attacker_root] unexpected: got %zd bytes back\n", n);
    }

    close(fd);
    return 0;
}
