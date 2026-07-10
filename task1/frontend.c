/*
 * frontend.c
 * -----------------------------------------------------------------------
 * Unprivileged frontend for the authentication service.
 *
 * Runs as a normal user, with normal user privileges, always. It never
 * touches the password store and never gains elevated rights. Its only
 * job: collect credentials from the user and relay them to backend
 * over a UNIX domain socket, then report the result.
 *
 * If this process is compromised (e.g. a buffer overflow from crafted
 * input), the attacker gains nothing more than the invoking user
 * already had -- this is the whole point of the isolation.
 * -----------------------------------------------------------------------
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCK_PATH  "/tmp/authsock"
#define MAX_FIELD  64

typedef struct {
    char username[MAX_FIELD];
    char password[MAX_FIELD];
} auth_request_t;

typedef struct {
    int success;
} auth_response_t;

/* Disable terminal echo while the password is typed. Not the focus of
 * the assignment, but worth having so demo runs don't show the
 * password on screen -- mention briefly in your report if you like. */
static void read_password_hidden(char *buf, size_t len) {
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    if (fgets(buf, (int)len, stdin) == NULL) buf[0] = '\0';
    buf[strcspn(buf, "\n")] = '\0';

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");
}

int main(void) {
    printf("[frontend] running as uid=%d euid=%d (unprivileged)\n", getuid(), geteuid());

    auth_request_t req;
    memset(&req, 0, sizeof(req));

    printf("Username: ");
    if (fgets(req.username, sizeof(req.username), stdin) == NULL) {
        fprintf(stderr, "input error\n");
        return 1;
    }
    req.username[strcspn(req.username, "\n")] = '\0';

    printf("Password: ");
    fflush(stdout);
    read_password_hidden(req.password, sizeof(req.password));

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("connect (is backend running?)");
        return 1;
    }

    if (write(fd, &req, sizeof(req)) != (ssize_t)sizeof(req)) {
        perror("write");
        close(fd);
        return 1;
    }

    auth_response_t resp;
    ssize_t n = read(fd, &resp, sizeof(resp));
    close(fd);

    /* Wipe our own copy of the password -- same reasoning as backend.c */
    explicit_bzero(req.password, sizeof(req.password));

    if (n != (ssize_t)sizeof(resp)) {
        fprintf(stderr, "[frontend] backend gave no/short response\n");
        return 1;
    }

    printf("Authentication %s\n", resp.success ? "SUCCESSFUL" : "FAILED");
    return resp.success ? 0 : 1;
}
