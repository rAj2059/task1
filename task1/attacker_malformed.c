/*
 * attacker_malformed.c
 * -----------------------------------------------------------------------
 * Attack-resistance test #1: connects to the backend's UNIX domain
 * socket like a legitimate client, but sends garbage instead of a
 * properly-formed auth_request_t. Demonstrates that the backend
 * validates the SHAPE of incoming data (exact expected size) before
 * doing anything privileged with it, rather than trusting the client.
 *
 * Expected backend-side result: "malformed request" rejection logged,
 * connection closed, no password comparison ever attempted.
 * -----------------------------------------------------------------------
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCK_PATH "/tmp/authsock"

int main(void) {
    printf("[attacker_malformed] connecting to %s as uid=%d...\n", SOCK_PATH, getuid());

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("connect (is backend running?)");
        return 1;
    }

    /* Send a short, wrong-sized, garbage payload instead of a valid
     * auth_request_t (which backend.c expects to be exactly
     * sizeof(auth_request_t) bytes: two 64-byte fields). */
    const char *garbage = "not a real request just garbage bytes";
    ssize_t sent = write(fd, garbage, strlen(garbage));
    printf("[attacker_malformed] sent %zd garbage bytes (expected size mismatch)\n", sent);

    char resp[64];
    ssize_t n = read(fd, resp, sizeof(resp));
    if (n <= 0) {
        printf("[attacker_malformed] connection closed by backend with no response -- rejected as expected\n");
    } else {
        printf("[attacker_malformed] unexpected: got %zd bytes back\n", n);
    }

    close(fd);
    return 0;
}
