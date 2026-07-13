#include <string.h>
void wipe_with_memset(void) {
    char buf[64];
    strcpy(buf, "supersecretpassword");
    memset(buf, 0, sizeof(buf));   // may be optimized away: buf is dead after this
}
void wipe_with_explicit_bzero(void) {
    char buf[64];
    strcpy(buf, "supersecretpassword");
    explicit_bzero(buf, sizeof(buf));  // guaranteed to happen
}
