#include "protocol.h"

ssize_t readn(int fd, void *buf, size_t n) {
    size_t left = n;
    ssize_t r;
    char *ptr = buf;

    while (left > 0) {
        if ((r = read(fd, ptr, left)) <= 0) {
            if (r < 0 && errno == EINTR) r = 0; // retry
            else return -1;
        }
        else if (r == 0) break; // EOF
        left -= r;
        ptr += r;
    }
    return (n - left);
}

ssize_t writen(int fd, const void *buf, size_t n) {
    size_t left = n;
    ssize_t w;
    const char *ptr = buf;

    while (left > 0) {
        if ((w = write(fd, ptr, left)) <= 0) {
            if (w < 0 && errno == EINTR) w = 0; // retry
            else return -1;
        }
        left -= w;
        ptr += w;
    }
    return n;
}

int send_message(int fd, const char *msg) {
    uint32_t len = htonl(strlen(msg));  // 4-byte length prefix
    if (writen(fd, &len, sizeof(len)) != sizeof(len)) return -1;
    if (writen(fd, msg, strlen(msg)) != (ssize_t)strlen(msg)) return -1;
    return 0;
}

int recv_message(int fd, char *buffer, size_t size) {
    uint32_t len;
    if (readn(fd, &len, sizeof(len)) != sizeof(len)) return -1;
    len = ntohl(len);
    if (len >= size) len = size - 1; // prevent overflow
    if (readn(fd, buffer, len) != (ssize_t)len) return -1;
    buffer[len] = '\0';
    return 0;
}
