#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

// Function prototypes
ssize_t readn(int fd, void *buf, size_t n);
ssize_t writen(int fd, const void *buf, size_t n);

// Simple message helper
int send_message(int fd, const char *msg);
int recv_message(int fd, char *buffer, size_t size);

#endif
