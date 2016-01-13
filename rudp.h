#pragma once

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>


int rudp_socket(int type);
int rudp_close(int fd);
int rudp_bind(int fd, const struct sockaddr *address, socklen_t address_len);
int rudp_listen(int fd, int backlog);
int rudp_connect(int fd, const struct sockaddr *addr, socklen_t address_len);
int rudp_accept(int fd, struct sockaddr *address, socklen_t *address_len);
ssize_t rudp_send(int fd, const void *data, size_t length, int flags);
ssize_t rudp_recv(int fd, void *data, size_t length, int flags);
int rudp_setsockopt(int fd, const void *data, size_t length);
int rudp_getsockopt(int fd, const void *data, size_t length);
// int
// rudp_poll(); <- think about this one
