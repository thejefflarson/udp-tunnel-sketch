#include <stdlib.h>

int rudp_socket();
int rudp_close(int fd);
int rudp_listen(int fd, int backlog);
int rudp_connect(int fd, struct sockaddr *addr, int port);
int rudp_accept(int fd);
int rudp_send(int fd, const void *data, size_t length, int flags);
int rudp_recv(int fd, void *data, size_t lengt, int flags);
int rudp_setsockopt(int fd, const void *data, size_t length);
int rudp_getsockopt(int fd, const void *data, size_t length);
// int
// rudp_poll(); <- think about this one
