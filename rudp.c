#include <arpa/inet.h>
#include <memory.h>
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <unistd.h>
#include "rudp.h"
#include "tweetnacl.h"

// handshake
const uint8_t RUDP_HELLO = (1 << 0); // client -> server
const uint8_t RUDP_HI    = (1 << 1); // server -> client
const uint8_t RUDP_INIT  = (1 << 2); // client -> server
const uint8_t RUDP_BYE   = (1 << 3); // close
const uint8_t RUDP_DATA  = (1 << 4); // encrypted data

#define RUDP_SECRET_SIZE 1088 - 2 - crypto_box_NONCEBYTES - crypto_box_PUBLICKEYBYTES
typedef struct {
  uint8_t proto;
  uint8_t version;
  uint8_t pk[crypto_box_PUBLICKEYBYTES];
  uint8_t nonce[crypto_box_NONCEBYTES];
  uint8_t encrypted[RUDP_SECRET_SIZE]; // always encrypted
} __attribute__((packed)) rudp_packet_t;

#define RUDP_DATA_SIZE RUDP_SECRET_SIZE - 4 - crypto_box_ZEROBYTES
typedef struct {
  uint8_t padding[crypto_box_ZEROBYTES];
  uint16_t ack;
  uint16_t seq;
  uint8_t data[RUDP_DATA_SIZE];
} __attribute__((packed)) rudp_secret_t;

typedef enum {
  R_NONE = 0,
  R_LISTENING,
  R_CONNECTING,
  R_CONNECTED,
  R_TERM
} rudp_state;

typedef struct {
  rudp_state state;
  int out;  // our bound socket
  int read; // interthread communication socket
  int write;
  pthread_mutex_t sync;

  // connection fields, only filled in for CONNECTED sockets
  uint16_t seq;
  uint16_t ack;
  uint16_t rseq;
  uint8_t their_key[crypto_box_PUBLICKEYBYTES];
  uint8_t pk[crypto_box_PUBLICKEYBYTES];
  uint8_t sk[crypto_box_SECRETKEYBYTES];
} rudp_socket_t;

#define RUDP_MAX_SOCKETS FD_SETSIZE
typedef struct {
  // listening sockets
  rudp_socket_t **socks;
  uint16_t nsocks;
  // idea stolen from how nanomsg handles it
  uint16_t *unused;
  pthread_t worker;
  // for encrypting cookie packets rotates every 2 minutes
  uint8_t cpk[crypto_box_PUBLICKEYBYTES];
  uint8_t csk[crypto_box_SECRETKEYBYTES];
  time_t last_update;
  int init;
} rudp_global_t;

rudp_global_t self = {0};
pthread_mutex_t glock = PTHREAD_MUTEX_INITIALIZER;

// real assert
#define check(err) if(!(err)) { fprintf(stderr, "assertion \"%s\" failed: file \"%s\", line %d\n", "expression", __FILE__, __LINE__); abort(); }


static void
global_lock() {
  check(pthread_mutex_lock(&glock) == 0);
}

static void
global_unlock() {
  check(pthread_mutex_unlock(&glock) == 0);
}

// the whole shebang really -- this should be broken up and cleaned up
static void *
runloop(void *arg) {
  while(1) {
    // we lock here to make a copy of our open sockets
    global_lock();
    int nsocks = self.nsocks;
    struct pollfd fds[nsocks];
    struct pollfd chans[nsocks];

    for(int i = 0; i < nsocks; i++) {
      fds[i].fd = self.socks[i]->out;
      fds[i].events = POLLIN | POLLOUT;
      chans[i].fd = self.socks[i]->write;
      chans[i].events = POLLIN | POLLOUT;
    }
    global_lock();

    poll(fds, nsocks, 1000 * 60);
    poll(chans, nsocks, 1000 * 60);

    global_lock();
    for(int i = 0; i < nsocks; i++) {
      char data[RUDP_DATA_SIZE];
      size_t length = RUDP_DATA_SIZE;

      // CLOSED SOCKET
      if(self.socks[i] == NULL)
        continue;

      // BAD_SOCKET
      if(self.socks[i]->state == R_NONE)
        continue; // set errors

      if(fds[i].revents | POLLIN && chans[i].revents | POLLOUT) {
        do_recv(self.socks[i], &data, &length);
        send(self.socks[i]->out->fd, data, length, 0);
      }

      if(fds[i].revents | POLLOUT && chans[i].revents | POLLIN) {
        recv(self.socks[i]->out->fd, &data, length, 0);
        do_send(self.socks[i], data, length);
      }
    }
    global_unlock();
  }
}


static void
rudp_global_init() {
  if(self.socks)
    return;

  self.socks  = (rudp_socket_t **) calloc(RUDP_MAX_SOCKETS, sizeof(rudp_socket_t *));
  self.unused = (uint16_t *) calloc(RUDP_MAX_SOCKETS, sizeof(uint16_t));
  for(uint16_t i = 0; i != RUDP_MAX_SOCKETS; ++i)
    self.unused[i] = RUDP_MAX_SOCKETS - i - 1;

  // off to the races
  pthread_create(&self.worker, NULL, &runloop, NULL);
}

int
rudp_socket(int type) {
  if(self.nsocks >= RUDP_MAX_SOCKETS){
    errno = EMFILE;
    return -1;
  }

  global_lock();
  rudp_global_init();

  int lfd = socket(type, SOCK_DGRAM, 0);
  if(lfd < 0) { global_unlock(); return -1; }

  int pair[2];
  int err = socketpair(AF_UNIX, SOCK_DGRAM, 0, pair);
  if(err < 0) { global_unlock(); close(lfd);  return -1; }

  int fd = self.unused[RUDP_MAX_SOCKETS - self.nsocks - 1];
  self.socks[fd] = (rudp_socket_t  *) calloc(1, sizeof(rudp_socket_t));
  self.nsocks++;

  self.socks[fd]->out   = lfd;
  self.socks[fd]->read  = pair[0];
  self.socks[fd]->write = pair[1];
  global_unlock();

  return fd;
}

int
rudp_close(int fd) {
  if(fd >= RUDP_MAX_SOCKETS || fd >= self.nsocks || self.socks[fd] == NULL){
    errno = EBADF;
    return -1;
  }

  global_lock();
  // TODO: wait until it flushes
  // socket_term(self.socks[fd]);
  free(self.socks[fd]);
  self.socks[fd] = NULL;
  self.unused[RUDP_MAX_SOCKETS - self.nsocks] = fd;
  self.nsocks--;
  global_unlock();

  return 0;
}

int
rudp_bind(int fd, const struct sockaddr *address, socklen_t address_len) {
  if(fd >= RUDP_MAX_SOCKETS || fd >= self.nsocks || self.socks[fd] == NULL){
    errno = EBADF;
    return -1;
  }

  global_lock();
  rudp_socket_t *s = self.socks[fd];
  int rc = bind(s->out, address, address_len);
  if(rc < -1) { global_unlock(); return -1; }
  global_unlock();

  return 0;
}

