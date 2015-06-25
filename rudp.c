#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
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
  R_CLOSING,
  R_TERM
} rudp_state;

typedef struct {
  rudp_state state;
  int world;    // our bound socket
  int user;     // interthread communication socket
  int internal; // pipe from world to user
  pthread_mutex_t sync;
  pthread_cond_t close;

  // connection fields, only filled in for CONNECTED sockets
  uint16_t seq;
  uint16_t ack;
  uint16_t rseq;
  time_t last_heard;
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
pthread_rwlock_t glock = PTHREAD_RWLOCK_INITIALIZER;

// real crash only assert
#define check(err) if(!(err)) { fprintf(stderr, "assertion \"%s\" failed: file \"%s\", line %d\n", "expression", __FILE__, __LINE__); abort(); }

static void
global_read_lock() {
  check(pthread_rwlock_rdlock(&glock) == 0);
}

static void
global_unlock() {
  check(pthread_rwlock_unlock(&glock) == 0);
}

static void
global_write_lock() {
  check(pthread_rwlock_wrlock(&glock) == 0);
}

static void
socket_lock(rudp_socket_t *s) {
  check(pthread_mutex_lock(&s->sync) == 0);
}

static void
socket_unlock(rudp_socket_t *s) {
  check(pthread_mutex_unlock(&s->sync) == 0);
}

static void
socket_wait(rudp_socket_t *s) {
  check(pthread_cond_wait(&s->close, &s->sync) == 0);
}

static void
socket_signal(rudp_socket_t *s) {
  check(pthread_cond_signal(&s->close) == 0);
}

// the whole shebang really -- this should be broken up and cleaned up
static void *
runloop(void *arg) {
  while(1) {
    // we lock here to make a copy of our open sockets
    global_read_lock();
    if(self.nsocks == 0) {
      global_unlock();
      return NULL;
    }
    struct pollfd fds[self.nsocks];
    struct pollfd chans[self.nsocks];
    for(int i = 0; i < self.nsocks; i++) {
      fds[i].fd = self.socks[i]->world;
      fds[i].events = POLLIN | POLLOUT;
      chans[i].fd = self.socks[i]->internal;
      chans[i].events = POLLIN | POLLOUT;
    }

    poll(fds, self.nsocks, 100);
    poll(chans, self.nsocks, 100);

    for(int i = 0; i < self.nsocks; i++) {
      socket_lock(self.socks[i]);
      switch(self.socks[i]->state) {
        case R_CLOSING:
          send_close(self.socks[i]);
          self.socks[i]->state = R_TERM;
          socket_signal(self.socks[i]);
          socket_unlock(self.socks[i]);
          break;
        case R_CONNECTING:
          if(fds[i].revents | POLLIN) {
            char
          } else {

          }
          break;
        case R_LISTENING:
        case R_CONNECTED:
          if(fds[i].revents | POLLIN && chans[i].revents | POLLOUT)
            do_recv(self.socks[i]);

          if(fds[i].revents | POLLOUT && chans[i].revents | POLLIN)
            do_send(self.socks[i]);
          break;
        case R_TERM:
          // not deleted yet, fall through
        case R_NONE:
          // not connected yet
          break;
      }
      socket_unlock(self.socks[i]);
    }
    global_unlock();
  }
}


static void
rudp_global_init() {
  // always called with write lock held
  if(self.socks != NULL)
    return;

  self.socks  = (rudp_socket_t **) calloc(RUDP_MAX_SOCKETS, sizeof(rudp_socket_t *));
  self.unused = (uint16_t *) calloc(RUDP_MAX_SOCKETS, sizeof(uint16_t));
  for(uint16_t i = 0; i != RUDP_MAX_SOCKETS; ++i)
    self.unused[i] = (uint16_t) (RUDP_MAX_SOCKETS - i - 1);

  // off to the races
  pthread_create(&self.worker, NULL, &runloop, NULL);
}

int
rudp_socket(int type) {
  global_write_lock();
  rudp_global_init();

  if(self.nsocks >= RUDP_MAX_SOCKETS){
    errno = EMFILE;
    return -1;
  }

  int lfd = socket(type, SOCK_DGRAM, 0);
  if(lfd < 0) { return -1; }

  int pair[2];
  int err = socketpair(AF_UNIX, SOCK_DGRAM, 0, pair);
  if(err < 0) { close(lfd);  return -1; }

  int fd = self.unused[RUDP_MAX_SOCKETS - self.nsocks - 1];

  rudp_socket_t *sock = (rudp_socket_t  *) calloc(1, sizeof(rudp_socket_t));
  err = pthread_mutex_init(&sock->sync, NULL);
  check(err == 0);
  err = pthread_cond_wait(&sock->close, NULL);
  check(err == 0);
  self.nsocks++;
  self.socks[fd] = sock;
  self.socks[fd]->world = lfd;
  self.socks[fd]->user = pair[0];
  self.socks[fd]->internal = pair[1];
  global_unlock();

  return fd;
}

#define BASIC_CHECKS if(fd >= RUDP_MAX_SOCKETS || fd >= self.nsocks || self.socks[fd] == NULL){ \
  errno = EBADF; \
  return -1; \
}

int
rudp_close(int fd) {
  global_read_lock();
  BASIC_CHECKS
  rudp_socket_t *s = self.socks[fd];

  socket_lock(s);
  if(s->state != R_TERM)
    s->state = R_CLOSING;
  while(s->state != R_TERM) {
    socket_wait(s);
  }
  socket_unlock(s);
  global_unlock();

  global_write_lock();
  if(self.socks[fd] != NULL) {
    close(self.socks[fd]->world);
    close(self.socks[fd]->user);
    close(self.socks[fd]->internal);
    free(self.socks[fd]);
    self.socks[fd] = NULL;
    self.unused[RUDP_MAX_SOCKETS - self.nsocks] = (uint16_t) fd;
    self.nsocks--;
    if(self.nsocks == 0) {
      free(self.socks);
      self.socks = NULL;
    }
  }
  global_unlock();

  return 0;
}

int
rudp_bind(int fd, const struct sockaddr *address, socklen_t address_len) {
  global_read_lock();
  BASIC_CHECKS

  rudp_socket_t *s = self.socks[fd];

  socket_lock(s);
  int rc = bind(s->world, address, address_len);
  if(rc < -1) { s->world = 0; socket_unlock(s); return -1; }
  s->state = R_LISTENING;
  socket_unlock(s);
  global_unlock();

  return 0;
}

#define SIZE_CHECK if(length > RUDP_DATA_SIZE) { \
  errno = EMSGSIZE; \
  return -1; \
}

ssize_t
rudp_send(int fd, const void *data, size_t length, int flags) {
  global_read_lock();
  BASIC_CHECKS
  SIZE_CHECK

  ssize_t rc = send(self.socks[fd]->user, data, length, 0);
  global_unlock();
  return rc;
}

ssize_t
rudp_recv(int fd, void *data, size_t length, int flags) {
  global_read_lock();
  BASIC_CHECKS
  SIZE_CHECK

  ssize_t rc = recv(self.socks[fd]->user, data, length, 0);
  global_unlock();
  return rc;
}

#undef BASIC_CHECKS
#undef SIZE_CHECK