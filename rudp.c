#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rudp.h"
#include "tweetnacl.h"

// handshake
const uint8_t RUDP_HELLO  = (1 << 0); // client -> server
const uint8_t RUDP_COOKIE = (1 << 1); // server -> client
const uint8_t RUDP_INIT   = (1 << 2); // client -> server
const uint8_t RUDP_DATA   = (1 << 3); // encrypted data
const uint8_t RUDP_BYE    = (1 << 4); // close

#define RUDP_SECRET_SIZE 1088 - 2 - crypto_box_NONCEBYTES - crypto_box_PUBLICKEYBYTES
typedef struct {
  uint8_t proto;
  uint8_t version;
  uint8_t pk[crypto_box_PUBLICKEYBYTES];
  uint8_t nonce[crypto_box_NONCEBYTES];
  uint8_t encrypted[RUDP_SECRET_SIZE]; // always encrypted
} __attribute__((packed)) rudp_packet_t;

#define RUDP_DATA_SIZE RUDP_SECRET_SIZE - 8 - crypto_box_ZEROBYTES
typedef struct {
  uint8_t padding[crypto_box_ZEROBYTES];
  uint32_t ack;
  uint32_t seq;
  uint8_t data[RUDP_DATA_SIZE];
} __attribute__((packed)) rudp_secret_t;

typedef enum {
  R_NONE = 0,
  R_BOUND,
  R_LISTENING,
  R_CONNECTING,
  R_CONNECTED,
  R_CLOSING,
  R_TERM,
  R_ERROR
} rudp_state;

typedef struct {
  rudp_state state;
  int world;    // our bound socket
  int user;     // interthread communication socket
  int internal; // pipe from world to user
  pthread_mutex_t sync;
  pthread_cond_t close;
  pthread_cond_t conn;

  // connection fields, only filled in for CONNECTED sockets
  uint16_t seq;
  uint16_t ack;
  uint16_t rseq;
  time_t last_heard;
  time_t last_sent;
  uint8_t their_longkey[crypto_box_PUBLICKEYBYTES];
  uint8_t their_shortkey[crypto_box_PUBLICKEYBYTES];
  uint8_t pk[crypto_box_PUBLICKEYBYTES];
  uint8_t sk[crypto_box_SECRETKEYBYTES];
  // for encrypting cookie packets rotates every 2 minutes
  uint8_t cpk[crypto_box_PUBLICKEYBYTES];
  uint8_t csk[crypto_box_SECRETKEYBYTES];
} rudp_socket_t;

#define RUDP_MAX_SOCKETS FD_SETSIZE
typedef struct {
  // listening sockets
  rudp_socket_t **socks;
  uint16_t nsocks;
  // idea stolen from how nanomsg handles it
  uint16_t *unused;
  pthread_t worker;
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
socket_wait_close(rudp_socket_t *s) {
  check(pthread_cond_wait(&s->close, &s->sync) == 0);
}

static void
socket_wait_conn(rudp_socket_t *s) {
  check(pthread_cond_wait(&s->conn, &s->sync) == 0);
}

static void
socket_signal_close(rudp_socket_t *s) {
  check(pthread_cond_broadcast(&s->close) == 0);
}

static void
socket_signal_conn(rudp_socket_t *s) {
  check(pthread_cond_broadcast(&s->conn) == 0);
}

static int
create_socket(int domain) {
  if(self.nsocks >= RUDP_MAX_SOCKETS){
    errno = EMFILE;
    return -1;
  }

  if(domain != AF_INET || domain != AF_INET6) {
    errno = EAFNOSUPPORT;
    return -1;
  }

  int lfd = socket(domain, SOCK_DGRAM, 0);
  if(lfd < 0) { return -1; }

  int pair[2];
  int err = socketpair(AF_UNIX, SOCK_DGRAM, 0, pair);
  if(err < 0) { close(lfd);  return -1; }

  int fd = self.unused[RUDP_MAX_SOCKETS - self.nsocks - 1];

  rudp_socket_t *sock = (rudp_socket_t *) calloc(1, sizeof(rudp_socket_t));
  err = pthread_mutex_init(&sock->sync, NULL);
  check(err == 0);
  self.nsocks++;
  self.socks[fd] = sock;
  self.socks[fd]->world = lfd;
  self.socks[fd]->user = pair[0];
  self.socks[fd]->internal = pair[1];
  self.socks[fd]->last_heard = 0;
  crypto_box_keypair(sock->pk, sock->sk);
  crypto_box_keypair(sock->cpk, sock->csk);
  return fd;
}

static void
do_connect(rudp_socket_t *sock, short revents) {
  if(revents & POLLIN) {
    rudp_packet_t data;
    ssize_t size = recv(sock->world, &data, sizeof(data), 0);
    if(size != sizeof(data)) return;
    if(data.proto != RUDP_COOKIE) return;
    if(crypto_verify_32(sock->their_longkey, data.pk)) return;
    rudp_secret_t secret;
    memset(&secret, 0, sizeof(secret));
    int err = crypto_box_open((uint8_t *)&secret, data.encrypted, RUDP_SECRET_SIZE, data.nonce, data.pk, sock->sk);
    if(!err) return;
    if(crypto_verify_32(sock->pk, secret.data + crypto_box_PUBLICKEYBYTES)) return;
    memcpy(sock->their_shortkey, secret.data, crypto_box_PUBLICKEYBYTES);
    memcpy(secret.data, sock->pk, crypto_box_PUBLICKEYBYTES);
    rudp_secret_t ret;
    memset(&ret, 0, sizeof(ret));
    secret.seq = 1;
    secret.ack = 1;
    randombytes(data.nonce, crypto_box_NONCEBYTES);
    randombytes(ret.data, RUDP_SECRET_SIZE);
    crypto_box((uint8_t *)&ret, (uint8_t *)&secret, RUDP_SECRET_SIZE, data.nonce, sock->their_shortkey, sock->sk);
    memcpy(data.encrypted, &ret, sizeof(ret));
    memcpy(data.pk, sock->pk, crypto_box_PUBLICKEYBYTES);
    data.proto = RUDP_INIT;
    send(sock->world, &data, sizeof(data), 0);
    sock->state = R_CONNECTED;
    socket_signal_conn(sock);
  } else if(sock->last_heard == 0 || (time(NULL) - sock->last_sent > 50 && sock->last_heard - time(NULL) < 60000)) {
    // (re)send a connection attempt
    rudp_packet_t data;
    data.proto = RUDP_HELLO;
    crypto_box_keypair(sock->pk, sock->sk);
    memcpy(data.pk, sock->pk, crypto_box_PUBLICKEYBYTES);
    randombytes(data.nonce, crypto_box_NONCEBYTES);
    randombytes(data.encrypted, RUDP_SECRET_SIZE);
    send(sock->world, &data, sizeof(data), 0);
  } else if(sock->last_heard - time(NULL) > 60000) {
    // etimeout
    sock->state = R_ERROR;
  }
}

static void
do_accept(rudp_socket_t *sock, short revents) {
  if(revents & POLLIN) {
    rudp_packet_t data;
    struct sockaddr addr;
    socklen_t len;
    ssize_t size = recvfrom(sock->world, &data, sizeof(data), 0, &addr, &len);
    if(size != sizeof(data))  return;
    switch(data.proto) {
      case RUDP_HELLO: {
        rudp_packet_t data;
        uint8_t pk[crypto_box_PUBLICKEYBYTES], sk[crypto_box_SECRETKEYBYTES];
        crypto_box_keypair(pk, sk);
        memcpy(data.pk, sock->pk, crypto_box_PUBLICKEYBYTES);

        break;
      }
      case RUDP_INIT: {
        global_write_lock();
        int fd = create_socket(addr.sa_family);
        global_unlock();
        if(fd == -1) return;
        // needs error checks
        rudp_socket_t *new_sock = self.socks[fd];
        connect(new_sock->world, &addr, len);
        struct sockaddr original;
        socklen_t len = sizeof(original);
        getsockname(new_sock->world, &original, &len);
        bind(new_sock->world, &original, len);
        send(sock->internal, &fd, sizeof(fd), 0);
        break;
      }
    }
  }
}

static void
do_send(rudp_socket_t *sock, short internal, short world) {

}

static void
do_recv(rudp_socket_t *sock, short internal, short world) {

}

static void
send_close(rudp_socket_t *sock) {

}

// the whole shebang really -- this should be broken up and cleaned up
static void *
runloop(void *arg) {
  while(1) {
    global_read_lock();
    if(self.nsocks == 0) {
      global_unlock();
      return NULL;
    }
    struct pollfd fds[self.nsocks];
    struct pollfd chans[self.nsocks];
    for(int i = 0; i < self.nsocks; i++) {
      fds[i].fd = self.socks[i]->world;
      fds[i].events = POLLIN;
      chans[i].fd = self.socks[i]->internal;
      chans[i].events = POLLIN;
    }

    poll(fds, self.nsocks, 100);
    poll(chans, self.nsocks, 100);

    for(int i = 0; i < self.nsocks; i++) {
      socket_lock(self.socks[i]);
      switch(self.socks[i]->state) {
        case R_CLOSING:
          send_close(self.socks[i]);
          self.socks[i]->state = R_TERM;
          socket_signal_close(self.socks[i]);
          socket_unlock(self.socks[i]);
          break;
        case R_CONNECTING:
          do_connect(self.socks[i], fds[i].revents);
          break;
        case R_LISTENING:
          do_accept(self.socks[i], fds[i].revents);
          break;
        case R_CONNECTED:
          do_recv(self.socks[i], fds[i].revents, chans[i].revents);
          do_send(self.socks[i], fds[i].revents, chans[i].revents);
          break;
        case R_BOUND:
          // bound but not listening or connected
        case R_TERM:
          // not deleted yet, fall through
        case R_NONE:
          // not connected yet
        case R_ERROR:
          // couldn't connect
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
  int fd = create_socket(type);
  global_unlock();
  return fd;
}

int
rudp_setsockopt() {
  return 0;
}

#define BASIC_CHECKS if(self.socks == NULL || fd >= RUDP_MAX_SOCKETS || fd >= self.nsocks || self.socks[fd] == NULL){ \
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
    socket_wait_close(s);
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
rudp_connect(int fd, const struct sockaddr *address, socklen_t address_len) {
  global_read_lock();
  BASIC_CHECKS

  rudp_socket_t *s = self.socks[fd];
  socket_lock(s);
  // TODO: better checks here, check for is connected EISCONN or is listening EOPNOTSUPP
  if(s->state != R_NONE) {
    if(s->state == R_CONNECTED) {
      errno = EISCONN;
    } else if(s->state == R_LISTENING) {
      errno = EOPNOTSUPP;
    }
    socket_unlock(s);
    return -1;
  }

  // connect socket
  int rc = connect(s->world, address, address_len);
  if(rc == -1) { socket_unlock(s); return rc; }
  s->state = R_CONNECTING;;
  while(s->state == R_CONNECTING) {
    socket_wait_conn(s);
  }
  if(s->state != R_CONNECTED) {
    socket_unlock(s);
    rudp_close(fd);
    errno = ECONNREFUSED;
    return 1;
  }
  socket_unlock(s);
  global_unlock();
  return 0;
}

int
rudp_accept(int fd, struct sockaddr *address, socklen_t *address_len){
  global_read_lock();
  BASIC_CHECKS

  rudp_socket_t *s = self.socks[fd];
  socket_lock(s);
  if(s->state != R_LISTENING) {
    if(s->state == R_CONNECTED) {
      errno = EISCONN;
    } else {
      errno = EOPNOTSUPP;
    }
    socket_unlock(s);
    return -1;
  }
  socket_unlock(s);

  // TODO: async
  uint8_t new_fd;
  int r = read(s->user, &new_fd, sizeof(new_fd));
  global_unlock();
  if(r == -1) return r;

  global_read_lock();
  s = self.socks[new_fd];
  r = getsockname(s->world, address, address_len);
  global_unlock();

  if(r == -1) return r;
  return new_fd;
}

int
rudp_bind(int fd, const struct sockaddr *address, socklen_t address_len) {
  global_read_lock();
  BASIC_CHECKS

  rudp_socket_t *s = self.socks[fd];

  socket_lock(s);
  int rc = bind(s->world, address, address_len);
  if(rc == -1) { socket_unlock(s); return rc; }
  s->state = R_BOUND;
  socket_unlock(s);
  global_unlock();

  return 0;
}

int
rudp_listen(int fd, int backlog){
  global_read_lock();
  BASIC_CHECKS

  rudp_socket_t *s = self.socks[fd];
  if(s->state == R_LISTENING) { socket_unlock(s); errno = EINVAL; return -1; }
  if(s->state != R_BOUND) { socket_unlock(s); errno = EDESTADDRREQ; return -1; }
  socket_lock(s);
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
