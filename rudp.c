#include <arpa/inet.h>
#include <memory.h>
#include <memory.h>
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <poll.h>
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
  R_CONNNECTING,
  R_CONNECTED,
  R_TERM
} rudp_state;

#define RUDP_BUFFER_SIZE 1024
typedef struct rudp_circular_buffer {
  rudp_packet_t *packets[RUDP_BUFFER_SIZE];
  uint16_t size;
} rudp_circular_buffer_t;

void
buffer_put(rudp_circular_buffer_t *buf, rudp_packet_t *packet, size_t index){
  buf->packets[index % RUDP_BUFFER_SIZE] = packet;
  buf->size++;
}

rudp_packet_t *
buffer_get(rudp_circular_buffer_t *buf, size_t index){
  return buf->packets[index % RUDP_BUFFER_SIZE];
}

rudp_packet_t *
buffer_delete(rudp_circular_buffer_t *buf, size_t index){
  rudp_packet_t *packet = buffer_get(buf, index);
  buf->packets[index % RUDP_BUFFER_SIZE] = NULL;
  buf->size--;
  return packet;
}

bool
buffer_has_space(rudp_circular_buffer_t *buf) {
  return buf->size < RUDP_BUFFER_SIZE;
}
#undef RUDP_BUFFER_SIZE

typedef struct {
  rudp_state state;
  int outfd;     // our bound socket
  int chanfd[2]; // interthread communication sockets 0 -> user, 1 -> lib
  pthread_mutex_t sync;

  // connection fields, only filled in for CONNECTED sockets
  uint16_t seq;
  uint16_t ack;
  uint16_t rseq;
  uint8_t their_key[crypto_box_PUBLICKEYBYTES];
  uint8_t pk[crypto_box_PUBLICKEYBYTES];
  uint8_t sk[crypto_box_SECRETKEYBYTES];
  rudp_circular_buffer_t out;
} rudp_socket_t;

#define RUDP_MAX_SOCKETS FD_SETSIZE
typedef struct {
  // listening sockets
  rudp_socket_t **socks;
  uint16_t nsocks;
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

// the whole shebang really -- this should be broken up and cleaned up
static void *
runloop(void *arg){
  while(1) {
    int nsocks;
    struct pollfd *fds;

    check(pthread_mutex_lock(&glock) == 0);
    nsocks = self.nsocks;
    fds = calloc(nsocks, sizeof(struct pollfd));
    for(int i = 0; i < nsocks; i++) {
      fds[i].fd = self.socks[i]->outfd;
      fds[i].events = POLLIN;
    }
    check(pthread_mutex_unlock(&glock) == 0);

    poll(fds, nsocks, 0);

    for(int i = 0; i < nsocks; i++) {
      if(fds[i].events | POLLIN) {
        check(pthread_mutex_lock(&self.socks[i]->sync) == 0);
        if(&self.socks[i]->state == R_NONE) continue; // set errors
        // read packet
        // handle packet and put in our communication channel
        check(pthread_mutex_unlock(&self.socks[i]->sync) == 0);
      }
    }

    // terminate closing sockets
  }
}


static void
rudp_global_init(){
  if(self.socks)
    return;

  self.socks  = (rudp_socket_t **) calloc(RUDP_MAX_SOCKETS, sizeof(rudp_socket_t *));
  self.unused = (uint16_t *) calloc(RUDP_MAX_SOCKETS, sizeof(uint16_t));
  for(uint16_t i = 0; i != RUDP_MAX_SOCKETS; ++i)
    self.unused[i] = RUDP_MAX_SOCKETS - i - 1;

  // off to the races
  pthread_create(&self.worker, NULL, &runloop, NULL);
}



























///////////////////////////////////////////////////////////////////// JUNK DRAWER

int
rudp_connect(int fd, struct sockaddr *addr, int port) {
  rudp_conn_t *conn = calloc(1, sizeof(rudp_conn_t));
  if(conn == NULL) {
    errno = EINVAL;
    return NULL;
  }
}

static int
handle_hi(rudp_conn_t *conn, rudp_packet_t *packet) {
  if(conn->state != RUDP_KEYS) {
    errno = EINVAL;
    return -1;
  }
  rudp_packet_t *pckt = (rudp_packet_t *)calloc(1, sizeof(rudp_packet_t));
  conn->state = RUDP_CONN;
  pckt->proto = RUDP_DATA;
  buffer_put(&conn->out, packet, conn->seq);
  return -1;
}

typedef struct {
  uint8_t nonce[crypto_box_NONCEBYTES];
  uint8_t encrypted[crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES + crypto_box_BOXZEROBYTES];
} __attribute__((packed)) hi_secret_t;

// we don't need a packet here, because we are encrypting just to the cookie key
static int
handle_hello(rudp_node_t *node, struct sockaddr_storage addr) {
  uint8_t pk[crypto_box_PUBLICKEYBYTES];
  uint8_t sk[crypto_box_SECRETKEYBYTES];

  rudp_packet_t packet;
  // because we won't be using all fields but we still want it to be random looking
  randombytes((uint8_t *)&packet, sizeof(packet));
  packet.proto = RUDP_HI;

  hi_secret_t hi_secret;
  memset(&hi_secret, 0, sizeof(hi_secret));

  crypto_box_keypair(pk, sk);
  memcpy(packet.pk, pk, sizeof(pk));
  randombytes(hi_secret.nonce, sizeof(hi_secret.nonce));

  uint8_t m[sizeof(hi_secret.encrypted) + crypto_box_BOXZEROBYTES] = {0};
  memcpy(m + crypto_box_ZEROBYTES, sk, sizeof(sk));
  memcpy(m + crypto_box_PUBLICKEYBYTES + crypto_box_ZEROBYTES, pk, sizeof(pk));

  uint8_t c[sizeof(m)] = {0};
  crypto_box(c, m, sizeof(m), hi_secret.nonce, node->cpk, node->csk);

  memcpy(hi_secret.encrypted, c + crypto_box_BOXZEROBYTES, sizeof(hi_secret.encrypted));
  memcpy(packet.encrypted, &hi_secret, sizeof(hi_secret));

  return sendto(node->socket, &packet, sizeof(packet), 0, (struct sockaddr *)&addr, sizeof(addr));
}

static rudp_conn_t *
handle_init(rudp_node_t *node, rudp_packet_t *packet) {
  rudp_conn_t *conn = calloc(1, sizeof(rudp_conn_t));
  conn->socket = node->socket;

}

int
rudp_accept(int fd) {

}



static int
open_packet(const rudp_packet_t *packet, const rudp_conn_t *conn, rudp_secret_t *secret){
  uint8_t c[RUDP_SECRET_SIZE + crypto_box_BOXZEROBYTES] = {0};
  memcpy(c + crypto_box_BOXZEROBYTES, packet->encrypted, RUDP_SECRET_SIZE);
  memset(&secret, 0, sizeof(secret));
  int err = crypto_box_open((uint8_t *)&secret, c, RUDP_SECRET_SIZE, packet->nonce, conn->their_key, conn->sk);
  return err;
}

// make this work on multiple connections
int
rudp_select(rudp_conn_t *conn) {


  return -1;
}

// use this for testing: http://lcamtuf.coredump.cx/afl/README.txt
int
rudp_send(int fd, uint8_t *data, size_t length) {
  // packet too big
  if(length > RUDP_DATA_SIZE) {
    errno = EINVAL;
    return -1;
  }
  // need to flush the buffer first
  if(!buffer_has_space(&conn->out)) {
    errno = EAGAIN;
    return -1;
  }
  // not connected yet
  if(conn->state != RUDP_CONN) {
    errno = ENOTCONN;
    return -1;
  }
  // TODO: handle ETIMEDOUT

  rudp_packet_t *packet = (rudp_packet_t *)calloc(1, sizeof(rudp_packet_t));
  randombytes(packet->nonce, crypto_box_NONCEBYTES);
  rudp_secret_t secret;
  memset(&secret, 0, sizeof(secret));
  secret.ack = ntohl(conn->rseq);
  secret.seq = ntohl(++conn->seq);
  memcpy(secret.data, data, length);
  uint8_t m[sizeof(secret)] = {0};
  crypto_box(m, (uint8_t *)&secret, sizeof(secret), packet->nonce, conn->their_key, conn->sk);
  memcpy(packet->encrypted, m + crypto_box_BOXZEROBYTES, sizeof(secret) - crypto_box_BOXZEROBYTES);
  randombytes((uint8_t *)&secret, sizeof(secret));
  buffer_put(&conn->out, packet, conn->seq);
  return length;
}

int
rudp_recv(int fd, uint8_t *data, int length) {
  rudp_packet_t *packet = buffer_delete(&conn->in, conn->rseq);
  if(packet == NULL) {
    errno = EWOULDBLOCK;
    return -1;
  }

  rudp_secret_t secret;
  if(open_packet(packet, conn, &secret) == -1) {
    free(packet);
    errno = EINVAL;
    return -1;
  }

  assert(secret.ack == conn->rseq);
  conn->ack = ntohl(secret.ack);
  conn->rseq++;
  memcpy(data, secret.data, RUDP_DATA_SIZE);
  randombytes((uint8_t *)&secret, sizeof(secret));
  free(packet);
  return -1;
}