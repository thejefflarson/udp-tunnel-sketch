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
#include <sys/select.h>
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

enum rudp_state {
  RUDP_NONE,
  RUDP_KEYS,
  RUDP_CONN
};

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
  // for encrypting cookie packets rotates every 2 minutes
  uint8_t cpk[crypto_box_PUBLICKEYBYTES];
  uint8_t csk[crypto_box_SECRETKEYBYTES];
  time_t last_update;
} rudp_listener_fields_t;

typedef struct {
  enum rudp_type; // connected
  enum rudp_state state; // where to write our messages
  uint16_t seq;
  uint16_t ack;
  uint16_t rseq;
  uint8_t their_key[crypto_box_PUBLICKEYBYTES];
  uint8_t pk[crypto_box_PUBLICKEYBYTES];
  uint8_t sk[crypto_box_SECRETKEYBYTES];
  struct sockaddr_storage addr;
  struct rudp_circular_buffer out;
} rudp_connected_fields_t;

typedef struct {
  // the socket pair
  int socks[2];
  enum rudp_type;
  bool open;
  pthread_cond_t closed;
  union {
    rudp_listener_fields_t  list;
    rudp_connected_fields_t conn;
  } impl;
} rudp_socket_t;

typedef enum {
  LISTENING,
  CONNECTED
} rudp_type;

#define RUDP_MAX_SOCKETS FD_SETSIZE
typedef struct {
  // listening sockets
  rudp_socket_t **socks;
  uint16_t nsocks;
  uint16_t *unused;
  pthread_t worker;
  int init;
} rudp_global_t;

rudp_global_t self = {0};
pthread_mutex_t glock = PTHREAD_MUTEX_INITIALIZER;


static void *
runloop(void *arg){
  while(1) {
    // doooooo nneeeetwooork
  }
}


static void
rudp_global_init(){
  int rc = pthread_mutex_lock(&glock);
  // needs to be a crash only error
  assert(rc == 0);
  if(self.init)
    return;

  self.socks  = calloc(RUDP_MAX_SOCKETS, sizeof(rudp_socket_t *));
  self.unused = calloc(RUDP_MAX_SOCKETS, sizeof(uint16_t));
  for(uint16_t i = 0; i != RUDP_MAX_SOCKETS; ++i)
    self.unused[i] = RUDP_MAX_SOCKETS - i - 1;

  // off to the races
  pthread_create(&self.worker, NULL, &runloop, NULL);

  self.init = 1;
  rc = pthread_mutex_unlock(&glock);
  assert(rc == 0);
}


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



  // decrypt cookie packet
  // fill in connection fields
  // return a new connection
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
  fd_set read, write;
  rudp_packet_t packet;
  socklen_t slen = sizeof(conn->addr);

  // check that the pub key in the packet is for this connection
  if(recvfrom(conn->socket, (uint8_t*) &packet, sizeof(packet), MSG_PEEK, (struct sockaddr *)&conn->addr, &slen) != -1) {
    if(memcmp(packet.pk, conn->pk, sizeof(packet.pk))) {
      errno = EINVAL;
      return -1;
    }

    if(conn->state != RUDP_CONN || packet.proto != RUDP_DATA) {
      errno = EINVAL;
      return -1;
    }

    // check for ack
    // clear out buffer

    rudp_packet_t *packet;
    packet = calloc(1, sizeof(packet));
    int err = recvfrom(conn->socket, (uint8_t*) packet, sizeof(packet), 0, (struct sockaddr *)&conn->addr, &slen);
    if(err == -1) return -1;

    rudp_secret_t secret;
    if(!buffer_has_space(&conn->in) // can't buffer more
        || open_packet(packet, conn, &secret) == -1) {
      free(packet);
      return -1;
    }

    // todo: send ack packet

    if(secret.ack < conn->rseq) {
      free(packet);
      return -1;
    }

    buffer_put(&conn->in, packet, ntohl(secret.seq));
    randombytes((uint8_t *)&secret, sizeof(secret));
  }

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

  rudp_packet_t *packet = calloc(1, sizeof(rudp_packet_t));
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