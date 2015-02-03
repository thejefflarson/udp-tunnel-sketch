#include <arpa/inet.h>
#include <memory.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <errno.h>
#include "tweetnacl.h"

// use this for testing: http://lcamtuf.coredump.cx/afl/README.txt
const uint8_t HELLO = (1 << 0); // syn pubkey
const uint8_t HI    = (1 << 1); // ack pubkey
const uint8_t BYE   = (1 << 2); // close
const uint8_t DATA  = (1 << 3); // encrypted data

#define PACKET_SIZE 1024 - 5 - crypto_box_NONCEBYTES
typedef struct {
  uint8_t proto;
  uint16_t ack;
  uint16_t seq;
  uint8_t data[PACKET_SIZE];
  uint8_t nonce[crypto_box_NONCEBYTES];
} rudp_packet_t;

// 1k packets per connection -- can buffer ~1.5mb total
#define BUFFER_SIZE 1024
typedef struct {
  struct sockaddr_storage addr;
  rudp_packet_t *packets[BUFFER_SIZE];
  uint16_t size;
} rudp_circular_buffer_t;

void
buffer_put(rudp_circular_buffer_t *buf, rudp_packet_t *packet, size_t index){
  buf->packets[index % BUFFER_SIZE] = packet;
  buf->size++;
}

rudp_packet_t *
buffer_get(rudp_circular_buffer_t *buf, size_t index){
  return buf->packets[index % BUFFER_SIZE];
}

rudp_packet_t *
buffer_delete(rudp_circular_buffer_t *buf, size_t index){
  rudp_packet_t *packet = buffer_get(buf, index);
  buf->packets[index % BUFFER_SIZE] = NULL;
  buf->size--;
  return packet;
}

bool
has_space(rudp_circular_buffer_t *buf) {
  return buf->size < BUFFER_SIZE;
}
#undef BUFFER_SIZE

enum state {
  INIT,
  KEYS,
  CONN
};

typedef struct rudp_conn {
  int socket;
  enum state state;
  uint16_t seq;
  uint16_t ack;
  uint8_t their_key[crypto_box_PUBLICKEYBYTES];
  uint8_t pk[crypto_box_PUBLICKEYBYTES];
  uint8_t sk[crypto_box_SECRETKEYBYTES];
  uint16_t connid;
  struct sockaddr_storage addr;
  rudp_circular_buffer_t *out;
} rudp_conn_t;


int
rudp_connect(struct sockaddr_storage addr) {
  return 0;
}

static void
_queue(rudp_conn_t *conn, rudp_packet_t *packet) {
  packet->seq = htonl(++conn->seq);
  packet->ack = htonl(conn->ack);
  buffer_put(conn->out, packet, conn->seq);
}

int
rudp_send(rudp_conn_t *conn, uint8_t *data, size_t length) {
  if(conn->state != CONN || conn->state != KEYS) {
    errno = EINVAL;
    return -1;
  }
  rudp_packet_t *packet = (rudp_packet_t *)calloc(1, sizeof(rudp_packet_t));
  size_t len = length < sizeof(packet) ? length : sizeof(packet);
  memcpy(data, packet->data, len);
  _queue(conn, packet);
  return len;
}

static int
fill_keys(rudp_conn_t *conn, rudp_packet_t *packet) {
  memcpy(conn->their_key, packet->data, crypto_box_PUBLICKEYBYTES);
  conn->ack = ntohl(packet->seq);
  errno = EINPROGRESS;
  return 0;
}

// needs to have a cookie, and immediately reply
static int
handle_hello(rudp_conn_t *conn, rudp_packet_t *packet) {
  if(fill_keys(conn, packet) == -1) return -1;
  rudp_packet_t *pckt = (rudp_packet_t *)calloc(1, sizeof(rudp_packet_t));
  conn->state = KEYS;
  pckt->proto = HI;
  memcpy(packet->data, conn->pk, crypto_box_PUBLICKEYBYTES);
  _queue(conn, pckt);
  return -1;
}

static int
handle_hi(rudp_conn_t *conn, rudp_packet_t *packet) {
  if(fill_keys(conn, packet) == -1) return -1;
  if(conn->state != KEYS) {
    errno = EINVAL;
    return -1;
  }
  rudp_packet_t *pckt = (rudp_packet_t *)calloc(1, sizeof(rudp_packet_t));
  conn->state = CONN;
  pckt->proto = DATA;
  _queue(conn, pckt);
  return -1;
}

static int
handle_data(rudp_conn_t *conn, rudp_packet_t *packet, uint8_t **data) {
  // data packet sent too early
  if(conn->state != CONN) {
    errno = EINVAL;
    return -1;
  }

  // decrypt packet, update ack, and dequeue ack packets
  size_t mlen = PACKET_SIZE - crypto_box_BOXZEROBYTES;
  uint8_t *c = (uint8_t *)calloc(mlen + crypto_box_BOXZEROBYTES, sizeof(uint8_t));
  if(c == NULL) {
    errno = ENOMEM;
    return -1;
  }

  uint8_t *m = (uint8_t *)calloc(mlen + crypto_box_ZEROBYTES, sizeof(uint8_t));
  if(m == NULL) {
    errno = ENOMEM;
    return -1;
  }

  uint8_t nonce[crypto_box_NONCEBYTES];
  memcpy(nonce, packet->nonce, crypto_box_NONCEBYTES);
  memcpy(c + crypto_box_BOXZEROBYTES, packet->data, mlen);
  int err = crypto_box_open(c, m, mlen, nonce, conn->their_key, conn->sk);
  if(err == -1) {
    errno = EINVAL;
    return -1;
  }

  while(conn->ack < ntohl(packet->ack)) {
    rudp_packet_t *packet = buffer_delete(conn->out, conn->ack);
    if(packet != NULL) free(packet);
    conn->ack++;
  }

  memcpy(data, m + crypto_box_BOXZEROBYTES, mlen);
  // empty ack packet, slightly abusing errno here but I'm cool with it
  return 0;
}

int
rudp_recv(rudp_conn_t *conn, uint8_t **data) {
  rudp_packet_t packet;
  socklen_t slen = sizeof(conn->addr);
  recvfrom(conn->socket, (uint8_t*) &packet, sizeof(packet), 0, (struct sockaddr *)&conn->addr, &slen);

  switch(packet.proto) {
    case HELLO:
      return handle_hello(conn, &packet);
    case HI:
      return handle_hi(conn, &packet);
    case DATA:
      return handle_data(conn, &packet, data);
    default: {
      errno = EINVAL;
      return -1;
    }
  }
  return 0;
}