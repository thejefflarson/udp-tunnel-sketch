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
const uint8_t ACK   = (1 << 4);

int sockfd;
uint16_t seq = 0;
uint16_t ack = 0;

typedef struct {
  uint8_t proto;
  uint16_t ack;
  uint16_t seq;
} __attribute__((packed)) rudp_header_t;

typedef struct {
  rudp_header_t header;
  uint8_t *data;
  size_t length;
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
  return buf->size <= BUFFER_SIZE;
}
#undef BUFFER_SIZE

enum state {
  INIT,
  KEYS,
  CONN
};

typedef struct rudp_conn {
  enum state state;
  uint16_t seq;
  uint16_t ack;
  uint8_t their_key[crypto_box_PUBLICKEYBYTES];
  uint8_t pk[crypto_box_PUBLICKEYBYTES];
  uint8_t sk[crypto_box_SECRETKEYBYTES];
  uint16_t connid;
  struct sockaddr_storage addr;
  rudp_circular_buffer_t *out;
  rudp_circular_buffer_t *in;
} rudp_conn_t;

int
rudp_recv(rudp_conn_t *conn, const uint8_t *data, int length);

int
rudp_send(rudp_conn_t *conn, const uint8_t *data, int length);

void
loop(rudp_conn_t *conn){
  fd_set readfd, writefd;
  FD_ZERO(&readfd);
  FD_ZERO(&writefd);
  FD_SET(sockfd, &readfd);
  FD_SET(sockfd, &writefd);
  while(1) {
    select(sockfd + 1, &readfd, &writefd, NULL, NULL);
    if(FD_ISSET(sockfd, &readfd)) {
      uint8_t data[1472];
      socklen_t size;
      ssize_t length = recvfrom(sockfd, data, 1472, 0, (struct sockaddr *) &conn->addr, &size);
      rudp_recv(conn, data, length);
    }
    if(FD_ISSET(sockfd, &writefd)) {
      rudp_packet_t *packet = buffer_get(conn->out, conn->ack + 1);
      if(packet != NULL)
        sendto(sockfd, packet->data, packet->length, 0, (struct sockaddr *)&conn->addr, sizeof(conn->addr));
    }
  }
}

int
rudp_connect(struct sockaddr_storage addr) {
  return 0;
}

void
_queue(rudp_conn_t *conn, rudp_packet_t *packet) {
  packet->proto = DATA;
  packet->header.seq = htonl(++conn->seq);
  packet->header.ack = htonl(conn->ack);
  buffer_put(conn->out, packet, conn->seq);
}

int
rudp_send(rudp_conn_t *conn, const uint8_t *data, size_t length) {
  if(conn->state != CONN || conn->state != KEYS) {
    errno = EINVAL;
    return -1;
  }
  rudp_packet_t *packet = calloc(1, sizeof(rudp_packet_t));
  if(packet == NULL) return -1;
  packet->data = data;
  packet->length = length;
  _queue(conn, packet);
  return 0;
}

// even though this is simple needs to be a ragel
int
rudp_recv(rudp_conn_t *conn, const uint8_t *data, size_t length, uint8_t **out, size_t &len) {
  switch(data[0]) {
    // both of these cases are EINPROGRESS cases
    case HI:
    case HELLO:{
      if(length < sizeof(rudp_header_t) + crypto_box_PUBLICKEYBYTES) {
        errno = EINVAL;
        return -1;
      }
      if(data[0] != HELLO || data[0] != HI) {
        errno = EINVAL;
        return -1;
      }

      rudp_packet_t *packet = calloc(1, sizeof(rudp_packet_t));
      if(packet == NULL) return -1;
      errno = EINPROGRESS;
      memcpy(conn->their_key, data + sizeof(rudp_header_t), crypto_box_PUBLICKEYBYTES);
      rudp_header_t *header = data;
      conn->ack = ntohl(header->seq);

      if(data[0] == HELLO) {
        conn->state = KEYS;
        packet->header.proto = HI;
        packet->data = calloc(crypto_box_PUBLICKEYBYTES, sizeof(uint8_t));
        if(!packet->data) return -1;
        memcpy(packet->data, conn->pk, crypto_box_PUBLICKEYBYTES);
        packet->length = crypto_box_PUBLICKEYBYTES;
        _queue(conn, packet);
      } else if(data[0] == HI) {
        if(conn->state != KEYS) {
          errno = EINVAL;
          free(packet);
          return -1;
        }
        conn->state = CONN;
        packet->header.proto = DATA;
        packet->data = NULL;
        packet->length = 0;
        _queue(conn, packet);
      }

      return -1;
    }
    case DATA:{
      // data packet sent too early
      if(conn->state != CONN || data[0] != DATA) {
        errno = EINVAL;
        return -1;
      }
      // decrypt packet, update ack, and dequeue ack packets
      size_t mlen = length - crypto_box_NONCEBYTES - crypto_box_ZEROBYTES - 1;
      uint8_t message = calloc(mlen, sizeof(uint8_t));
      if(message == NULL) return -1;
      uint8_t nonce[crypto_box_NONCEBYTES];
      memcpy(nonce, data + 1, crypto_box_NONCEBYTES);

      // empty ack packet, slightly abusing errno here but I'm cool with it
      if(length == sizeof(rudp_header_t) + crypto_box_NONCEBYTES) {
        if(conn->state == KEYS) conn->state = CONN;
        errno = EAGAIN;
        return -1;
      }

      // return data

      break;
    }
    default: {
      errno = EINVAL;
      return -1;
    }
  }
  return 0;
}