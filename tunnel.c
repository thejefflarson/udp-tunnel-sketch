#include <arpa/inet.h>
#include <memory.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include "tweetnacl.h"

const uint8_t HELLO = (1 << 0); // syn pubkey
const uint8_t HI    = (1 << 1); // ack pubkey
const uint8_t BYE   = (1 << 2); // close
const uint8_t DATA  = (1 << 3); // encrypted data

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

typedef struct {
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
rudp_recv(rudp_conn_t *conn, uint8_t *data, int length);

int
rudp_send(rudp_conn_t *conn, uint8_t *data, int length);

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
      struct sockaddr_storage addr;
      uint8_t data[1472];
      socklen_t size;
      ssize_t length = recvfrom(sockfd, data, 1472, 0, (struct sockaddr *) &addr, &size);
      rudp_recv(addr, data, length);
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

int
rudp_send(rudp_conn_t *conn, uint8_t *data, int length) {
  rudp_packet_t *packet = calloc(1, sizeof(rudp_packet_t));
  if(packet == NULL) return -1;
  packet->header.seq = htonl(++conn->seq);
  packet->header.ack = htonl(conn->ack);
  packet->data = data;
  packet->length = length;
  buffer_put(conn->out, packet, conn->seq);
  return 0;
}

int
rudp_recv(rudp_conn_t *conn, uint8_t *data, int length) {

  switch(data[0]) {
    case HI:
    case HELLO:{
      rudp_packet_t *packet = calloc(1, sizeof(rudp_packet_t));
      packet->header.seq = conn->seq++;
      packet->header.ack = conn->ack;
      packet->data = data;
      packet->length = length;
      if(packet == NULL) return -1;
      if(data[0] == HELLO) {
        packet->header.proto = HI;

      } else if(data[0] == HI) { // HI

      } else {
        free(packet);
        return -1;
      }
      break;
    }
    case DATA:{


      break;
    }
    default:
      goto err;
      return -1;
  }
  return 0;
}