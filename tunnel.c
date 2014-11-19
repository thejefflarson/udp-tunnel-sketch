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
} rudp_packet_t;

typedef struct {
  uint8_t proto;
  uint16_t connid;
  uint8_t pk[crypto_box_PUBLICKEYBYTES];
} __attribute__((packed)) rudp_conn_packet_t;

typedef struct {
  uint8_t proto;
  uint16_t ack;
  uint16_t seq;
  uint16_t connid;
  uint8_t *data;
  size_t *length;
} rudp_data_packet_t;

// 1k packets per connection -- can buffer ~1.5mb total
#define BUFFER_SIZE 1024
typedef struct {
  struct sockaddr_storage addr;
  rudp_packet_t *packets[BUFFER_SIZE];
  uint16_t size;
} rudp_circular_buffer_t;

rudp_circular_buffer_t in;
rudp_circular_buffer_t out;

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

uint8_t their_key[crypto_box_PUBLICKEYBYTES] = {0};
uint8_t pk[crypto_box_PUBLICKEYBYTES] = {0};
uint8_t sk[crypto_box_SECRETKEYBYTES] = {0};

int
rudp_recv(struct sockaddr_storage addr, uint8_t *data, int length);

int
rudp_send(struct sockaddr_storage addr, uint8_t *data, int length);

void
loop(){
  fd_set readfd, writefd;
  FD_ZERO(&readfd);
  FD_ZERO(&writefd);
  FD_SET(sockfd, &readfd);
  FD_SET(sockfd, &writefd);
  while(1) {
    struct timeval tv;
    tv.tv_sec  = 0;
    tv.tv_usec = 50;
    select(1, &readfd, &writefd, NULL, &tv);
    if(FD_ISSET(sockfd, &readfd)) {
      struct sockaddr_storage addr;
      uint8_t data[65536];
      socklen_t size;
      ssize_t length = recvfrom(sockfd, data, 65536, 0, (struct sockaddr *) &addr, &size);
      rudp_recv(addr, data, length);
    }
    if(FD_ISSET(sockfd, &writefd)) {
      rudp_packet_t *packet = buffer_get(&out, ack + 1);
      uint8_t *reply = calloc(1, sizeof(uint8_t));
      size_t length = 0;
        // something like this
        // size_t plen = sizeof(seq) * 2;
        // uint8_t *plain = calloc(plen, sizeof(uint8_t));
        // uint16_t nseq = htons(seq);
        // memcpy(plain, &nseq, sizeof(nseq));
        // memcpy(plain + sizeof(nseq), &nseq, sizeof(nseq));
        // size_t clen = len + crypto_box_ZEROBYTES;
        // uint8_t *cipher = calloc(clen, sizeof(uint8_t));
        // uint8_t *nonce = calloc(crypto_box_ZEROBYTES, sizeof(uint8_t));
        // randombytes(nonce, crypto_box_NONCEBYTES);
        // crypto_box(cipher, plain, sizeof(plain), nonce, their_key, sk);
        // len = sizeof(plain) + sizeof(DATA) + crypto_box_BOXZEROBYTES + crypto_box_NONCEBYTES;
        // reply = calloc(len, sizeof(uint8_t));
        // reply[0] = DATA;
        // clen -= crypto_box_BOXZEROBYTES;
        // memcpy(reply + sizeof(data), cipher + crypto_box_BOXZEROBYTES, clen);
        // memcpy(reply + sizeof(data) + clen, nonce, crypto_box_NONCEBYTES);
        // todo: keep sending until acked
      sendto(sockfd, reply, length, 0, (struct sockaddr *) addr, sizeof(addr));
      free(reply);
    }
  }
}

int
rudp_connect(struct sockaddr_storage addr) {
  return 0;
}

int
rudp_send(struct sockaddr_storage addr, uint8_t *data, int length) {

  return 0;
}

int
rudp_recv(struct sockaddr_storage addr, uint8_t *data, int length) {
  size_t len;
  uint8_t flags = *data;
  switch(flags) {
    case HI:
    case HELLO:
      len = sizeof(their_key) + sizeof(HELLO) + sizeof(uint16_t);
      if(length < len) return -1;
      memcpy(their_key, data + 1, sizeof(their_key));
      if(flags == HELLO) {
        rudp_conn_packet_t *reply = calloc(1, sizeof(rudp_conn_packet_t));
        reply->proto  = HI;
        reply->connid = ntohl(*(data + 1));
        crypto_box_keypair(pk, sk);
        memcpy(reply + sizeof(uint16_t) + sizeof(HI), pk, sizeof(pk));
        buffer_put(&out, (rudp_packet_t *)reply, seq); // needs to be a simple list insert
      } else { // HI
        seq++;
        rudp_data_packet_t *reply = calloc(1, sizeof(rudp_data_packet_t));
        reply->proto = DATA;
        reply->seq = htons(seq);
        ack = seq - 1;
        reply->ack = htons(seq - 1);
        reply->data = NULL;
        reply->length = 0;
        buffer_put(&out, (rudp_packet_t *)reply, seq);// needs to be a simple list insert
        rudp_conn_packet_t *hi = (rudp_conn_packet_t *)buffer_delete(&out, 0);
        free(hi);
      }
      break;
    case DATA:{
      ack = ntohs(*(uint16_t *)(data + 1));
      break;
    }
    default:
      puts("error!");
      return -1;
  }
  return 0;
}