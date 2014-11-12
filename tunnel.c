#include <arpa/inet.h>
#include <memory.h>
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


typedef struct rudp_queue {
  struct sockaddr_storage addr;
  uint8_t *data;
  size_t length;
  struct rudp_queue *next;
} rudp_queue_t;

rudp_queue_t *queue = NULL;
uint8_t their_key[crypto_box_PUBLICKEYBYTES] = {0};
uint8_t pk[crypto_box_PUBLICKEYBYTES] = {0};
uint8_t sk[crypto_box_SECRETKEYBYTES] = {0};

int
rudp_recv(struct sockaddr_storage addr, uint8_t *data, int length);

int
rudp_send(struct sockaddr_storage addr, uint8_t *data, int length);

void
loop(rudp_queue_t *queue){
  fd_set readfd, writefd;
  FD_ZERO(&readfd);
  FD_ZERO(&writefd);
  FD_SET(sockfd, &readfd);
  FD_SET(sockfd, &writefd);
  while(1) {
    struct timeval tv;
    tv.tv_sec  = 0;
    tv.tv_usec = 0;
    select(1, &readfd, &writefd, NULL, &tv);
    if(FD_ISSET(sockfd, &readfd)) {
      struct sockaddr_storage addr;
      uint8_t data[65536];
      ssize_t length = sendto(sockfd, data, 65536, 0, (struct sockaddr *) &addr, sizeof(addr));
      rudp_recv(addr, data, length);
    }
    if(FD_ISSET(sockfd, &writefd)) {
      if(queue != NULL) {
        rudp_queue_t *head = queue;
        if(head != NULL) {
          // todo: keep sending until acked
          sendto(sockfd, head->data, head->length, 0, (struct sockaddr *) &head->addr, sizeof(head->addr));
          queue = head->next;
          free(head->data);
          free(head);
        }
      }
    }
  }
}

int
rudp_send(struct sockaddr_storage addr, uint8_t *data, int length) {
  rudp_queue_t *tail = queue;
  if(tail == NULL) {
    tail = (rudp_queue_t *)calloc(1, sizeof(rudp_queue_t));
    queue = tail;
  } else {
    while(tail->next != NULL) tail = tail->next;
    tail->next = (rudp_queue_t *)calloc(1, sizeof(rudp_queue_t));
    tail = tail->next;
  }
  tail->addr = addr;
  tail->data = data;
  tail->length = length;
  return 0;
}

int
rudp_recv(struct sockaddr_storage addr, uint8_t *data, int length) {
  size_t len;
  uint8_t flags = *data;
  uint8_t *reply;
  switch(flags) {
    case HI:
    case HELLO:
      len = sizeof(their_key) + sizeof(HELLO);
      if(length < len) return -1;
      memcpy(their_key, data + 1, sizeof(their_key));
      if(flags == HELLO) {
        reply = (uint8_t *)calloc(len, sizeof(uint8_t));
        reply[0] = HI;
        crypto_box_keypair(pk, sk);
        memcpy(reply + sizeof(HI), pk, sizeof(pk));
        rudp_send(addr, reply, len); // needs to be a simple list insert
      } else { // HI
        // needs to be a seal function
        size_t plen = sizeof(seq) * 2;
        uint8_t *plain = (uint8_t *)calloc(plen, sizeof(uint8_t));
        uint16_t nseq = htons(seq);
        memcpy(plain, &nseq, sizeof(nseq));
        memcpy(plain + sizeof(nseq), &nseq, sizeof(nseq));
        size_t clen = len + crypto_box_ZEROBYTES;
        uint8_t *cipher = (uint8_t *)calloc(clen, sizeof(uint8_t));
        uint8_t *nonce = (uint8_t *)calloc(crypto_box_ZEROBYTES, sizeof(uint8_t));
        randombytes(nonce, crypto_box_NONCEBYTES);
        crypto_box(cipher, plain, sizeof(plain), nonce, their_key, sk);
        len = sizeof(plain) + sizeof(DATA) + crypto_box_BOXZEROBYTES + crypto_box_NONCEBYTES;
        reply = (uint8_t *)calloc(len, sizeof(uint8_t));
        reply[0] = DATA;
        clen -= crypto_box_BOXZEROBYTES;
        memcpy(reply + sizeof(data), cipher + crypto_box_BOXZEROBYTES, clen);
        memcpy(reply + sizeof(data) + clen, nonce, crypto_box_NONCEBYTES);
        rudp_send(addr, reply, len);
        // end seal function
      }
      break;
    case DATA:{
      uint16_t ack = ntohs(*(uint16_t *)(data + 1));
      rudp_send(addr, data, 0);
      break;
    }
    default:
      puts("error!");
      return -1;
  }
  return 0;
}