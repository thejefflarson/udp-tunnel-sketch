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
uint8_t their_key[crypto_secretbox_KEYBYTES] = {0};
uint8_t our_key[crypto_secretbox_KEYBYTES] = {0};

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
    tail = calloc(1, sizeof(rudp_queue_t));
    queue = tail;
  } else {
    while(tail->next != NULL) tail = tail->next;
    tail->next = calloc(1, sizeof(rudp_queue_t));
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
  switch(flags) {
    case HELLO:
      len = sizeof(their_key) + sizeof(HELLO);
      if(length < len) return -1;
      memcpy(their_key, data + 1, sizeof(their_key));
      len = sizeof(their_key) + sizeof(HI);
      len += crypto_secretbox_NONCEBYTES + crypto_secretbox_BOXZEROBYTES;
      uint8_t *reply = calloc(len, sizeof(uint8_t));
      reply[0] = HI;
      reply += sizeof(HI);
      uint16_t nack = htons(0);
      memcpy(reply, &nack, sizeof(nack));
      reply += sizeof(nack);
      seq++;
      uint16_t nseq = htons(seq);
      memcpy(reply + 1 + sizeof(seq), &nseq, sizeof(nseq));
      reply += sizeof(seq);
      // encrypt our_key;
      rudp_send(addr, reply, len);
      break;
    case HI:;
      size_t len = crypto_secretbox_KEYBYTES;
      if(length < len) return -1;
      // decrypt our_key and ensure it is the same
      break;
    case DATA:;
      uint16_t ack = ntohs(*(uint16_t *)(data + 1));
      rudp_send(addr, data, 0);
      break;
    default:
      puts("error!");
      return -1;
  }
  return 0;
}