#include <memory.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>

const uint8_t HELLO = (1 << 0);
const uint8_t HI    = (1 << 1);
const uint8_t DATA  = (1 << 2);
int sockfd;
uint16_t seq = 0;

typedef struct rudp_queue {
  struct sockaddr_storage addr;
  uint8_t *data;
  size_t length;
  struct rudp_queue *next;
} rudp_queue_t;

rudp_queue_t *queue = NULL;

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

void
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
}

int
rudp_recv(struct sockaddr_storage addr, uint8_t *data, int length) {
  size_t hlen = sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t);
  if(length < hlen) return -1;
  uint8_t flags = *data;
  uint16_t *ack = (uint16_t *)data + 1;
  switch(flags) {
    case HELLO:;
      size_t length = 1; // protocol
      length += sizeof(uint32_t); // ack number
      length += sizeof(uint32_t); // seq number
      length += sizeof(uint8_t) * 32; // public key
      uint8_t *reply = calloc(1 * 4 * 32, sizeof(uint8_t));
      reply[0] = HI;
      memcpy(reply + 1, ack, sizeof(*ack));
      seq++;
      memcpy(reply + 1 + sizeof(ack), &seq, sizeof(seq));
      rudp_send(addr, reply, length);
      break;
    case HI:
      rudp_send(addr, data, length);
      break;
    case DATA:
      rudp_send(addr, data, length);
      break;
    default:
      puts("error!");
  }
}