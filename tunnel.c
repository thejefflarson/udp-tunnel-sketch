const uint8_t HELLO = (1 << 0);
const uint8_t HI    = (1 << 1);
const uint8_t ACK   = (1 << 2);
const uint8_t DATA  = (1 << 3);
uint16_t seq = 0;
int sockfd;

typedef struct rudp_queue {
  struct sockaddr_storage addr;
  uint8_t *data;
  size_t length;
  rudp_queue *next;
} rudp_queue_t;

rudp_queue_t *queue = NULL;

void
loop(rudp_queue_t *queue){
  fd_set readfd, writefd;
  FD_ZERO(&readfd);
  FD_ZERO(&writefd);
  FD_SET(sockfd, &readfd);
  FD_SET(sockfd, &writefd);
  while(1) {
    timeval tv;
    tv.tv_sec  = 0;
    tv.tv_usec = 0;
    select(1, &readfd, &writefd, NULL, &tv);
    if(IS_SET(sockfd, &readfd)) {
      struct sockaddr_storage addr;
      uint8_t data[65536];
      sendto(sockfd, data, 65536, addr, sizeof(addr));
      rudp_recv(addr, data, length);
    }
    if(IS_SET(sockfd, &writefd)) {
      // send waiting packets
      if(rudp_queue_t *queue) {
        rudp_queue_t *head = queue;
        sendto(sockfd, head->data, head->length, head->addr, sizeof(head->addr));
        queue = head->next;
        free(head);
      }
    }
  }
}

void
rudp_send(struct sockaddr_storage addr, uint8_t *data, int length) {
  rudp_queue_t *tail = queue;
  if(tail == NULL) {
    tail = calloc(1, sizeof(rudp_queue_t));
  } else {
    while(tail->next != NULL) tail = tail->next;
    tail->next = calloc(1, sizeof(rudp_queue_t));
    tail = tail->next;
  }
  tail->addr = addr;
  tail->data = data;
  tail->length = length;
}

void
rudp_recv(struct sockaddr_storage addr, uint8_t *data, int length) {
  proto_t prot = data[0];
  switch(prot) {
    case HELLO:
      send(addr);
    case HI:
      send(addr);
    case ACK:
      send(addr);
    case DATA:
      send(addr);
    default:
      puts("error!");
  }
}