

const uint8_t HELLO = (1 << 0);
const uint8_t HI    = (1 << 1);
const uint8_t ACK   = (1 << 2);
const uint8_t DATA  = (1 << 3);
uint16_t seq = 0;
int sockfd;

void
loop(){
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

    }
    if(IS_SET(sockfd, &writefd)) {
      // send waiting packets

    }
  }
}

void
rudp_send(struct sockaddr_storage addr, uint8_t *data, int length) {
  sendto(sockfd, data, length, addr, sizeof(addr));
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