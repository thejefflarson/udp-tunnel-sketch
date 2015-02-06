#include <arpa/inet.h>
#include <memory.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include "rudp.h"
#include "buffer.h"

// make this work on multiple connections
int
rudp_do(rudp_conn_t *conn) {
  fd_set read, write;

  return 0;
}

// use this for testing: http://lcamtuf.coredump.cx/afl/README.txt
int
rudp_send(rudp_conn_t *conn, uint8_t *data, size_t length) {
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


  rudp_packet_t *packet = (rudp_packet_t *)calloc(1, sizeof(rudp_packet_t));
  randombytes(packet->nonce, crypto_box_NONCEBYTES);
  rudp_secret_t secret;
  memset(&secret, 0, sizeof(secret));
  secret.ack = ntohl(conn->ack);
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
rudp_recv(rudp_conn_t *conn, uint8_t **data) {
  rudp_packet_t packet;
  socklen_t slen = sizeof(conn->addr);
  // check that the pub key in the packet is our pubkey


  recvfrom(conn->socket, (uint8_t*) &packet, sizeof(packet), 0, (struct sockaddr *)&conn->addr, &slen);
  // data packet sent too early
  if(conn->state != RUDP_CONN || data[0] != RUDP_DATA) {
    errno = EINVAL;
    return -1;
  }

  // pad secret
  uint8_t c[RUDP_SECRET_SIZE + crypto_box_BOXZEROBYTES] = {0};
  if(c == NULL) {
    errno = ENOMEM;
    return -1;
  }
  memcpy(c + crypto_box_BOXZEROBYTES, packet.encrypted, RUDP_SECRET_SIZE);

  // decrypt packet
  rudp_secret_t secret;
  memset(&secret, 0, sizeof(secret));
  int err = crypto_box_open((uint8_t *)&secret, c, RUDP_SECRET_SIZE, packet.nonce, conn->their_key, conn->sk);
  if(err == -1) {
    errno = EINVAL;
    return -1;
  }

  // update ack and dequeue acked packets
  while(conn->ack < ntohl(secret.ack)) {
    rudp_packet_t *packet = buffer_delete(&conn->out, conn->ack);
    if(packet != NULL) free(packet);
    conn->ack++;
    // todo: ack back man
  }

  memcpy(data, secret.data, RUDP_DATA_SIZE);
  randombytes((uint8_t *)&secret, sizeof(secret));
  return 0;
}