#include <arpa/inet.h>
#include <memory.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include "rudp.h"
#include "buffer.h"

static int
open_packet(const rudp_packet_t *packet, const rudp_conn_t *conn, rudp_secret_t *secret){
  uint8_t c[RUDP_SECRET_SIZE + crypto_box_BOXZEROBYTES] = {0};
  memcpy(c + crypto_box_BOXZEROBYTES, packet->encrypted, RUDP_SECRET_SIZE);
  memset(&secret, 0, sizeof(secret));
  int err = crypto_box_open((uint8_t *)&secret, c, RUDP_SECRET_SIZE, packet->nonce, conn->their_key, conn->sk);
  if(err == -1) return -1;
}

// make this work on multiple connections
int
rudp_select(rudp_conn_t *conn) {
  fd_set read, write;
  rudp_packet_t packet;
  socklen_t slen = sizeof(conn->addr);

  // check that the pub key in the packet is for this connection
  if(recvfrom(conn->socket, (uint8_t*) &packet, sizeof(packet), MSG_PEEK, (struct sockaddr *)&conn->addr, &slen) != -1) {
    if(memcmp(packet.pk, conn->pk, sizeof(packet.pk))) {
      errno = EINVAL;
      return -1;
    }

    if(conn->state != RUDP_CONN || packet.proto != RUDP_DATA) {
      errno = EINVAL;
      return -1;
    }

    rudp_packet_t *packet;
    packet = calloc(1, sizeof(packet));
    int err = recvfrom(conn->socket, (uint8_t*) packet, sizeof(packet), 0, (struct sockaddr *)&conn->addr, &slen);
    if(err == -1) return -1;

    rudp_secret_t secret;
    if(!buffer_has_space(&conn->in) // can't buffer more
        || open_packet(packet, conn, &secret) == -1 // bad decrypt
        || ntohl(secret.seq) < conn->rseq) { // repeat packet
      free(packet);
      return -1;
    }

    buffer_put(&conn->in, packet, ntohl(secret.seq));
    randombytes((uint8_t *)&secret, sizeof(secret));
  }

  return -1;
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
  rudp_packet_t *packet = buffer_delete(&conn->in, conn->rseq);
  if(packet == NULL) {
    errno = EWOULDBLOCK;
    return -1;
  }

  rudp_secret_t secret;
  if(open_packet(packet, conn, &secret) == -1) {
    free(packet);
    errno = EINVAL;
    return -1;
  }

  // really unlikely scenario
  if(__builtin_expect(secret.ack != conn->rseq, 0)) {
    free(packet);
    errno = EINVAL;
    return -1;
  }

  conn->ack = ntohl(secret.ack);
  conn->rseq++;
  memcpy(data, secret.data, RUDP_DATA_SIZE);
  randombytes((uint8_t *)&secret, sizeof(secret));
  free(packet);
  // todo: ack back
  return -1;
}