#include <arpa/inet.h>
#include <memory.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include "rudp.h"
#include "buffer.h"

// use this for testing: http://lcamtuf.coredump.cx/afl/README.txt

static void
_queue(rudp_conn_t *conn, rudp_packet_t *packet) {
  buffer_put(conn->out, packet, conn->seq);
}

int
rudp_send(rudp_conn_t *conn, uint8_t *data, size_t length) {
  if(conn->state != RUDP_CONN || conn->state != RUDP_KEYS || length > sizeof(rudp_secret_t)) {
    errno = EINVAL;
    return -1;
  }
  rudp_packet_t *packet = (rudp_packet_t *)calloc(1, sizeof(rudp_packet_t));
  randombytes(packet->nonce, crypto_box_NONCEBYTES);
  rudp_secret_t secret;
  memset(&secret, 0, sizeof(secret));
  secret.ack = ntohl(conn->ack);
  secret.seq = ntohl(++conn->seq);
  memcpy(secret.data, data, length);
  uint8_t m[sizeof(secret)] = {0};
  crypto_box(m, (uint8_t *)&secret, sizeof(secret), packet->nonce, conn->their_key, conn->sk);
  memcpy(packet->data, m + crypto_box_BOXZEROBYTES, sizeof(secret) - crypto_box_BOXZEROBYTES);
  randombytes((uint8_t *)&secret, sizeof(secret));
  _queue(conn, packet);
  return length;
}

static int
fill_keys(rudp_conn_t *conn, rudp_packet_t *packet) {
  memcpy(conn->their_key, packet->data, crypto_box_PUBLICKEYBYTES);
  errno = EINPROGRESS;
  return 0;
}

// needs to have a cookie, and immediately reply
static int
handle_hello(rudp_conn_t *conn, rudp_packet_t *packet) {
  if(fill_keys(conn, packet) == -1) return -1;
  rudp_packet_t *pckt = (rudp_packet_t *)calloc(1, sizeof(rudp_packet_t));
  conn->state = RUDP_KEYS;
  pckt->proto = RUDP_HI;
  memcpy(packet->data, conn->pk, crypto_box_PUBLICKEYBYTES);
  _queue(conn, pckt);
  return -1;
}

static int
handle_hi(rudp_conn_t *conn, rudp_packet_t *packet) {
  if(fill_keys(conn, packet) == -1) return -1;
  if(conn->state != RUDP_KEYS) {
    errno = EINVAL;
    return -1;
  }
  rudp_packet_t *pckt = (rudp_packet_t *)calloc(1, sizeof(rudp_packet_t));
  conn->state = RUDP_CONN;
  pckt->proto = RUDP_DATA;
  _queue(conn, pckt);
  return -1;
}

static int
handle_data(rudp_conn_t *conn, rudp_packet_t *packet, uint8_t **data) {
  // data packet sent too early
  if(conn->state != RUDP_CONN) {
    errno = EINVAL;
    return -1;
  }

  // pad secret
  uint8_t c[RUDP_SECRET_SIZE + crypto_box_BOXZEROBYTES] = {0};
  if(c == NULL) {
    errno = ENOMEM;
    return -1;
  }
  memcpy(c + crypto_box_BOXZEROBYTES, packet->data, RUDP_SECRET_SIZE);

  // decrypt packet
  rudp_secret_t secret;
  memset(&secret, 0, sizeof(secret));
  int err = crypto_box_open((uint8_t *)&secret, c, RUDP_SECRET_SIZE, packet->nonce, conn->their_key, conn->sk);
  if(err == -1) {
    errno = EINVAL;
    return -1;
  }

  // update ack and dequeue acked packets
  while(conn->ack < ntohl(secret.ack)) {
    rudp_packet_t *packet = buffer_delete(conn->out, conn->ack);
    if(packet != NULL) free(packet);
    conn->ack++;
  }

  memcpy(data, secret.data, RUDP_DATA_SIZE);
  randombytes((uint8_t *)&secret, sizeof(secret));

  return 0;
}

int
rudp_recv(rudp_conn_t *conn, uint8_t **data) {
  rudp_packet_t packet;
  socklen_t slen = sizeof(conn->addr);
  recvfrom(conn->socket, (uint8_t*) &packet, sizeof(packet), 0, (struct sockaddr *)&conn->addr, &slen);

  switch(packet.proto) {
    case RUDP_HELLO:
      return handle_hello(conn, &packet);
    case RUDP_HI:
      return handle_hi(conn, &packet);
    case RUDP_DATA:
      return handle_data(conn, &packet, data);
    default: {
      errno = EINVAL;
      return -1;
    }
  }
  return 0;
}