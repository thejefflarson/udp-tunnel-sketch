#include "rudp.h"
#include <memory.h>
#include <sys/types.h>
#include <sys/socket.h>

typedef struct {
  uint8_t nonce[crypto_box_NONCEBYTES];
  uint8_t encrypted[crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES + crypto_box_BOXZEROBYTES];
} __attribute__((packed)) hi_secret_t;

// we don't need a packet here, because we are encrypting just to the cookie key
static int
handle_hello(rudp_node_t *node, struct sockaddr_storage addr) {
  uint8_t pk[crypto_box_PUBLICKEYBYTES];
  uint8_t sk[crypto_box_SECRETKEYBYTES];

  rudp_packet_t packet;
  // because we won't be using all fields but we still want it to be random looking
  randombytes((uint8_t *)&packet, sizeof(packet));
  packet.proto = RUDP_HI;

  hi_secret_t hi_secret;
  memset(&hi_secret, 0, sizeof(hi_secret));

  crypto_box_keypair(pk, sk);
  memcpy(packet.pk, pk, sizeof(pk));
  randombytes(hi_secret.nonce, sizeof(hi_secret.nonce));

  uint8_t m[sizeof(hi_secret.encrypted) + crypto_box_BOXZEROBYTES] = {0};
  memcpy(m + crypto_box_ZEROBYTES, sk, sizeof(sk));
  memcpy(m + crypto_box_PUBLICKEYBYTES + crypto_box_ZEROBYTES, pk, sizeof(pk));

  uint8_t c[sizeof(m)] = {0};
  crypto_box(c, m, sizeof(m), hi_secret.nonce, node->cpk, node->csk);

  memcpy(hi_secret.encrypted, c + crypto_box_BOXZEROBYTES, sizeof(hi_secret.encrypted));
  memcpy(packet.encrypted, &hi_secret, sizeof(hi_secret));

  return sendto(node->socket, &packet, sizeof(packet), 0, (struct sockaddr *)&addr, sizeof(addr));
}

static rudp_conn_t *
handle_init(rudp_node_t *node, rudp_packet_t *packet) {
  rudp_conn_t *conn = calloc(1, sizeof(rudp_conn_t));
  conn->socket = node->socket;



  // decrypt cookie packet
  // fill in connection fields
  // return a new connection
}

rudp_conn_t *
rudp_accept(rudp_node_t *node) {

}