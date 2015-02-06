#include "rudp.h"

// needs to have a cookie, and immediately reply
static int
handle_hello(rudp_conn_t *conn, rudp_packet_t *packet) {
  if(fill_keys(conn, packet) == -1) return -1;
  rudp_packet_t *pckt = (rudp_packet_t *)calloc(1, sizeof(rudp_packet_t));
  conn->state = RUDP_KEYS;
  pckt->proto = RUDP_HI;
  memcpy(packet->data, conn->pk, crypto_box_PUBLICKEYBYTES);
  buffer_put(&conn->out, packet, conn->seq);
  return -1;
}

rudp_conn_t *
rudp_accept(rudp_node_t *node) {

}