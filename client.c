#include "rudp.h"
#include <memory.h>
#include <errno.h>

rudp_conn_t *
rudp_connect(struct sockaddr_storage addr) {
  rudp_conn_t *conn = calloc(1, sizeof(rudp_conn_t));
  if(conn == NULL) {
  	errno = EINVAL;
  	return NULL;
  }
}


static int
handle_hi(rudp_conn_t *conn, rudp_packet_t *packet) {
  if(conn->state != RUDP_KEYS) {
    errno = EINVAL;
    return -1;
  }
  rudp_packet_t *pckt = (rudp_packet_t *)calloc(1, sizeof(rudp_packet_t));
  conn->state = RUDP_CONN;
  pckt->proto = RUDP_DATA;
  buffer_put(&conn->out, packet, conn->seq);
  return -1;
}