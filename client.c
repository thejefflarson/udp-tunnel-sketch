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
