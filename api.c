#import "rudp.h"


void
server(){

}

void
client(){

}


int
main(int argc, char **argv) {
  // server

  rudp_conn_t *conn1 = NULL, *conn2 = NULL;
  conn1 = rudp_accept(server);
  rudp_send(conn1, "hello", length);

  conn2 = rudp_connect(client, addr, port);
  rudp_send(conn2, "world", length);

  rudp_recv(conn1, &data, length);
  rudp_recv(conn2, &data, length);

  rudp_conn_close(conn1);
  rudp_conn_close(conn2);

  rudp_server_close(server);
};