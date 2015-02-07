#include <stdint.h>
#include "tweetnacl.h"
#include <sys/select.h>
#include <sys/socket.h>

// handshake
const uint8_t RUDP_HELLO = (1 << 0); // client -> server
const uint8_t RUDP_HI    = (1 << 1); // server -> client
const uint8_t RUDP_INIT  = (1 << 2); // client -> server

const uint8_t RUDP_BYE   = (1 << 3); // close
const uint8_t RUDP_DATA  = (1 << 4); // encrypted data

#define RUDP_SECRET_SIZE 1088 - 2 - crypto_box_NONCEBYTES - crypto_box_PUBLICKEYBYTES
typedef struct {
  uint8_t proto;
  uint8_t version;
  uint8_t pk[crypto_box_PUBLICKEYBYTES];
  uint8_t nonce[crypto_box_NONCEBYTES];
  uint8_t encrypted[RUDP_SECRET_SIZE]; // always encrypted
} __attribute__((packed)) rudp_packet_t;

#define RUDP_DATA_SIZE RUDP_SECRET_SIZE - 4 - crypto_box_ZEROBYTES
typedef struct {
  uint8_t padding[crypto_box_ZEROBYTES];
  uint16_t ack;
  uint16_t seq;
  uint8_t data[RUDP_DATA_SIZE];
} __attribute__((packed)) rudp_secret_t;

enum rudp_state {
  RUDP_NONE,
  RUDP_KEYS,
  RUDP_CONN
};

// 1k packets per connection -- can buffer ~1.5mb total
#define RUDP_BUFFER_SIZE 1024
typedef struct rudp_circular_buffer {
  rudp_packet_t *packets[RUDP_BUFFER_SIZE];
  uint16_t size;
} rudp_circular_buffer_t;

typedef struct {
  int socket;
  enum rudp_state state;
  uint16_t seq;
  uint16_t ack;
  uint8_t their_key[crypto_box_PUBLICKEYBYTES];
  uint8_t pk[crypto_box_PUBLICKEYBYTES];
  uint8_t sk[crypto_box_SECRETKEYBYTES];
  struct sockaddr_storage addr;
  struct rudp_circular_buffer out;
} rudp_conn_t;

typedef struct {
  int socket;
  // for encrypting cookie packets rotates every 2 minutes
  uint8_t cpk[crypto_box_PUBLICKEYBYTES];
  uint8_t csk[crypto_box_SECRETKEYBYTES];

  time_t last_update;
} rudp_node_t;

rudp_conn_t *
rudp_connect(rudp_node_t *node, struct sockaddr *addr, int port);