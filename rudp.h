#include <stdint.h>
#include "tweetnacl.h"
#include <sys/select.h>
#include <sys/socket.h>

const uint8_t RUDP_HELLO = (1 << 0); // syn pubkey
const uint8_t RUDP_HI    = (1 << 1); // ack pubkey
const uint8_t RUDP_BYE   = (1 << 2); // close
const uint8_t RUDP_DATA  = (1 << 3); // encrypted data

#define RUDP_SECRET_SIZE 1024 - 1 - crypto_box_NONCEBYTES
typedef struct {
  uint8_t proto;
  uint8_t encrypted[RUDP_SECRET_SIZE]; // always encrypted
  uint8_t nonce[crypto_box_NONCEBYTES];
} __attribute__((packed)) rudp_packet_t;

#define RUDP_DATA_SIZE RUDP_SECRET_SIZE - 4 - crypto_box_ZEROBYTES
typedef struct {
  uint8_t padding[crypto_box_ZEROBYTES];
  uint16_t ack;
  uint16_t seq;
  uint8_t data[RUDP_DATA_SIZE];
} __attribute__((packed)) rudp_secret_t;

enum state {
  RUDP_INIT,
  RUDP_KEYS,
  RUDP_CONN
};

// 1k packets per connection -- can buffer ~1.5mb total
#define RUDP_BUFFER_SIZE 1024
typedef struct rudp_circular_buffer {
  rudp_packet_t *packets[RUDP_BUFFER_SIZE];
  uint16_t size;
} rudp_circular_buffer_t;

typedef struct rudp_conn {
  int socket;
  enum state state;
  uint16_t seq;
  uint16_t ack;
  uint8_t their_key[crypto_box_PUBLICKEYBYTES];
  uint8_t pk[crypto_box_PUBLICKEYBYTES];
  uint8_t sk[crypto_box_SECRETKEYBYTES];
  struct sockaddr_storage addr; // can mebbe delete this in place of their key? fft
  struct rudp_circular_buffer out;
  struct rudp_circular_buffer in;
} rudp_conn_t;

rudp_conn_t *
rudp_connect(struct sockaddr_storage addr);