#include "rudp.h"

// 1k packets per connection -- can buffer ~1.5mb total
#define BUFFER_SIZE 1024
typedef struct rudp_circular_buffer {
  struct sockaddr_storage addr;
  rudp_packet_t *packets[BUFFER_SIZE];
  uint16_t size;
} rudp_circular_buffer_t;

void
buffer_put(rudp_circular_buffer_t *buf, rudp_packet_t *packet, size_t index);

rudp_packet_t *
buffer_get(rudp_circular_buffer_t *buf, size_t index);

rudp_packet_t *
buffer_delete(rudp_circular_buffer_t *buf, size_t index);

bool
has_space(rudp_circular_buffer_t *buf);
