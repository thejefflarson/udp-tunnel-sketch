#include "buffer.h"
#include <memory.h>
#include <stdbool.h>

void
buffer_put(rudp_circular_buffer_t *buf, rudp_packet_t *packet, size_t index){
  buf->packets[index % RUDP_BUFFER_SIZE] = packet;
  buf->size++;
}

rudp_packet_t *
buffer_get(rudp_circular_buffer_t *buf, size_t index){
  return buf->packets[index % RUDP_BUFFER_SIZE];
}

rudp_packet_t *
buffer_delete(rudp_circular_buffer_t *buf, size_t index){
  rudp_packet_t *packet = buffer_get(buf, index);
  buf->packets[index % RUDP_BUFFER_SIZE] = NULL;
  buf->size--;
  return packet;
}

bool
buffer_has_space(rudp_circular_buffer_t *buf) {
  return buf->size < RUDP_BUFFER_SIZE;
}
