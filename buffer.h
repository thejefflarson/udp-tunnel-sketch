#include "rudp.h"

void
buffer_put(rudp_circular_buffer_t *buf, rudp_packet_t *packet, size_t index);

rudp_packet_t *
buffer_get(rudp_circular_buffer_t *buf, size_t index);

rudp_packet_t *
buffer_delete(rudp_circular_buffer_t *buf, size_t index);

bool
buffer_has_space(rudp_circular_buffer_t *buf);
