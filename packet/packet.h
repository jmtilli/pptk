#ifndef _PACKET_H_
#define _PACKET_H_

#include "linkedlist.h"
#include "rbtree.h"
#include <stddef.h>
#include <stdint.h>

enum packet_direction {
  PACKET_DIRECTION_UPLINK = 0,
  PACKET_DIRECTION_DOWNLINK = 1,
};

struct hole {
  struct linked_list_node node;
  uint16_t first;
  uint16_t last;
};

struct rbhole {
  struct rb_tree_node node;
  uint16_t first;
  uint16_t last;
};

struct rbtcppositive {
  struct rb_tree_node node;
  uint32_t first;
  uint32_t last;
};

struct positive {
  uint32_t flags;
  uint16_t offset;
  uint16_t pulled;
};

struct packet {
  struct linked_list_node node;
  union {
    struct hole hole;
    struct rbhole rbhole;
    struct positive positive;
    struct rbtcppositive rbtcppositive;
  } u;
  enum packet_direction direction;
  size_t sz;
  void *data;
  // after this: packet data
};

static inline void *packet_calc_data(struct packet *pkt)
{
  return ((char*)pkt) + sizeof(struct packet);
}

static inline void *packet_data(struct packet *pkt)
{
  return pkt->data;
}

static inline const void *packet_const_data(const struct packet *pkt)
{
  return pkt->data;
}

static inline size_t packet_size(size_t sz)
{
  return sz + sizeof(struct packet);
}

#endif
