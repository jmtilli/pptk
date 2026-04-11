#ifndef _IPRB815_H_
#define _IPRB815_H_

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "allocif.h"
#include "packet.h"
#include "ipfrag.h"

struct rb815hole {
  uint16_t len;
  uint16_t parent_div_8:13;
  uint16_t parent_valid:1;
  uint16_t spare1:2;
  uint16_t left_div_8:13;
  uint16_t left_valid:1;
  uint16_t spare2:2;
  uint16_t right_div_8:13;
  uint16_t right_valid:1;
  uint16_t is_black:1;
  uint16_t spare3:1;
};
#define RB815HOLE_EMPTY {.len=0}

#define RB815_HOLE_NULL (65535)

struct rb815ctx {
  uint16_t root_hole; // 65535 == NULL
  uint16_t most_restricting_last;
  size_t hdr_len;
  enum packet_direction direction;
  char pkt_header[128];
  char pkt[65535];
};

void rb815ctx_init(struct rb815ctx *ctx);

void rb815ctx_init_fast(struct rb815ctx *ctx);

static inline int rb815ctx_complete(struct rb815ctx *ctx)
{
  return ctx->root_hole == RB815_HOLE_NULL;
}

struct packet *
rb815ctx_reassemble(struct allocif *loc, struct rb815ctx *ctx);

void rb815ctx_add(struct rb815ctx *ctx, struct packet *pkt);

#endif
