#ifndef _IPREASS_H_
#define _IPREASS_H_

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "allocif.h"
#include "packet.h"
#include "ipfrag.h"

struct reassctx {
  struct linked_list_head packet_list;
  struct linked_list_head hole_list;
  struct hole first_hole;
  uint16_t most_restricting_last;
};

void reassctx_init(struct reassctx *ctx);

static inline int reassctx_complete(struct reassctx *ctx)
{
  return linked_list_is_empty(&ctx->hole_list);
}

void reassctx_free(struct allocif *loc, struct reassctx *ctx);

struct packet *
reassctx_reassemble(struct allocif *loc, struct reassctx *ctx);

void reassctx_add(struct reassctx *ctx, struct packet *pkt);

#endif
