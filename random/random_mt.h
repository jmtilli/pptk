#ifndef _RANDOM_MT_H_
#define _RANDOM_MT_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include "hdr.h"

struct random_mt_ctx {
  int index;
  uint32_t mt[624];
};

void random_mt_ctx_init(struct random_mt_ctx *ctx, uint32_t seed);

void random_mt_twist(struct random_mt_ctx *ctx);

static inline uint32_t random_mt(struct random_mt_ctx *ctx)
{
  uint32_t y;
  if (ctx->index >= 624)
  {
    random_mt_twist(ctx);
  }
  y = ctx->mt[ctx->index];
  y = y ^ (y>>11);
  y = y ^ ((y<<7) & 2636928640U);
  y = y ^ ((y<<15) & 4022730752U);
  y = y ^ (y>>18);
  ctx->index++;
  return y;
}

static inline int32_t random_mt_signed_nonnegative(struct random_mt_ctx *ctx)
{
  return (int32_t)(random_mt(ctx)>>1);
}

static inline double random_mt_real_closed(struct random_mt_ctx *ctx)
{
  // [0,1]
  return random_mt(ctx)*(1.0/4294967295.0); 
}
static inline double random_mt_real_semiopen(struct random_mt_ctx *ctx)
{
  // [0,1)
  return random_mt(ctx)*(1.0/4294967296.0); 
}
static inline double random_mt_real_open(struct random_mt_ctx *ctx)
{
  // (0,1)
  return (((double)random_mt(ctx)) + 0.5)*(1.0/4294967296.0); 
}

void random_mt_bytes(struct random_mt_ctx *ctx, void *buf, size_t bufsiz);

#endif
