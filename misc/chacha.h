#ifndef _CHACHA_H_
#define _CHACHA_H_

#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

struct chacha20_ctx {
  char key[32];
  char nonce[12];
  uint32_t counter;
};

static inline void chacha20_init(
  struct chacha20_ctx *ctx, char key[32], char nonce[12])
{
  memcpy(ctx->key, key, 32);
  memcpy(ctx->nonce, nonce, 12);
  ctx->counter = 0;
}

static inline void chacha20_init_deterministic(
  struct chacha20_ctx *ctx)
{
  char key[32] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
  char nonce[12] = {0x00,0x00,0x00,0x09,0x00,0x00,0x00,0x4a,0x00,0x00,0x00,0x00};
  memcpy(ctx->key, key, 32);
  memcpy(ctx->nonce, nonce, 12);
  ctx->counter = 0;
}

static inline int chacha20_init_devrandom(
  struct chacha20_ctx *ctx)
{
  char key[32] = {0};
  char nonce[12] = {0};
  FILE *f;
  f = fopen("/dev/urandom", "r");
  if (f == NULL)
  {
    return -EIO;
  }
  if (fread(key, 32, 1, f) != 1)
  {
    return -EIO;
  }
  if (fread(nonce, 12, 1, f) != 1)
  {
    return -EIO;
  }
  fclose(f);
  memcpy(ctx->key, key, 32);
  memcpy(ctx->nonce, nonce, 12);
  ctx->counter = 0;
  return 0;
}

void chacha20_block(
  char key[32], uint32_t counter, char nonce[12], char out[64]);

static inline void chacha20_next_block(
  struct chacha20_ctx *ctx, char out[64])
{
  chacha20_block(ctx->key, ctx->counter++, ctx->nonce, out);
}

#endif
