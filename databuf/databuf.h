#ifndef _DATABUF_H_
#define _DATABUF_H_

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

struct datainbuf {
  const char *buf;
  size_t size;
  size_t location;
  int errors;
};

struct databuf {
  char *buf;
  size_t capacity;
  size_t size;
  int errors;
};

#define DATABUF_INITER { \
  .buf = NULL, \
  .capacity = 0, \
  .size = 0, \
  .errors = 0, \
}

void datainbuf_init(struct datainbuf *inbuf, const void *buf, size_t sz);

void databuf_init(struct databuf *buf);

void databuf_free(struct databuf *buf);

int databuf_extend(struct databuf *buf, size_t extend);

static inline int databuf_ensure_extend(struct databuf *buf, size_t extend)
{
  if (buf->size + extend <= buf->capacity)
  {
    return 0;
  }
  return databuf_extend(buf, extend);
}

static inline int databuf_add_bytes(struct databuf *buf, void *bytes, size_t sz)
{
  int result;
  result = databuf_ensure_extend(buf, sz);
  if (result)
  {
    return result;
  }
  memcpy(&buf->buf[buf->size], bytes, sz);
  buf->size += sz;
  return 0;
}

static inline int datainbuf_get_u64(struct datainbuf *buf, uint64_t *u64ptr)
{
  uint64_t u64 = 0;
  if (buf->location + 8 > buf->size)
  {
    return -EFAULT;
  }
  u64 |= (uint8_t)buf->buf[buf->location++];
  u64 <<= 8;
  u64 |= (uint8_t)buf->buf[buf->location++];
  u64 <<= 8;
  u64 |= (uint8_t)buf->buf[buf->location++];
  u64 <<= 8;
  u64 |= (uint8_t)buf->buf[buf->location++];
  u64 <<= 8;
  u64 |= (uint8_t)buf->buf[buf->location++];
  u64 <<= 8;
  u64 |= (uint8_t)buf->buf[buf->location++];
  u64 <<= 8;
  u64 |= (uint8_t)buf->buf[buf->location++];
  u64 <<= 8;
  u64 |= (uint8_t)buf->buf[buf->location++];
  *u64ptr = u64;
  return 0;
}

static inline int datainbuf_get_u32(struct datainbuf *buf, uint32_t *u32ptr)
{
  uint32_t u32 = 0;
  if (buf->location + 4 > buf->size)
  {
    return -EFAULT;
  }
  u32 |= (uint8_t)buf->buf[buf->location++];
  u32 <<= 8;
  u32 |= (uint8_t)buf->buf[buf->location++];
  u32 <<= 8;
  u32 |= (uint8_t)buf->buf[buf->location++];
  u32 <<= 8;
  u32 |= (uint8_t)buf->buf[buf->location++];
  *u32ptr = u32;
  return 0;
}

static inline int datainbuf_get_u16(struct datainbuf *buf, uint16_t *u16ptr)
{
  uint16_t u16 = 0;
  if (buf->location + 2 > buf->size)
  {
    return -EFAULT;
  }
  u16 |= (uint16_t)(uint8_t)buf->buf[buf->location++];
  u16 = (uint16_t)(u16 << 8);
  u16 |= (uint16_t)(uint8_t)buf->buf[buf->location++];
  *u16ptr = u16;
  return 0;
}

static inline int datainbuf_get_u8(struct datainbuf *buf, uint8_t *u8ptr)
{
  uint8_t u8 = 0;
  if (buf->location + 1 > buf->size)
  {
    return -EFAULT;
  }
  u8 |= (uint8_t)buf->buf[buf->location++];
  *u8ptr = u8;
  return 0;
}

static inline int datainbuf_get_bytes(struct datainbuf *buf, void *b, size_t sz)
{
  if (buf->location + sz > buf->size)
  {
    return -EFAULT;
  }
  memcpy(b, &buf->buf[buf->location], sz);
  buf->location += sz;
  return 0;
}

static inline int databuf_add_u64(struct databuf *buf, uint64_t u64)
{
  int result;
  result = databuf_ensure_extend(buf, 8);
  if (result)
  {
    return result;
  }
  buf->buf[buf->size++] = (char)((u64>>56)&0xFF);
  buf->buf[buf->size++] = (char)((u64>>48)&0xFF);
  buf->buf[buf->size++] = (char)((u64>>40)&0xFF);
  buf->buf[buf->size++] = (char)((u64>>32)&0xFF);
  buf->buf[buf->size++] = (char)((u64>>24)&0xFF);
  buf->buf[buf->size++] = (char)((u64>>16)&0xFF);
  buf->buf[buf->size++] = (char)((u64>>8)&0xFF);
  buf->buf[buf->size++] = (char)((u64>>0)&0xFF);
  return 0;
}

static inline int databuf_add_u32(struct databuf *buf, uint32_t u32)
{
  int result;
  result = databuf_ensure_extend(buf, 4);
  if (result)
  {
    return result;
  }
  buf->buf[buf->size++] = (char)((u32>>24)&0xFF);
  buf->buf[buf->size++] = (char)((u32>>16)&0xFF);
  buf->buf[buf->size++] = (char)((u32>>8)&0xFF);
  buf->buf[buf->size++] = (char)((u32>>0)&0xFF);
  return 0;
}

static inline int datainbuf_eof(struct datainbuf *inbuf)
{
  return inbuf->size == inbuf->location;
}

#endif
