#ifndef _LLALLOC_H_
#define _LLALLOC_H_

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "generalalloc.h"
#include "linkedlist.h"

struct ll_alloc_global {
  pthread_mutex_t mtx;
  struct linked_list_head cache;
  size_t capacity;
  size_t size;
  size_t native_size;
};

struct ll_alloc_local {
  struct ll_alloc_global *glob;
  struct linked_list_head cache;
  size_t capacity;
  size_t size;
  size_t native_size;
};

struct ll_alloc_st {
  struct linked_list_head cache;
  size_t capacity;
  size_t size;
  size_t native_size;
};
#define LL_ALLOC_ST_EMPTY {.size=0}

int ll_alloc_st_init(
  struct ll_alloc_st *st, size_t capacity, size_t native_size);

void ll_alloc_st_free(struct ll_alloc_st *st);

int ll_alloc_global_init(
  struct ll_alloc_global *glob, size_t capacity, size_t native_size);

void ll_alloc_global_free(struct ll_alloc_global *glob);

int ll_alloc_local_init(
  struct ll_alloc_local *loc, struct ll_alloc_global *glob, size_t capacity);

void ll_alloc_local_free(struct ll_alloc_local *loc);

void ll_alloc_fill(struct ll_alloc_local *loc);

void ll_alloc_halve(struct ll_alloc_local *loc);

static inline void *ll_alloc_mt(struct ll_alloc_local *loc, size_t size)
{
  char *buf;
  if (size > loc->native_size)
  {
    buf = malloc(size + sizeof(size_t));
    if (buf == NULL)
    {
      return NULL;
    }
    memcpy(buf, &size, sizeof(size_t));
    return buf + sizeof(size_t);
  }
  size = loc->native_size;
  if (loc->size == 0)
  {
    ll_alloc_fill(loc);
  }
  if (loc->size > 0)
  {
    struct linked_list_node *buf2 = loc->cache.node.next;
    linked_list_delete(buf2);
    loc->size--;
    return buf2;
  }
  buf = malloc(size + sizeof(size_t));
  if (buf == NULL)
  {
    return NULL;
  }
  memcpy(buf, &size, sizeof(size_t));
  return buf + sizeof(size_t);
}

static inline void ll_free_mt(struct ll_alloc_local *loc, void *buf)
{
  size_t size;
  void *allocated_block;
  struct linked_list_node *node;
  if (buf == NULL)
  {
    return;
  }
  allocated_block = alloc_allocated_block(buf);
  memcpy(&size, allocated_block, sizeof(size_t));
  if (size != loc->native_size)
  {
    free(allocated_block);
    return;
  }
  if (loc->size >= loc->capacity)
  {
    ll_alloc_halve(loc);
  }
  node = buf;
  linked_list_add_tail(node, &loc->cache);
  loc->size++;
}

static inline void *ll_alloc_st(struct ll_alloc_st *st, size_t size)
{
  char *buf;
  if (size > st->native_size)
  {
    buf = malloc(size + sizeof(size_t));
    if (buf == NULL)
    {
      return NULL;
    }
    memcpy(buf, &size, sizeof(size_t));
    return buf + sizeof(size_t);
  }
  size = st->native_size;
  if (st->size > 0)
  {
    struct linked_list_node *buf2 = st->cache.node.next;
    linked_list_delete(buf2);
    st->size--;
    return buf2;
  }
  buf = malloc(size + sizeof(size_t));
  if (buf == NULL)
  {
    return NULL;
  }
  memcpy(buf, &size, sizeof(size_t));
  return buf + sizeof(size_t);
}

static inline void ll_free_st(struct ll_alloc_st *st, void *buf)
{
  size_t size;
  void *allocated_block;
  struct linked_list_node *node;
  if (buf == NULL)
  {
    return;
  }
  allocated_block = alloc_allocated_block(buf);
  memcpy(&size, allocated_block, sizeof(size_t));
  if (size != st->native_size || st->size >= st->capacity)
  {
    free(allocated_block);
    return;
  }
  node = buf;
  linked_list_add_tail(node, &st->cache);
  st->size++;
}

extern const struct allocif_ops ll_allocif_ops_mt;
extern const struct allocif_ops ll_allocif_ops_st;

#endif
