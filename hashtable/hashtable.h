#ifndef _HASHTABLE_H_
#define _HASHTABLE_H_

#include "hashlist.h"
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>

typedef uint32_t (*hash_fn)(struct hash_list_node *node, void *userdata);

struct hash_table {
  struct hash_list_head *buckets;
  pthread_mutex_t *bucket_mutexes; // Lock order: first
  pthread_mutex_t global_mutex; // Lock order: then
  uint32_t mutex_shift;
  size_t bucketcnt;
  hash_fn fn; 
  void *fn_userdata;
  size_t itemcnt;
};

static inline size_t next_highest_power_of_2(size_t x)
{
  x--;
  x |= x >> 1;
  x |= x >> 2;
  x |= x >> 4;
  x |= x >> 8;
  x |= x >> 16;
#if SIZE_MAX > (4U*1024U*1024U*1024U)
  x |= x >> 32;
#endif
  x++;
  return x;
}

static inline int hash_table_init_impl(
  struct hash_table *table, size_t bucketcnt, hash_fn fn, void *fn_userdata,
  int locked, uint32_t mutex_shift)
{
  size_t i;
  table->bucket_mutexes = NULL;
  table->fn = fn;
  table->fn_userdata = fn_userdata;
  table->itemcnt = 0;
  table->mutex_shift = mutex_shift;
  table->bucketcnt = next_highest_power_of_2(bucketcnt);
  table->buckets = malloc(sizeof(*table->buckets)*table->bucketcnt);
  if (table->buckets == NULL)
  {
    table->fn = NULL;
    table->fn_userdata = NULL;
    table->bucketcnt = 0;
    return -ENOMEM;
  }
  if (locked)
  {
    if (pthread_mutex_init(&table->global_mutex, NULL) != 0)
    {
      table->fn = NULL;
      table->fn_userdata = NULL;
      table->bucketcnt = 0;
      free(table->buckets);
      table->buckets = NULL;
      return -ENOMEM;
    }
    table->bucket_mutexes = malloc(sizeof(*table->bucket_mutexes)*table->bucketcnt >> mutex_shift);
    if (table->bucket_mutexes == NULL)
    {
      table->fn = NULL;
      table->fn_userdata = NULL;
      table->bucketcnt = 0;
      free(table->buckets);
      table->buckets = NULL;
      pthread_mutex_destroy(&table->global_mutex);
      return -ENOMEM;
    }
    for (i = 0; i < table->bucketcnt >> mutex_shift; i++)
    {
      if (pthread_mutex_init(&table->bucket_mutexes[i], NULL) != 0)
      {
        for (;;)
        {
          if (i == 0)
          {
            table->fn = NULL;
            table->fn_userdata = NULL;
            table->bucketcnt = 0;
            free(table->buckets);
            table->buckets = NULL;
            free(table->bucket_mutexes);
            table->bucket_mutexes = NULL;
            return -ENOMEM;
          }
          i--;
          pthread_mutex_destroy(&table->bucket_mutexes[i]);
        }

      }
    }
  }
  for (i = 0; i < table->bucketcnt; i++)
  {
    hash_list_head_init(&table->buckets[i]);
  }
  return 0;
}

static inline int hash_table_init(
  struct hash_table *table, size_t bucketcnt, hash_fn fn, void *fn_userdata)
{
  return hash_table_init_impl(table, bucketcnt, fn, fn_userdata, 0, 0);
}

static inline int hash_table_init_locked(
  struct hash_table *table, size_t bucketcnt, hash_fn fn, void *fn_userdata,
  uint32_t mutex_shift)
{
  return hash_table_init_impl(table, bucketcnt, fn, fn_userdata, 1, mutex_shift);
}

static inline void hash_table_free(struct hash_table *table)
{
  if (table->itemcnt)
  {
    abort();
  }
  if (table->bucket_mutexes)
  {
    size_t i;
    pthread_mutex_destroy(&table->global_mutex);
    for (i = 0; i < table->bucketcnt >> table->mutex_shift; i++)
    {
      pthread_mutex_destroy(&table->bucket_mutexes[i]);
    }
    free(table->bucket_mutexes);
    table->bucket_mutexes = NULL;
  }
  free(table->buckets);
  table->buckets = NULL;
  table->bucketcnt = 0;
  table->fn = NULL;
  table->fn_userdata = NULL;
  table->itemcnt = 0;
}

static inline void hash_table_delete_already_bucket_locked(
  struct hash_table *table, struct hash_list_node *node)
{
  if (table->bucket_mutexes)
  {
    pthread_mutex_lock(&table->global_mutex);
  }
  hash_list_delete(node);
  if (table->itemcnt == 0)
  {
    abort();
  }
  table->itemcnt--;
  if (table->bucket_mutexes)
  {
    pthread_mutex_unlock(&table->global_mutex);
  }
}

static inline void hash_table_delete(
  struct hash_table *table, struct hash_list_node *node, uint32_t hashval)
{
  if (table->bucket_mutexes)
  {
    pthread_mutex_lock(&table->bucket_mutexes[(hashval & (table->bucketcnt - 1)) >> table->mutex_shift]);
    pthread_mutex_lock(&table->global_mutex);
  }
  hash_list_delete(node);
  if (table->itemcnt == 0)
  {
    abort();
  }
  table->itemcnt--;
  if (table->bucket_mutexes)
  {
    pthread_mutex_unlock(&table->global_mutex);
    pthread_mutex_unlock(&table->bucket_mutexes[(hashval & (table->bucketcnt - 1)) >> table->mutex_shift]);
  }
}

static inline void hash_table_add_nogrow_already_bucket_locked(
  struct hash_table *table, struct hash_list_node *node, uint32_t hashval)
{
  if (table->bucket_mutexes)
  {
    pthread_mutex_lock(&table->global_mutex);
  }
  hash_list_add_head(node, &table->buckets[hashval & (table->bucketcnt - 1)]);
  table->itemcnt++;
  if (table->bucket_mutexes)
  {
    pthread_mutex_unlock(&table->global_mutex);
  }
}

static inline void hash_table_add_nogrow(
  struct hash_table *table, struct hash_list_node *node, uint32_t hashval)
{
  if (table->bucket_mutexes)
  {
    pthread_mutex_lock(&table->bucket_mutexes[(hashval & (table->bucketcnt - 1)) >> table->mutex_shift]);
    pthread_mutex_lock(&table->global_mutex);
  }
  hash_list_add_head(node, &table->buckets[hashval & (table->bucketcnt - 1)]);
  table->itemcnt++;
  if (table->bucket_mutexes)
  {
    pthread_mutex_unlock(&table->global_mutex);
    pthread_mutex_unlock(&table->bucket_mutexes[(hashval & (table->bucketcnt - 1)) >> table->mutex_shift]);
  }
}

static inline void hash_table_lock_bucket(
  struct hash_table *table, uint32_t hashval)
{
  if (table->bucket_mutexes)
  {
    pthread_mutex_lock(&table->bucket_mutexes[(hashval & (table->bucketcnt - 1)) >> table->mutex_shift]);
  }
}

static inline void hash_table_unlock_bucket(
  struct hash_table *table, uint32_t hashval)
{
  if (table->bucket_mutexes)
  {
    pthread_mutex_unlock(&table->bucket_mutexes[(hashval & (table->bucketcnt - 1)) >> table->mutex_shift]);
  }
}
static inline void hash_table_lock_next_bucket(
  struct hash_table *table, uint32_t hashval)
{
  if (table->bucket_mutexes)
  {
    uint32_t bucketmutex1 = (uint32_t)((hashval & (table->bucketcnt - 1)) >> table->mutex_shift);
    uint32_t bucketmutex2 = (uint32_t)(((hashval + 1) & (table->bucketcnt - 1)) >> table->mutex_shift);
    if (bucketmutex1 != bucketmutex2)
    {
      pthread_mutex_unlock(&table->bucket_mutexes[bucketmutex1]);
      pthread_mutex_lock(&table->bucket_mutexes[bucketmutex2]);
    }
  }
}

#define HASH_TABLE_FOR_EACH(table, bucket, x) \
  for ((bucket) = 0, x = NULL; x == NULL && (bucket) < (table)->bucketcnt; (bucket)++) \
    HASH_LIST_FOR_EACH(x, &(table)->buckets[bucket])

#define HASH_TABLE_FOR_EACH_SAFE(table, bucket, x, n) \
  for ((bucket) = 0, x = NULL; x == NULL && (bucket) < (table)->bucketcnt; (bucket)++) \
    HASH_LIST_FOR_EACH_SAFE(x, n, &(table)->buckets[bucket])

#define HASH_TABLE_FOR_EACH_POSSIBLE(table, x, hashval) \
  HASH_LIST_FOR_EACH(x, &((table)->buckets[hashval & ((table)->bucketcnt - 1)]))

#define HASH_TABLE_FOR_EACH_POSSIBLE_SAFE(table, x, n, hashval) \
  HASH_LIST_FOR_EACH_SAFE(x, n, &((table)->buckets[hashval & ((table)->bucketcnt - 1)]))

#endif
