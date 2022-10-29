#include "hashtable.h"
#include "siphash.h"
#include "timerlink.h"
#include "containerof.h"
#include "iphash.h"
#include "hashseed.h"
#include <sys/time.h>
#include "time64.h"

struct batch_timer_userdata {
  struct ip_hash *hash;
  pthread_rwlock_t *lock;
  size_t start;
  size_t end;
};

static void batch_timer_fn(
  struct timer_link *timer, struct timer_linkheap *heap, void *ud, void *td);

static inline int power_of_2(size_t x)
{
  return (x > 0) && ((x & (x-1)) == 0);
}

void ip_hash_init(struct ip_hash *hash, struct timer_linkheap *heap,
                  pthread_rwlock_t *lock)
{
  size_t i;
  size_t timercnt = hash->hash_size/hash->batch_size;
  if (!power_of_2(hash->hash_size) || !power_of_2(hash->batch_size) ||
      hash->hash_size < hash->batch_size)
  {
    abort();
  }
  hash->timers = malloc(timercnt*sizeof(*hash->timers));
  hash->timerud = malloc(timercnt*sizeof(*hash->timerud));
  for (i = 0; i < timercnt; i++)
  {
    hash->timerud[i].hash = hash;
    hash->timerud[i].start = hash->batch_size*i;
    hash->timerud[i].end = hash->batch_size*(i+1);
    hash->timerud[i].lock = lock;
    hash->timers[i].fn = batch_timer_fn;
    hash->timers[i].userdata = &hash->timerud[i];
    hash->timers[i].time64 = gettime64() + hash->timer_period*i/timercnt;
    timer_linkheap_add(heap, &hash->timers[i]);
  }
  
  if (use_tiny(hash))
  {
    hash->u.entries_tiny = malloc(hash->hash_size*sizeof(*hash->u.entries_tiny));
    for (i = 0; i < hash->hash_size; i++)
    {
      struct ip_hash_entry_tiny *e = &hash->u.entries_tiny[i];
      e->tokens = (uint8_t)hash->initial_tokens;
    }
  }
  else if (use_small(hash))
  {
    hash->u.entries_small = malloc(hash->hash_size*sizeof(*hash->u.entries_small));
    for (i = 0; i < hash->hash_size; i++)
    {
      struct ip_hash_entry_small *e = &hash->u.entries_small[i];
      e->tokens = (uint16_t)hash->initial_tokens;
    }
  }
  else
  {
    hash->u.entries = malloc(hash->hash_size*sizeof(*hash->u.entries));
    for (i = 0; i < hash->hash_size; i++)
    {
      struct ip_hash_entry *e = &hash->u.entries[i];
      e->tokens = hash->initial_tokens;
    }
  }
}

void ip_hash_free(struct ip_hash *hash, struct timer_linkheap *heap)
{
  size_t i;
  size_t timercnt = hash->hash_size/hash->batch_size;
  if (!power_of_2(hash->hash_size) || !power_of_2(hash->batch_size) ||
      hash->hash_size < hash->batch_size)
  {
    abort();
  }
  for (i = 0; i < timercnt; i++)
  {
    timer_linkheap_remove(heap, &hash->timers[i]);
  }
  free(hash->timerud);
  free(hash->timers);
  
  if (use_tiny(hash))
  {
    free(hash->u.entries_tiny);
  }
  else if (use_small(hash))
  {
    free(hash->u.entries_small);
  }
  else
  {
    free(hash->u.entries);
  }
}

int ipv6_permitted(
  const void *src_ip, uint8_t bits, struct ip_hash *hash)
{
  char src_net[16] = {0};
  size_t toset;
  int tomask;
  uint32_t hashval;
  memcpy(src_net, src_ip, 16);
  toset = (128U - bits)/8;
  tomask = (128U - bits)%8;
  memset(src_net + 16 - toset, 0, toset);
  src_net[16-toset-1] &= (char)(uint8_t)~((1<<tomask) - 1);
  hashval = (uint32_t)siphash_buf(hash_seed_get(), src_net, 16)&(hash->hash_size - 1);

  if (use_tiny(hash))
  {
    struct ip_hash_entry_tiny *e = NULL;
    e = &hash->u.entries_tiny[hashval];
    if (e->tokens == 0)
    {
      return 0;
    }
    e->tokens--;
    return 1;
  }
  else if (use_small(hash))
  {
    struct ip_hash_entry_small *e = NULL;
    e = &hash->u.entries_small[hashval];
    if (e->tokens == 0)
    {
      return 0;
    }
    e->tokens--;
    return 1;
  }
  else
  {
    struct ip_hash_entry *e = NULL;
    e = &hash->u.entries[hashval];
    if (e->tokens == 0)
    {
      return 0;
    }
    e->tokens--;
    return 1;
  }
}

int ip_permitted(
  uint32_t src_ip, uint8_t bits, struct ip_hash *hash)
{
  uint32_t bitmask = (~((1U<<(32-bits))-1U)) & 0xFFFFFFFFU;
  uint32_t network = src_ip & bitmask;
  uint32_t hashval = (uint32_t)siphash64(hash_seed_get(), network)&(hash->hash_size - 1);

  if (use_tiny(hash))
  {
    struct ip_hash_entry_tiny *e = NULL;
    e = &hash->u.entries_tiny[hashval];
    if (e->tokens == 0)
    {
      return 0;
    }
    e->tokens--;
    return 1;
  }
  else if (use_small(hash))
  {
    struct ip_hash_entry_small *e = NULL;
    e = &hash->u.entries_small[hashval];
    if (e->tokens == 0)
    {
      return 0;
    }
    e->tokens--;
    return 1;
  }
  else
  {
    struct ip_hash_entry *e = NULL;
    e = &hash->u.entries[hashval];
    if (e->tokens == 0)
    {
      return 0;
    }
    e->tokens--;
    return 1;
  }
}

void ipv6_increment_one(
  const void *src_ip, uint8_t bits, struct ip_hash *hash)
{
  char src_net[16] = {0};
  size_t toset;
  int tomask;
  uint32_t hashval;
  memcpy(src_net, src_ip, 16);
  toset = (128U - bits)/8;
  tomask = (128U - bits)%8;
  memset(src_net + 16 - toset, 0, toset);
  src_net[16-toset-1] &= (char)(uint8_t)~((1<<tomask) - 1);
  hashval = (uint32_t)siphash_buf(hash_seed_get(), src_net, 16)&(hash->hash_size - 1);

  if (use_tiny(hash))
  {
    struct ip_hash_entry_tiny *e = NULL;
    e = &hash->u.entries_tiny[hashval];
    if (e->tokens >= hash->initial_tokens)
    {
      return;
    }
    e->tokens++;
    return;
  }
  else if (use_small(hash))
  {
    struct ip_hash_entry_small *e = NULL;
    e = &hash->u.entries_small[hashval];
    if (e->tokens >= hash->initial_tokens)
    {
      return;
    }
    e->tokens++;
    return;
  }
  else
  {
    struct ip_hash_entry *e = NULL;
    e = &hash->u.entries[hashval];
    if (e->tokens >= hash->initial_tokens)
    {
      return;
    }
    e->tokens++;
    return;
  }
}

void ip_increment_one(
  uint32_t src_ip, uint8_t bits, struct ip_hash *hash)
{
  uint32_t bitmask = (~((1U<<(32-bits))-1U)) & 0xFFFFFFFFU;
  uint32_t network = src_ip & bitmask;
  uint32_t hashval = (uint32_t)siphash64(hash_seed_get(), network)&(hash->hash_size - 1);

  if (use_tiny(hash))
  {
    struct ip_hash_entry_tiny *e = NULL;
    e = &hash->u.entries_tiny[hashval];
    if (e->tokens >= hash->initial_tokens)
    {
      return;
    }
    e->tokens++;
    return;
  }
  else if (use_small(hash))
  {
    struct ip_hash_entry_small *e = NULL;
    e = &hash->u.entries_small[hashval];
    if (e->tokens >= hash->initial_tokens)
    {
      return;
    }
    e->tokens++;
    return;
  }
  else
  {
    struct ip_hash_entry *e = NULL;
    e = &hash->u.entries[hashval];
    if (e->tokens >= hash->initial_tokens)
    {
      return;
    }
    e->tokens++;
    return;
  }
}

static void batch_timer_fn(
  struct timer_link *timer, struct timer_linkheap *heap, void *ud, void *td)
{
  struct batch_timer_userdata *args = ud;
  size_t i;
  uint32_t tokens;
  uint32_t timer_add = args->hash->timer_add;
  uint32_t initial_tokens = args->hash->initial_tokens;
  if (args->lock)
  {
    pthread_rwlock_wrlock(args->lock);
  }
  if (use_tiny(args->hash))
  {
    struct ip_hash_entry_tiny *e;
    for (i = args->start; i < args->end; i++)
    {
      e = &args->hash->u.entries_tiny[i];
      tokens = e->tokens + timer_add;
      if (tokens >= initial_tokens)
      {
        tokens = initial_tokens;
      }
      e->tokens = (uint8_t)tokens;
    }
  }
  else if (use_small(args->hash))
  {
    struct ip_hash_entry_small *e;
    for (i = args->start; i < args->end; i++)
    {
      e = &args->hash->u.entries_small[i];
      tokens = e->tokens + timer_add;
      if (tokens >= initial_tokens)
      {
        tokens = initial_tokens;
      }
      e->tokens = (uint16_t)tokens;
    }
  }
  else
  {
    struct ip_hash_entry *e;
    for (i = args->start; i < args->end; i++)
    {
      e = &args->hash->u.entries[i];
      tokens = e->tokens + timer_add;
      if (tokens >= initial_tokens)
      {
        tokens = initial_tokens;
      }
      e->tokens = tokens;
    }
  }
  timer->time64 += args->hash->timer_period;
  timer_linkheap_add(heap, timer);
  if (args->lock)
  {
    pthread_rwlock_unlock(args->lock);
  }
}
