#include "hashtable.h"
#include "murmur.h"
#include "timerlink.h"
#include "containerof.h"
#include <sys/time.h>
#include "time64.h"

const uint32_t initial_tokens = 2000;
const uint32_t timer_period = (1000*1000);
const uint32_t timer_add = 400;
const uint32_t hash_size = 0x20000;
const uint32_t batch_size = 16384;

struct ip_hash_entry4 {
  uint32_t tokens;
};

struct ip_hash_entry4small {
  uint16_t tokens;
};

struct ip_hash4 {
  union {
    struct ip_hash_entry4 *entries;
    struct ip_hash_entry4small *entries_small;
  } u;
};

static inline int use_small(void)
{
  return initial_tokens <= 65535;
}

void ip_hash_timer_fn(struct timer_link *timer, struct timer_linkheap *heap, void *ud, void *td);

static void ip_hash_init(struct ip_hash4 *hash)
{
  size_t i;
  if (use_small())
  {
    hash->u.entries_small = malloc(hash_size*sizeof(*hash->u.entries_small));
    for (i = 0; i < hash_size; i++)
    {
      struct ip_hash_entry4small *e = &hash->u.entries_small[i];
      e->tokens = initial_tokens;
    }
  }
  else
  {
    hash->u.entries = malloc(hash_size*sizeof(*hash->u.entries));
    for (i = 0; i < hash_size; i++)
    {
      struct ip_hash_entry4 *e = &hash->u.entries[i];
      e->tokens = initial_tokens;
    }
  }
}

static int ip_permitted(
  uint32_t src_ip, struct timer_linkheap *heap, struct ip_hash4 *hash)
{
  uint32_t class_c = src_ip&0xFFFFFF00U;
  uint32_t hashval = murmur32(0x12345678U, class_c)&(hash_size - 1);
  if (use_small())
  {
    struct ip_hash_entry4small *e = NULL;
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
    struct ip_hash_entry4 *e = NULL;
    e = &hash->u.entries[hashval];
    if (e->tokens == 0)
    {
      return 0;
    }
    e->tokens--;
    return 1;
  }
}

struct batch_timer_userdata {
  struct ip_hash4 *hash;
  size_t start;
  size_t end;
};

static void batch_timer_fn(
  struct timer_link *timer, struct timer_linkheap *heap, void *ud, void *td)
{
  struct batch_timer_userdata *args = ud;
  size_t i;
  uint32_t tokens;
  if (use_small())
  {
    struct ip_hash_entry4small *e;
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
    struct ip_hash_entry4 *e;
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
  timer->time64 += timer_period;
  timer_linkheap_add(heap, timer);
}

int main(int argc, char **argv)
{
  struct timer_linkheap heap;
  struct ip_hash4 hash;
  uint32_t addr;
  size_t iter, inner;
  size_t timer_burst;
  struct timeval tv1, tv2;
  struct batch_timer_userdata timerud[hash_size/batch_size];
  struct timer_link timers[hash_size/batch_size];
  size_t timercnt;
  uint32_t tokens;
  timer_linkheap_init(&heap);
  ip_hash_init(&hash);
  timercnt = sizeof(timers)/sizeof(*timers);
  for (iter = 0; iter < sizeof(timers)/sizeof(*timers); iter++)
  {
    timerud[iter].hash = &hash;
    timerud[iter].start = batch_size*iter;
    timerud[iter].end = batch_size*(iter+1);
    timers[iter].fn = batch_timer_fn;
    timers[iter].userdata = &timerud[iter];
    timers[iter].time64 = gettime64() + timer_period*iter/timercnt;
  }
  iter = 0;
  while (iter < 128*1024*1024)
  {
    timer_burst = 0;
    while (gettime64() >= timer_linkheap_next_expiry_time(&heap))
    {
      struct timer_link *timer = timer_linkheap_next_expiry_timer(&heap);
      timer_linkheap_remove(&heap, timer);
      timer->fn(timer, &heap, timer->userdata, NULL);
      timer_burst++;
    }
    if (timer_burst >= 5000)
    {
      printf("timer burst of over 5000: %zu\n", timer_burst);
    }
    for (inner = 0; inner < 64; inner++)
    {
      addr = (uint32_t)rand();
      if (!ip_permitted(addr, &heap, &hash))
      {
        printf("not permitted at iter %zu\n", iter);
      }
      iter++;
      if ((iter & ((1<<20) - 1)) == 0)
      {
        printf("iter %zu\n", iter);
      }
    }
  }
  while (heap.size)
  {
    struct timer_link *timer = timer_linkheap_next_expiry_timer(&heap);
    timer_linkheap_remove(&heap, timer);
  }
  gettimeofday(&tv1, NULL);
  if (use_small())
  {
    for (iter = 0; iter < hash_size; iter++)
    {
      struct ip_hash_entry4small *e;
      e = &hash.u.entries_small[iter];
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
    for (iter = 0; iter < hash_size; iter++)
    {
      struct ip_hash_entry4 *e;
      e = &hash.u.entries[iter];
      tokens = e->tokens + timer_add;
      if (tokens >= initial_tokens)
      {
        tokens = initial_tokens;
      }
      e->tokens = tokens;
    }
  }
  gettimeofday(&tv2, NULL);
  printf("%lu us\n", (long)((tv2.tv_sec - tv1.tv_sec)*1000*1000 + tv2.tv_usec - tv1.tv_usec));
  gettimeofday(&tv1, NULL);
  if (use_small())
  {
    for (iter = 0; iter < batch_size; iter++)
    {
      struct ip_hash_entry4small *e;
      e = &hash.u.entries_small[iter];
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
    for (iter = 0; iter < batch_size; iter++)
    {
      struct ip_hash_entry4 *e;
      e = &hash.u.entries[iter];
      tokens = e->tokens + timer_add;
      if (tokens >= initial_tokens)
      {
        tokens = initial_tokens;
      }
      e->tokens = tokens;
    }
  }
  gettimeofday(&tv2, NULL);
  printf("%lu us\n", (long)((tv2.tv_sec - tv1.tv_sec)*1000*1000 + tv2.tv_usec - tv1.tv_usec));
  if (use_small())
  {
    free(hash.u.entries_small);
  }
  else
  {
    free(hash.u.entries);
  }
  timer_linkheap_free(&heap);
  return 0;
}
