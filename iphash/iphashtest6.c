#include "iphash.h"
#include "hashseed.h"
#include "time64.h"

const uint32_t default_initial_tokens = 200;
const uint32_t default_timer_period = (1000*1000);
const uint32_t default_timer_add = 40;
const uint32_t default_hash_size = (0x20000*16);
const uint32_t default_batch_size = 16384;

int main(int argc, char **argv)
{
  struct timer_linkheap heap;
  struct ip_hash hash;
  uint32_t addr;
  size_t iter, inner;
  size_t timer_burst;
  struct timeval tv1, tv2;
  uint32_t tokens;
  timer_linkheap_init(&heap);
  hash_seed_init();
  hash.hash_size = default_hash_size;
  hash.initial_tokens = default_initial_tokens;
  hash.timer_add = default_timer_add;
  hash.timer_period = default_timer_period;
  hash.batch_size = default_batch_size;
  ip_hash_init(&hash, &heap, NULL);
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
    if (timer_burst >= 2)
    {
      printf("timer burst of over 2: %zu\n", timer_burst);
    }
    for (inner = 0; inner < 64; inner++)
    {
      addr = (uint32_t)rand();
      if (!ip_permitted(addr, 24, &hash))
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
  if (use_tiny(&hash))
  {
    for (iter = 0; iter < hash.hash_size; iter++)
    {
      struct ip_hash_entry_tiny *e;
      e = &hash.u.entries_tiny[iter];
      tokens = e->tokens + hash.timer_add;
      if (tokens >= hash.initial_tokens)
      {
        tokens = hash.initial_tokens;
      }
      e->tokens = (uint8_t)tokens;
    }
  }
  else if (use_small(&hash))
  {
    for (iter = 0; iter < hash.hash_size; iter++)
    {
      struct ip_hash_entry_small *e;
      e = &hash.u.entries_small[iter];
      tokens = e->tokens + hash.timer_add;
      if (tokens >= hash.initial_tokens)
      {
        tokens = hash.initial_tokens;
      }
      e->tokens = (uint16_t)tokens;
    }
  }
  else
  {
    for (iter = 0; iter < hash.hash_size; iter++)
    {
      struct ip_hash_entry *e;
      e = &hash.u.entries[iter];
      tokens = e->tokens + hash.timer_add;
      if (tokens >= hash.initial_tokens)
      {
        tokens = hash.initial_tokens;
      }
      e->tokens = tokens;
    }
  }
  gettimeofday(&tv2, NULL);
  printf("%lu us\n", (long)((tv2.tv_sec - tv1.tv_sec)*1000*1000 + tv2.tv_usec - tv1.tv_usec));
  gettimeofday(&tv1, NULL);
  if (use_tiny(&hash))
  {
    for (iter = 0; iter < hash.batch_size; iter++)
    {
      struct ip_hash_entry_tiny *e;
      e = &hash.u.entries_tiny[iter];
      tokens = e->tokens + hash.timer_add;
      if (tokens >= hash.initial_tokens)
      {
        tokens = hash.initial_tokens;
      }
      e->tokens = (uint8_t)tokens;
    }
  }
  else if (use_small(&hash))
  {
    for (iter = 0; iter < hash.batch_size; iter++)
    {
      struct ip_hash_entry_small *e;
      e = &hash.u.entries_small[iter];
      tokens = e->tokens + hash.timer_add;
      if (tokens >= hash.initial_tokens)
      {
        tokens = hash.initial_tokens;
      }
      e->tokens = (uint16_t)tokens;
    }
  }
  else
  {
    for (iter = 0; iter < hash.batch_size; iter++)
    {
      struct ip_hash_entry *e;
      e = &hash.u.entries[iter];
      tokens = e->tokens + hash.timer_add;
      if (tokens >= hash.initial_tokens)
      {
        tokens = hash.initial_tokens;
      }
      e->tokens = tokens;
    }
  }
  gettimeofday(&tv2, NULL);
  printf("%lu us\n", (long)((tv2.tv_sec - tv1.tv_sec)*1000*1000 + tv2.tv_usec - tv1.tv_usec));
  if (use_tiny(&hash))
  {
    free(hash.u.entries_tiny);
  }
  else if (use_small(&hash))
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
