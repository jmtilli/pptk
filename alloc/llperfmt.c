#define _GNU_SOURCE
#include <stddef.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include "queue.h"
#include "llalloc.h"

struct queue queue;
struct ll_alloc_global glob;
const int cachesize = 512;
const int alloc_capacity = 16384;
const int alloc_native_size = 1;
const int queuesize = 8192;

static void *producer(void *ud)
{
  struct queue_cache cache;
  struct ll_alloc_local loc;
  ll_alloc_local_init(&loc, &glob, alloc_capacity);
  if (queue_cache_init(&cache, &queue, cachesize) != 0)
  {
    abort();
  }
  for (;;)
  {
    void *block = ll_alloc_mt(&loc, alloc_native_size);
    queue_cache_enq_one(&cache, block);
  }
}
static void *consumer(void *ud)
{
  uint64_t count = 0;
  struct timeval tv1, tv2;
  void **buf;
  struct ll_alloc_local loc;
  ll_alloc_local_init(&loc, &glob, alloc_capacity);
  buf = malloc((size_t)sizeof(*buf)*(size_t)cachesize);
  if (buf == NULL)
  {
    abort();
  }
  gettimeofday(&tv1, NULL);
  for (;;)
  {
    size_t cnt, i;
    cnt = queue_deq_many(&queue, buf, cachesize);
    for (i = 0; i < cnt; i++)
    {
      if (buf[i] == NULL)
      {
        abort();
      }
      ll_free_mt(&loc, buf[i]);
      count++;
      if ((count & (16*1024*1024 - 1)) == 0)
      {
        double diff;
        gettimeofday(&tv2, NULL);
        diff = (double)(tv2.tv_sec - tv1.tv_sec) + (double)(tv2.tv_usec - tv1.tv_usec)/1000.0/1000.0;
        tv1 = tv2;
        printf("%g Mpps\n", 16*1024*1024/diff/1e6);
        free(buf);
        exit(0);
      }
    }
  }

}

int main(int argc, char **argv)
{
  pthread_t cons, prod;
  cpu_set_t cpuset;

  if (ll_alloc_global_init(&glob, alloc_capacity, alloc_native_size) != 0)
  {
    abort();
  }
  if (queue_init(&queue, queuesize) != 0)
  {
    abort();
  }
  pthread_create(&prod, NULL, producer, NULL);
  pthread_create(&cons, NULL, consumer, NULL);
  CPU_ZERO(&cpuset);
  CPU_SET(0, &cpuset);
  pthread_setaffinity_np(prod, sizeof(cpuset), &cpuset);
  CPU_ZERO(&cpuset);
  CPU_SET(1, &cpuset);
  pthread_setaffinity_np(cons, sizeof(cpuset), &cpuset);
  pthread_join(prod, NULL);
  pthread_join(cons, NULL);
  return 0;
}
