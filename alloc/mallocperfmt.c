#define _GNU_SOURCE
#include <stddef.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include "queue.h"

struct queue queue;
const int cachesize = 512;
const int alloc_native_size = 16;
const int queuesize = 8192;

static void *producer(void *ud)
{
  struct queue_cache cache;
  if (queue_cache_init(&cache, &queue, cachesize) != 0)
  {
    abort();
  }
  for (;;)
  {
    void *block = malloc(alloc_native_size);
    queue_cache_enq_one(&cache, block);
  }
}
static void *consumer(void *ud)
{
  uint64_t count = 0;
  struct timeval tv1, tv2;
  void **buf;
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
      free(buf[i]);
      count++;
      if ((count & (1024*1024 - 1)) == 0)
      {
        double diff;
        gettimeofday(&tv2, NULL);
        diff = (double)(tv2.tv_sec - tv1.tv_sec) + (double)(tv2.tv_usec - tv1.tv_usec)/1000.0/1000.0;
        tv1 = tv2;
        printf("%g Mpps\n", 1024*1024/diff/1e6);
        exit(0);
      }
    }
  }

}

int main(int argc, char **argv)
{
  pthread_t cons, prod;
  cpu_set_t cpuset;
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
