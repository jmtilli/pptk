#include <stddef.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include "queue.h"

struct queue queue;
const size_t cachesize = 128;

static void *producer(void *ud)
{
  struct queue_cache cache;
  if (queue_cache_init(&cache, &queue, cachesize) != 0)
  {
    abort();
  }
  for (;;)
  {
    queue_cache_enq_one(&cache, NULL);
  }
}
static void *consumer(void *ud)
{
  uint64_t count = 0;
  struct timeval tv1, tv2;
  void **buf;
  buf = malloc(sizeof(*buf)*cachesize);
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
      if (buf[i] != NULL)
      {
        abort();
      }
      count++;
      if ((count & (16*1024*1024 - 1)) == 0)
      {
        double diff;
        gettimeofday(&tv2, NULL);
        diff = (double)(tv2.tv_sec - tv1.tv_sec) + (double)(tv2.tv_usec - tv1.tv_usec)/1000.0/1000.0;
        tv1 = tv2;
        printf("%g Mpps\n", 16*1024*1024/diff/1e6);
        exit(0);
      }
    }
  }

}

int main(int argc, char **argv)
{
  pthread_t cons, prod;
  if (queue_init(&queue, 8000) != 0)
  {
    abort();
  }
  pthread_create(&prod, NULL, producer, NULL);
  pthread_create(&cons, NULL, consumer, NULL);
  pthread_join(prod, NULL);
  pthread_join(cons, NULL);
  return 0;
}
