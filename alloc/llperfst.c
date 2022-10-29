#include <stddef.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include "llalloc.h"

struct ll_alloc_st st;
const size_t alloc_capacity = 10000;
const size_t alloc_native_size = 1;

int main(int argc, char **argv)
{
  struct timeval tv1, tv2;
  size_t count = 0;
  void *buf[4096];
  int i;

  if (ll_alloc_st_init(&st, alloc_capacity, alloc_native_size) != 0)
  {
    abort();
  }
  for (i = 0; i < 4096; i++)
  {
    buf[i] = ll_alloc_st(&st, alloc_native_size);
  }
  for (i = 0; i < 4096; i++)
  {
    ll_free_st(&st, buf[i]);
  }
  gettimeofday(&tv1, NULL);
  for (;;)
  {
    ll_free_st(&st, ll_alloc_st(&st, alloc_native_size));
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
  return 0;
}
