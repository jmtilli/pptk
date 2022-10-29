#include "allocif.h"
#include "llalloc.h"
#include "time64.h"

int main(int argc, char **argv)
{
  struct ll_alloc_st st = {};
  struct allocif intf = {.ops = &ll_allocif_ops_st, .userdata = &st};
  void *block;
  int i;
  uint64_t begin, end;

  ll_alloc_st_init(&st, 1000, 4096);

  begin = gettime64();
  for (i = 0; i < 100*1000*1000; i++)
  {
    block = allocif_alloc(&intf, 1024);
    allocif_free(&intf, block);
  }
  end = gettime64();
  printf("%g MPPS indirect\n", 1e8/(double)(end-begin));

  begin = gettime64();
  for (i = 0; i < 100*1000*1000; i++)
  {
    block = ll_alloc_st(&st, 1024);
    ll_free_st(&st, block);
  }
  end = gettime64();
  printf("%g MPPS direct\n", 1e8/(double)(end-begin));

  ll_alloc_st_free(&st);

  return 0;
}
