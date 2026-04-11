#include "ipcksum.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/time.h>
#include "hdr.h"
#include "iphdr.h"

int main(int argc, char **argv)
{
  char buf[1500] = {0};
  size_t i;
  struct timeval tv1, tv2;
  double diff;
  for (i = 0; i < sizeof(buf); i++)
  {
    buf[i] = i;
  }
  gettimeofday(&tv1, NULL);
  for (i = 0; i < 1000000; i++)
  {
    struct ip_cksum_ctx ctx = IP_CKSUM_CTX_INITER;
    ip_cksum_feed(&ctx, buf, sizeof(buf));
    if (ip_cksum_postprocess(&ctx) == 0)
    {
      abort();
    }
  }
  gettimeofday(&tv2, NULL);
  diff = tv2.tv_sec - tv1.tv_sec + (tv2.tv_usec - tv1.tv_usec)/1000.0/1000.0;
  printf("%g Gbps\n", 8*1000000*sizeof(buf)/diff/1e9);

  return 0;
}
