#define _GNU_SOURCE
#include <pthread.h>
#include "iphdr.h"
#include "ipcksum.h"
#include <sys/poll.h>
#include "time64.h"
#include "ldp.h"

struct ldp_interface *dlintf, *ulintf;

struct thr_ctx {
  int id;
};

static void *thr(void *arg)
{
  int num, i;
  uint64_t last_time64 = gettime64();
  uint64_t ulpkts = 0, ulbytes = 0, dlpkts = 0, dlbytes = 0;
  uint64_t last_ulpkts = 0, last_ulbytes = 0, last_dlpkts = 0, last_dlbytes = 0;
  const int iters = 1;
  int iter;
  struct ldp_packet pkts[1024];
  struct thr_ctx *ctx = arg;
  int thrid = ctx->id;

  last_time64 = gettime64();
  for (;;)
  {
    struct pollfd pfds[2];
    uint64_t time64;

    if (ldp_in_eof(ulintf->inq[thrid]) &&
        ldp_in_eof(dlintf->inq[thrid]))
    {
      printf("EOF, exiting\n");
      exit(0);
    }

    ldp_out_txsync(ulintf->outq[thrid]);
    ldp_out_txsync(dlintf->outq[thrid]);

    pfds[0].fd = dlintf->inq[thrid]->fd;
    pfds[0].events = POLLIN;
    pfds[1].fd = ulintf->inq[thrid]->fd;
    pfds[1].events = POLLIN;
    if (pfds[0].fd >= 0 && pfds[1].fd >= 0)
    {
      poll(pfds, 2, 5);
    }
    time64 = gettime64();
    if (time64 - last_time64 > 1000*1000)
    {
      uint64_t ulpdiff = ulpkts - last_ulpkts;
      uint64_t dlpdiff = dlpkts - last_dlpkts;
      uint64_t ulbdiff = ulbytes - last_ulbytes;
      uint64_t dlbdiff = dlbytes - last_dlbytes;
      double tdiff = (double)(time64 - last_time64);
      printf("thread/%d: %g MPPS %g Gbps ul, %g MPPS %g Gbps dl\n",
             thrid,
             (double)ulpdiff/tdiff, (double)ulbdiff*8/1000/tdiff,
             (double)dlpdiff/tdiff, (double)dlbdiff*8/1000/tdiff);
      last_time64 = time64;
      last_ulpkts = ulpkts;
      last_dlpkts = dlpkts;
      last_ulbytes = ulbytes;
      last_dlbytes = dlbytes;
    }

    for (iter = 0; iter < iters; iter++)
    {
      num = ldp_in_nextpkts(dlintf->inq[thrid], pkts, sizeof(pkts)/sizeof(*pkts));
      if (num < 0)
      {
        num = 0;
        break;
      }
      for (i = 0; i < num; i++)
      {
        ulpkts++;
        ulbytes += pkts[i].sz;
      }
      int c;
      c = ldp_inout_inject_dealloc(dlintf->inq[thrid], ulintf->outq[thrid], pkts, num);
      if (c < 0)
      {
        c = 0;
      }
      ldp_in_deallocate_some(dlintf->inq[thrid], pkts+c, num-c);
    }

    for (iter = 0; iter < iters; iter++)
    {
      num = ldp_in_nextpkts(ulintf->inq[thrid], pkts, sizeof(pkts)/sizeof(*pkts));
      if (num < 0)
      {
        num = 0;
        break;
      }
      for (i = 0; i < num; i++)
      {
        dlpkts++;
        dlbytes += pkts[i].sz;
      }
      int c;
      c = ldp_inout_inject_dealloc(ulintf->inq[thrid], dlintf->outq[thrid], pkts, num);
      if (c < 0)
      {
        c = 0;
      }
      ldp_in_deallocate_some(ulintf->inq[thrid], pkts+c, num-c);
    }

  }
}

int main(int argc, char **argv)
{
  int i;
  int numthr;
  pthread_t thrs[1024];
  struct thr_ctx thrctxs[1024];

  setlinebuf(stdout);

  if (argc != 4)
  {
    printf("usage: %s vale0:1 vale1:1 3\n", argv[0]);
    exit(1);
  }

  numthr = atoi(argv[3]);
  if (numthr <= 0 || numthr > 1024)
  {
    printf("usage: %s vale0:1 vale1:1 3\n", argv[0]);
    exit(1);
  }

  dlintf = ldp_interface_open(argv[1], numthr, numthr);
  if (dlintf == NULL)
  {
    printf("cannot open %s\n", argv[1]);
    exit(1);
  }

  ulintf = ldp_interface_open(argv[2], numthr, numthr);
  if (ulintf == NULL)
  {
    printf("cannot open %s\n", argv[1]);
    exit(1);
  }

  for (i = 0; i < numthr; i++)
  {
    thrctxs[i].id = i;
    pthread_create(&thrs[i], NULL, thr, &thrctxs[i]);
  }
  for (i = 0; i < numthr; i++)
  {
    pthread_join(thrs[i], NULL);
  }

  return 0;
}
