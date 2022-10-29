#include <sys/poll.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <pthread.h>
#include "ldp.h"
#include "time64.h"

struct ldp_interface *intf;

struct ctx {
  int id;
};

static void *thrfn(void *arg)
{
  struct ctx *ctx = arg;
  int id = ctx->id;
  uint64_t last_time64 = gettime64();
  uint64_t pkts = 0, bytes = 0;
  uint64_t last_pkts = 0, last_bytes = 0;
  struct ldp_packet pkt_tbl[1000];

  last_time64 = gettime64();
  for (;;)
  {
    int i, num;
    struct pollfd pfds[1];
    uint64_t time64;
    if (ldp_in_eof(intf->inq[id]))
    {
      printf("EOF, exiting thread %d\n", id);
      return NULL;
    }
    pfds[0].fd = intf->inq[id]->fd;
    pfds[0].events = POLLIN;
    if (pfds[0].fd >= 0)
    {
      poll(pfds, 1, 5);
    }
    time64 = gettime64();
    if (time64 - last_time64 > 1000*1000)
    {
      uint64_t pdiff = pkts - last_pkts;
      uint64_t bdiff = bytes - last_bytes;
      double tdiff = (double)(time64 - last_time64);
      printf("thread %d: %g MPPS %g Gbps\n", id,
             (double)pdiff/tdiff, (double)bdiff*8/1000/tdiff);
      last_time64 = time64;
      last_pkts = pkts;
      last_bytes = bytes;
    }
    num = ldp_in_nextpkts(intf->inq[id], pkt_tbl, sizeof(pkt_tbl)/sizeof(*pkt_tbl));
    if (num > 0)
    {
      pkts += (uint64_t)num;
    }
    for (i = 0; i < num; i++)
    {
      struct ldp_packet *pkt = &pkt_tbl[i];
      bytes += pkt->sz;
    }
    ldp_in_deallocate_some(intf->inq[id], pkt_tbl, num);
  }
  return NULL;
}

static int mac_parse(const char *str, char mac[6])
{
  char *nxt, *end;
  char *nxtx;
  unsigned long int uli;
  int i;

  nxtx = strchr(str, 'x');
  if (nxtx != NULL)
  {
    return -EINVAL;
  }

  for (i = 0; i < 6; i++)
  {
    nxt = strchr(str, ':');
    if ((nxt == NULL) != (i == 5))
    {
      return -EINVAL;
    }
    uli = strtoul(str, &end, 16);
    if (end != str + 1 && end != str + 2)
    {
      return -EINVAL;
    }
    if (i == 5)
    {
      if (*end != '\0')
      {
        return -EINVAL;
      }
    }
    else
    {
      if (end != nxt)
      {
        return -EINVAL;
      }
    }
    if (uli > 255)
    {
      return -EINVAL;
    }
    mac[i] = (char)(unsigned char)uli;
    str = nxt+1;
  }
  return 0;
}

int main(int argc, char **argv)
{
  struct ctx *ctx;
  pthread_t *pth;
  size_t num_thr, i;
  char mac[6];

  setlinebuf(stdout);

  if (argc != 3 && argc != 4)
  {
    printf("usage: %s 3 vale1:0 [02:00:00:00:00:01]\n", argv[0]);
    exit(1);
  }

  int num_thr_tmp = atoi(argv[1]);
  if (num_thr_tmp < 1 || num_thr_tmp > 1024)
  {
    printf("usage: %s 3 vale1:0 [02:00:00:00:00:01]\n", argv[0]);
    exit(1);
  }
  num_thr = (size_t)num_thr_tmp;
  if (argc == 4)
  {
    if (mac_parse(argv[3], mac) != 0)
    {
      printf("usage: %s 3 vale1:0 [02:00:00:00:00:01]\n", argv[0]);
      exit(1);
    }
  }
  ctx = malloc(num_thr*sizeof(*ctx));
  pth = malloc(num_thr*sizeof(*pth));
  if (ctx == NULL || pth == NULL)
  {
    printf("out of memory\n");
    exit(1);
  }

  intf = ldp_interface_open(argv[2], (int)num_thr, (int)num_thr);
  if (intf == NULL)
  {
    printf("cannot open %s\n", argv[2]);
    exit(1);
  }

  if (argc == 4 && strncmp(argv[2], "vale", 4) == 0)
  {
    /* Teach VALE learning switch we're on this port */
    char pktdata[14] = {(char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff,
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                        0, 0};
    struct ldp_packet pkt = { .data = pktdata, .sz = sizeof(pktdata) };
    ldp_out_inject(intf->outq[0], &pkt, 1);
    ldp_out_txsync(intf->outq[0]);
  }

  for (i = 0; i < num_thr; i++)
  {
    ctx[i].id = (int)i;
    pthread_create(&pth[i], NULL, thrfn, &ctx[i]);
  }
  for (i = 0; i < num_thr; i++)
  {
    pthread_join(pth[i], NULL);
  }
  return 0;
}
