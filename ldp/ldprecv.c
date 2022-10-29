#include <sys/poll.h>
#include <stdint.h>
#include <stdio.h>
#include "ldp.h"
#include "time64.h"

struct ldp_interface *intf;

int main(int argc, char **argv)
{
  uint64_t last_time64 = gettime64();
  uint64_t pkts = 0, bytes = 0;
  uint64_t last_pkts = 0, last_bytes = 0;
  struct ldp_packet pkt_tbl[1000];

  setlinebuf(stdout);

  if (argc != 2)
  {
    printf("usage: %s vale1:0\n", argv[0]);
    exit(1);
  }

  intf = ldp_interface_open(argv[1], 1, 1);
  if (intf == NULL)
  {
    printf("cannot open %s\n", argv[1]);
    exit(1);
  }

  last_time64 = gettime64();
  for (;;)
  {
    int i, num;
    struct pollfd pfds[1];
    uint64_t time64;
    if (ldp_in_eof(intf->inq[0]))
    {
      printf("EOF, exiting\n");
      exit(0);
    }
    pfds[0].fd = intf->inq[0]->fd;
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
      printf("%g MPPS %g Gbps\n",
             (double)pdiff/tdiff, (double)bdiff*8/1000/tdiff);
      last_time64 = time64;
      last_pkts = pkts;
      last_bytes = bytes;
    }
    num = ldp_in_nextpkts(intf->inq[0], pkt_tbl, sizeof(pkt_tbl)/sizeof(*pkt_tbl));
    if (num > 0)
    {
      pkts += (uint64_t)num;
    }
    for (i = 0; i < num; i++)
    {
      struct ldp_packet *pkt = &pkt_tbl[i];
      bytes += pkt->sz;
    }
    ldp_in_deallocate_some(intf->inq[0], pkt_tbl, num);
  }
  return 0;
}
