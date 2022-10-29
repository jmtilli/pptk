#define _GNU_SOURCE
#include <pthread.h>
#include "iphdr.h"
#include "ipcksum.h"
#include <sys/poll.h>
#include "time64.h"
#include "ldp.h"

struct ldp_interface *dlintf, *ulintf;

int main(int argc, char **argv)
{
  uint64_t last_time64 = gettime64();
  uint64_t ulpkts = 0, ulbytes = 0, dlpkts = 0, dlbytes = 0;
  uint64_t last_ulpkts = 0, last_ulbytes = 0, last_dlpkts = 0, last_dlbytes = 0;
  const int iters = 1;
  int iter;
  char ethersrc[6] = {2,0,0,0,0,1};
  char etherdst[6] = {2,0,0,0,0,2};
  struct ldp_packet pkts[1024];
  struct ldp_chunkpacket chunkpkts[1024] = {};
  struct iovec iovs[1024][2] = {};
  char tunnelhdrs[1024][14+20+4] = {};
  uint32_t ipsrc = (10<<24)|1;
  uint32_t ipdst = (10<<24)|2;
  void *ether, *ip, *gre;
  int num, i;

  for (i = 0; i < 1024; i++)
  {
    ether = tunnelhdrs[i];
    memcpy(ether_dst(ether), etherdst, 6);
    memcpy(ether_src(ether), ethersrc, 6);
    ether_set_type(ether, 0x0800);
    ip = ether_payload(ether);
    ip_set_version(ip, 4);
    ip_set_hdr_len(ip, 20);
    ip_set_dont_frag(ip, 1);
    ip_set_id(ip, 0);
    ip_set_ttl(ip, 64);
    ip_set_proto(ip, 47);
    ip_set_src(ip, ipsrc);
    ip_set_dst(ip, ipdst);
    gre = ip_payload(ip);
    hdr_set16n(((char*)gre)+2, 0x6558);
  }


  setlinebuf(stdout);

  if (argc != 3)
  {
    printf("usage: %s vale0:1 vale1:1\n", argv[0]);
    exit(1);
  }

  dlintf = ldp_interface_open(argv[1], 1, 1);
  if (dlintf == NULL)
  {
    printf("cannot open %s\n", argv[1]);
    exit(1);
  }

  ulintf = ldp_interface_open(argv[2], 1, 1);
  if (ulintf == NULL)
  {
    printf("cannot open %s\n", argv[1]);
    exit(1);
  }

  last_time64 = gettime64();
  for (;;)
  {
    struct pollfd pfds[2];
    uint64_t time64;

    if (ldp_in_eof(ulintf->inq[0]) &&
        ldp_in_eof(dlintf->inq[0]))
    {
      printf("EOF, exiting\n");
      exit(0);
    }

    ldp_out_txsync(ulintf->outq[0]);
    ldp_out_txsync(dlintf->outq[0]);

    pfds[0].fd = dlintf->inq[0]->fd;
    pfds[0].events = POLLIN;
    pfds[1].fd = ulintf->inq[0]->fd;
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
      printf("%g MPPS %g Gbps ul, %g MPPS %g Gbps dl\n",
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
      num = ldp_in_nextpkts(dlintf->inq[0], pkts, sizeof(pkts)/sizeof(*pkts));
      if (num < 0)
      {
        num = 0;
        break;
      }
      for (i = 0; i < num; i++)
      {
        ulpkts++;
        ulbytes += pkts[i].sz;

        ip = ether_payload((void*)tunnelhdrs[i]);
        ip_set_total_len(ip, (uint16_t)(pkts[i].sz+4+20)); // XXX int overflow
        ip_set_hdr_cksum_calc(ip, 20);
        iovs[i][0].iov_base = tunnelhdrs[i];
        iovs[i][0].iov_len = 14+20+4;
        iovs[i][1].iov_base = pkts[i].data;
        iovs[i][1].iov_len = pkts[i].sz;
        chunkpkts[i].iov = iovs[i];
        chunkpkts[i].iovlen = 2;
      }
      ldp_out_inject_chunk(ulintf->outq[0], chunkpkts, num);
      ldp_in_deallocate_some(dlintf->inq[0], pkts, num);
    }

    for (iter = 0; iter < iters; iter++)
    {
      int numchunk = 0;
      num = ldp_in_nextpkts(ulintf->inq[0], pkts, sizeof(pkts)/sizeof(*pkts));
      if (num < 0)
      {
        num = 0;
        break;
      }
      for (i = 0; i < num; i++)
      {
        dlpkts++;
        dlbytes += pkts[i].sz;
        printf("sz %zu\n", (size_t)pkts[i].sz);

        if (pkts[i].sz >= 14+20+4)
        {
          iovs[i][0].iov_base = ((char*)pkts[i].data) + 14 + 20 + 4;
          iovs[i][0].iov_len = pkts[i].sz - 14 - 20 - 4;
          chunkpkts[numchunk].iov = iovs[i];
          chunkpkts[numchunk].iovlen = 1;
          numchunk++;
        }
      }
      ldp_out_inject_chunk(dlintf->outq[0], chunkpkts, numchunk);
      ldp_in_deallocate_some(ulintf->inq[0], pkts, num);
    }

  }
  return 0;
}
