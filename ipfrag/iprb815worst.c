#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "llalloc.h"
#include "iphdr.h"
#include "packet.h"
#include "ipcksum.h"
#include "ipfrag.h"
#include "containerof.h"
#include "iprb815.h"
#include "time64.h"

int main(int argc, char **argv)
{
  struct ll_alloc_st st;
  struct allocif intf = {.ops = &ll_allocif_ops_st, .userdata = &st};
  struct fragment fragment[1];
  char pkt[65535] = {0};
  size_t sz = sizeof(pkt);
  char *ether = pkt;
  char *ip;
  char *tcp;
  char edst[6] = {0x02,0x00,0x00,0x00,0x00,0x01};
  char esrc[6] = {0x02,0x00,0x00,0x00,0x00,0x02};
  struct rb815ctx ctx;
  int i,j;
  uint64_t begin, end;
  uint64_t pktcnt = 0;

  memcpy(ether_dst(ether), edst, 6);
  memcpy(ether_src(ether), esrc, 6);
  ether_set_type(ether, ETHER_TYPE_IP);
  ip = ether_payload(ether);
  ip_set_version(ip, 4);
  ip_set_hdr_len(ip, 20);
  ip_set_total_len(ip, sizeof(pkt) - 14);
  ip_set_id(ip, 0x1234);
  ip_set_ttl(ip, 64);
  ip_set_proto(ip, 6);
  ip_set_src(ip, (10<<24) | 1);
  ip_set_dst(ip, (10<<24) | 2);
  ip_set_hdr_cksum_calc(ip, 20);
  tcp = ip_payload(ip);
  tcp_set_src_port(tcp, 12345);
  tcp_set_dst_port(tcp, 54321);
  tcp_set_ack_on(tcp);
  tcp_set_seq_number(tcp, 0x12345678);
  tcp_set_ack_number(tcp, 0x87654321);
  tcp_set_window(tcp, 32768);
  tcp_set_data_offset(tcp, 20);
  memset(((char*)tcp) + 20, 'X', sizeof(pkt)-14-20-20);
  tcp_set_cksum_calc(ip, 20, tcp, sizeof(pkt)-14-20);
  ll_alloc_st_init(&st, 10000, 4096);

  printf("beginning randomized tests\n");

  begin = gettime64();
  for (j = 0; j < 1000; j++)
  {
    rb815ctx_init_fast(&ctx);
    for (i = 0; i < 65535-14-20; i += 16)
    {
      fragment[0].datastart = (uint16_t)i;
      fragment[0].datalen = 8;
      fragment[0].pkt = NULL;
      if (fragment4(&intf, pkt, (uint16_t)sz, fragment, 1) != 0)
      {
        abort();
      }
      pktcnt++;
      rb815ctx_add(&ctx, fragment[0].pkt);
      allocif_free(&intf, fragment[0].pkt);
      if (rb815ctx_complete(&ctx))
      {
        printf("1\n");
        abort();
      }
    }
  }
  end = gettime64();
  printf("%g MPPS\n", (double)pktcnt*1.0/(double)(end-begin));

  ll_alloc_st_free(&st);
  
  return 0;
}
