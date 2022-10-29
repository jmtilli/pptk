/*
 * Authors:
 * - Juha-Matti Tilli <juha-matti.tilli@iki.fi>
 *
 * This file is covered by GNU GENERAL PUBLIC LICENSE Version 2.
 */

#include <errno.h>
#include <stdint.h>
#include "iphdr.h"
#include "llalloc.h"
#include "packet.h"
#include "containerof.h"
#include "ipfrag.h"
#include "iphdr.h"
#include "ipcksum.h"
#include "time64.h"
#include "linux.h"


int main(int argc, char **argv)
{
  struct ipq ipq;
  struct fragment fragment[2];
  char pkt[2102] = {0};
  size_t sz = sizeof(pkt);
  char *ether = pkt;
  char *ip;
  char *tcp;
  char edst[6] = {0x02,0x00,0x00,0x00,0x00,0x01};
  char esrc[6] = {0x02,0x00,0x00,0x00,0x00,0x02};
  struct ll_alloc_st st;
  struct allocif intf = {.ops = &ll_allocif_ops_st, .userdata = &st};
  struct packet *reassembled;
  uint64_t begin, end;
  int j;

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

  ll_alloc_st_init(&st, 1000, 4096);


  printf("beginning randomized tests\n");

  begin = gettime64();

  for (j = 0; j < 10*1000*1000; j++)
  {
    fragment[0].datastart = 0;
    fragment[0].datalen = 1514 - 14 - 20;
    fragment[0].pkt = NULL;
    fragment[1].datastart = 1514 - 14 - 20;
    fragment[1].datalen = (uint16_t)(sz - 14 - 20 - (1514 - 14 - 20));
    fragment[1].datastart = (uint16_t)(fragment[1].datastart - 8); // FIXME rm
    fragment[1].datalen = (uint16_t)(fragment[1].datalen + 8); // FIXME rm
    fragment[1].pkt = NULL;
    if (fragment4(&intf, pkt, (uint16_t)sz, fragment, 2) != 0)
    {
      abort();
    }
  
    ipq_init(&ipq);
  
    if (ip_frag_queue(&intf, &ipq, fragment[0].pkt) != -EINPROGRESS)
    {
      abort();
    }
    if (ip_frag_queue(&intf, &ipq, fragment[1].pkt) != 0)
    {
      abort();
    }
    reassembled = ip_frag_reassemble(&intf, &ipq);
    if (reassembled->sz != sz)
    {
      printf("size mismatch %d %d\n", (int)reassembled->sz, (int)sz);
      abort();
    }
    if (memcmp(reassembled->data, pkt, sz) != 0)
    {
      char *pkt2 = reassembled->data;
      size_t idx;
      printf("data mismatch\n");
      for (idx = 0; idx < sz; idx++)
      {
        if (pkt2[idx] != pkt[idx])
        {
          printf("mismatch idx %zu %d %d\n", idx, (unsigned char)pkt2[idx], (unsigned char)pkt[idx]);
        }
      }
      abort();
    }
    ll_free_st(&st, reassembled);
    ipq_free(&intf, &ipq);
  }
  end = gettime64();
  printf("%g MPPS\n", 20e6/(double)(end-begin));

  ll_alloc_st_free(&st);
   
  return 0;
}
