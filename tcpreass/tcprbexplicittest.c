#include "iphdr.h"
#include "allocif.h"
#include "llalloc.h"
#include "ipcksum.h"
#include "packet.h"
#include "time64.h"
#include "tcprbexplicit.h"

int main(int argc, char **argv)
{
  struct tcp_rb_explicit_reassctx ctx;
  char edst[6] = {0x02,0x00,0x00,0x00,0x00,0x01};
  char esrc[6] = {0x02,0x00,0x00,0x00,0x00,0x02};
  struct ll_alloc_st st;
  struct allocif loc = {.ops = &ll_allocif_ops_st, .userdata = &st};
  uint32_t isn = UINT32_MAX - 100;
  uint32_t cursn = isn + 1;
  char ether[1514] = {0};
  char *ip, *tcp;
  uint32_t iter;
  const uint32_t pktcnt = 1000*1000;
  uint64_t begin, end;

  ll_alloc_st_init(&st, 100000, 1536);

  tcp_rb_explicit_reassctx_init(&ctx, isn);

  memcpy(ether_dst(ether), edst, 6);
  memcpy(ether_src(ether), esrc, 6);
  ether_set_type(ether, ETHER_TYPE_IP);
  ip = ether_payload(ether);
  ip_set_version(ip, 4);
  ip_set_hdr_len(ip, 20);
  ip_set_total_len(ip, 20); // To be overwritten later
  ip_set_id(ip, 0);
  ip_set_ttl(ip, 64);
  ip_set_proto(ip, 6);
  ip_set_src(ip, (10<<24) | 1);
  ip_set_dst(ip, (10<<24) | 2);
  ip_set_hdr_cksum_calc(ip, 20); // To be overwritten later
  tcp = ip_payload(ip);
  tcp_set_src_port(tcp, 12345);
  tcp_set_dst_port(tcp, 54321);
  tcp_set_ack_on(tcp);
  tcp_set_seq_number(tcp, 0x12345678);
  tcp_set_ack_number(tcp, 0x87654321);
  tcp_set_window(tcp, 32768);
  tcp_set_data_offset(tcp, 20);
  memset(((char*)tcp) + 20, 'X', sizeof(ether)-14-20-20);
  tcp_set_cksum_calc(ip, 20, tcp, sizeof(ether)-14-20); // To be overwritten

  begin = gettime64();

  for (iter = 0; iter < pktcnt; iter++)
  {
    //uint32_t tcppay_len = (rand()%1000) + 1;
    uint32_t tcppay_len = 1;
    struct packet *pkt;
    pkt = allocif_alloc(&loc, packet_size(14+20+20+tcppay_len));
    pkt->data = packet_calc_data(pkt);
    pkt->sz = 14+20+20+tcppay_len;
    ip_set_total_len(ip, 20+20+tcppay_len);
    ip_set_hdr_cksum_calc(ip, 20);
    tcp_set_seq_number(tcp, cursn + (uint32_t)(rand()%10000));
    tcp_set_cksum_calc(ip, 20, tcp, 20+tcppay_len);
    memcpy(pkt->data, ether, pkt->sz);
    pkt = tcp_rb_explicit_reassctx_add(&loc, &ctx, pkt);
    //printf("added pkt\n");
    while (pkt != NULL)
    {
      cursn = pkt->u.rbtcppositive.last + 1;
      //printf("got pkt %u:%u\n", (uint32_t)pkt->rbtcppositive.first, (uint32_t)pkt->rbtcppositive.last);
      allocif_free(&loc, pkt);
      pkt = tcp_rb_explicit_reassctx_fetch(&ctx);
    }
  }

  end = gettime64();
  printf("%g MPPS\n", pktcnt*1.0/(end-begin));

  tcp_rb_explicit_reassctx_free(&loc, &ctx);

  ll_alloc_st_free(&st);

  return 0;
}
