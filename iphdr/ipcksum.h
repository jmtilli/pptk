#ifndef _IPCKSUM_H_
#define _IPCKSUM_H_

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "hdr.h"
#include "iphdr.h"

struct ip_cksum_ctx {
  uint32_t sum;
};

#define IP_CKSUM_CTX_INITER { .sum = 0 }

static inline uint16_t ip_cksum_postprocess(struct ip_cksum_ctx *ctx)
{
  uint32_t sum = ctx->sum;
  while (sum>>16)
  {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  return htons((uint16_t)~sum);
}

static inline void ip_cksum_add16(struct ip_cksum_ctx *ctx, uint16_t val16)
{
  ctx->sum += val16;
}

static inline void ip_cksum_add_leftover(struct ip_cksum_ctx *ctx, uint8_t val)
{
  ctx->sum += val;
}

static inline void ip_cksum_feed32ptr(struct ip_cksum_ctx *ctx, const void *buf)
{
  const char *cbuf = buf;
  ip_cksum_add16(ctx, hdr_get16h(&cbuf[0]));
  ip_cksum_add16(ctx, hdr_get16h(&cbuf[2]));
}

void ip_cksum_feed(struct ip_cksum_ctx *ctx, const void *buf, size_t sz);

uint16_t ip_hdr_cksum_calc(const void *iphdr, uint16_t iplen);

static inline uint16_t ip46_hdr_cksum_calc(const void *iphdr)
{
  uint16_t iplen = ip46_hdr_len(iphdr);
  if (ip_version(iphdr) == 4)
  {
    return ip_hdr_cksum_calc(iphdr, iplen);
  }
  else if (ip_version(iphdr) == 6)
  {
    return 0;
  }
  else
  {
    abort();
  }
}

uint16_t tcp_cksum_calc(
  const void *iphdr, uint16_t iplen, const void *tcphdr, uint16_t tcplen);

uint16_t udp_cksum_calc(
  const void *iphdr, uint16_t iplen, const void *udphdr, uint16_t udplen);

uint16_t tcp6_cksum_calc(
  const void *iphdr, uint16_t iplen, const void *tcphdr, uint16_t tcplen);

static inline uint16_t tcp46_cksum_calc(
  const void *iphdr)
{
  int32_t tcplen = ip46_payload_len(iphdr);
  uint16_t iplen = ip46_hdr_len(iphdr);
  const void *tcphdr = ip46_const_payload(iphdr);
  if (tcplen < 0)
  {
    tcplen = 0;
  }
  else if (tcplen > UINT16_MAX)
  {
    tcplen = UINT16_MAX;
  }
  if (ip46_proto(iphdr) != 6)
  {
    abort();
  }
  if (ip_version(iphdr) == 4)
  {
    return tcp_cksum_calc(iphdr, iplen, tcphdr, (uint16_t)tcplen);
  }
  else if (ip_version(iphdr) == 6)
  {
    return tcp6_cksum_calc(iphdr, iplen, tcphdr, (uint16_t)tcplen);
  }
  else
  {
    abort();
  }
}

uint16_t udp6_cksum_calc(
  const void *iphdr, uint16_t iplen, const void *udphdr, uint16_t udplen);

static inline void ip_set_hdr_cksum_calc(void *iphdr, uint16_t iplen)
{
  uint16_t cksum;
  if (iplen < 20)
  {
    abort();
  }
  ip_set_hdr_cksum(iphdr, 0);
  cksum = ip_hdr_cksum_calc(iphdr, iplen);
  ip_set_hdr_cksum(iphdr, cksum);
}

static inline void ip46_set_hdr_cksum_calc(void *iphdr)
{
  if (ip_version(iphdr) == 4)
  {
    uint16_t iplen = ip_hdr_len(iphdr);
    ip_set_hdr_cksum_calc(iphdr, iplen);
  }
  else if (ip_version(iphdr) == 6)
  {
    // nop
  }
  else
  {
    abort();
  }
}

static inline void tcp_set_cksum_calc(
  const void *iphdr, uint16_t iplen, void *tcphdr, uint16_t tcplen)
{
  if (iplen < 20)
  {
    abort();
  }
  if (tcplen < 20)
  {
    abort();
  }
  tcp_set_cksum(tcphdr, 0);
  tcp_set_cksum(tcphdr, tcp_cksum_calc(iphdr, iplen, tcphdr, tcplen));
}

static inline void tcp6_set_cksum_calc(
  const void *iphdr, uint16_t iplen, void *tcphdr, uint16_t tcplen)
{
  if (iplen < 40)
  {
    abort();
  }
  if (tcplen < 20)
  {
    abort();
  }
  tcp_set_cksum(tcphdr, 0);
  tcp_set_cksum(tcphdr, tcp6_cksum_calc(iphdr, iplen, tcphdr, tcplen));
}

static inline void tcp46_set_cksum_calc(void *iphdr)
{
  int32_t tcplen = ip46_payload_len(iphdr);
  uint16_t iplen = ip46_hdr_len(iphdr);
  void *tcphdr = ip46_payload(iphdr);
  if (tcplen < 0)
  {
    tcplen = 0;
  }
  else if (tcplen > UINT16_MAX)
  {
    tcplen = UINT16_MAX;
  }
  if (ip46_proto(iphdr) != 6)
  {
    abort();
  }
  if (ip_version(iphdr) == 4)
  {
    tcp_set_cksum_calc(iphdr, iplen, tcphdr, (uint16_t)tcplen);
  }
  else if (ip_version(iphdr) == 6)
  {
    tcp6_set_cksum_calc(iphdr, iplen, tcphdr, (uint16_t)tcplen);
  }
  else
  {
    abort();
  }
}

static inline void udp_set_cksum_calc(
  const void *iphdr, uint16_t iplen, void *udphdr, uint16_t udplen)
{
  if (iplen < 20)
  {
    abort();
  }
  if (udplen < 8)
  {
    abort();
  }
  udp_set_cksum(udphdr, 0);
  udp_set_cksum(udphdr, udp_cksum_calc(iphdr, iplen, udphdr, udplen));
}

static inline void udp6_set_cksum_calc(
  const void *iphdr, uint16_t iplen, void *udphdr, uint16_t udplen)
{
  if (iplen < 40)
  {
    abort();
  }
  if (udplen < 8)
  {
    abort();
  }
  udp_set_cksum(udphdr, 0);
  udp_set_cksum(udphdr, udp6_cksum_calc(iphdr, iplen, udphdr, udplen));
}

static inline uint16_t ip_update_cksum16(
  uint16_t old_cksum16, uint16_t old16, uint16_t new16)
{
  uint32_t old_cksum = old_cksum16;
  old_cksum = (uint16_t)~old_cksum;
  old_cksum += (uint16_t)~old16;
  old_cksum += new16;
  while (old_cksum >> 16)
  {
    old_cksum = (old_cksum & 0xffff) + (old_cksum >> 16);
  }
  old_cksum = (uint16_t)~old_cksum;
  return (uint16_t)old_cksum;
}

static inline uint16_t ip_update_cksum32(
  uint16_t old_cksum, uint32_t old32, uint32_t new32)
{
  uint16_t new1 = (uint16_t)(new32>>16), old1 = (uint16_t)(old32>>16);
  uint16_t new2 = (uint16_t)(new32&0xFFFF), old2 = (uint16_t)(old32&0xFFFF);
  uint16_t x;
  x = ip_update_cksum16(ip_update_cksum16(old_cksum, old1, new1), old2, new2);
  return x;
}

static inline void ip_set_src_cksum_update(
  void *iphdr, uint16_t iplen, uint8_t proto, void *payhdr, uint16_t paylen, uint32_t src)
{
  uint32_t old_src = ip_src(iphdr);
  uint16_t old_cksum = ip_hdr_cksum(iphdr);
  old_cksum = ip_update_cksum32(old_cksum, old_src, src);
  ip_set_hdr_cksum(iphdr, old_cksum);
  if (proto == 6)
  {
    old_cksum = tcp_cksum(payhdr);
    old_cksum = ip_update_cksum32(old_cksum, old_src, src);
    tcp_set_cksum(payhdr, old_cksum);
  }
  else if (proto == 17)
  {
    old_cksum = udp_cksum(payhdr);
    if (old_cksum != 0)
    {
      old_cksum = ip_update_cksum32(old_cksum, old_src, src);
      udp_set_cksum(payhdr, old_cksum);
    }
  }
  ip_set_src(iphdr, src);
}

static inline void tcp_set_src_port_cksum_update(
  void *tcphdr, uint16_t tcplen, uint16_t src_port)
{
  uint16_t old_src_port = tcp_src_port(tcphdr);
  uint16_t old_cksum = tcp_cksum(tcphdr);
  old_cksum = ip_update_cksum16(old_cksum, old_src_port, src_port);
  tcp_set_cksum(tcphdr, old_cksum);
  tcp_set_src_port(tcphdr, src_port);
}

static inline void tcp_set_dst_port_cksum_update(
  void *tcphdr, uint16_t tcplen, uint16_t dst_port)
{
  uint16_t old_dst_port = tcp_dst_port(tcphdr);
  uint16_t old_cksum = tcp_cksum(tcphdr);
  old_cksum = ip_update_cksum16(old_cksum, old_dst_port, dst_port);
  tcp_set_cksum(tcphdr, old_cksum);
  tcp_set_dst_port(tcphdr, dst_port);
}

static inline void icmp_set_echo_identifier_cksum_update(
  void *icmphdr, uint16_t icmplen, uint16_t echo_identifier)
{
  uint16_t old_echo_identifier = icmp_echo_identifier(icmphdr);
  uint16_t old_cksum = icmp_checksum(icmphdr);
  old_cksum = ip_update_cksum16(old_cksum, old_echo_identifier, echo_identifier);
  icmp_set_checksum(icmphdr, old_cksum);
  icmp_set_echo_identifier(icmphdr, echo_identifier);
}

static inline void tcp_set_seq_number_cksum_update(
  void *tcphdr, uint16_t tcplen, uint32_t seq_number)
{
  uint32_t old_seq_number = tcp_seq_number(tcphdr);
  uint16_t old_cksum = tcp_cksum(tcphdr);
  old_cksum = ip_update_cksum32(old_cksum, old_seq_number, seq_number);
  tcp_set_cksum(tcphdr, old_cksum);
  tcp_set_seq_number(tcphdr, seq_number);
}

static inline void tcp_set_ack_number_cksum_update(
  void *tcphdr, uint16_t tcplen, uint32_t ack_number)
{
  uint32_t old_ack_number = tcp_ack_number(tcphdr);
  uint16_t old_cksum = tcp_cksum(tcphdr);
  old_cksum = ip_update_cksum32(old_cksum, old_ack_number, ack_number);
  tcp_set_cksum(tcphdr, old_cksum);
  tcp_set_ack_number(tcphdr, ack_number);
}

static inline void tcp_set_window_cksum_update(
  void *tcphdr, uint16_t tcplen, uint16_t window)
{
  uint16_t old_window = tcp_window(tcphdr);
  uint16_t old_cksum = tcp_cksum(tcphdr);
  old_cksum = ip_update_cksum16(old_cksum, old_window, window);
  tcp_set_cksum(tcphdr, old_cksum);
  tcp_set_window(tcphdr, window);
}

static inline void udp_set_src_port_cksum_update(
  void *udphdr, uint16_t udplen, uint16_t src_port)
{
  uint16_t old_src_port = udp_src_port(udphdr);
  uint16_t old_cksum = udp_cksum(udphdr);
  if (old_cksum != 0)
  {
    old_cksum = ip_update_cksum16(old_cksum, old_src_port, src_port);
    udp_set_cksum(udphdr, old_cksum);
  }
  udp_set_src_port(udphdr, src_port);
}

static inline void udp_set_dst_port_cksum_update(
  void *udphdr, uint16_t udplen, uint16_t dst_port)
{
  uint16_t old_dst_port = udp_dst_port(udphdr);
  uint16_t old_cksum = udp_cksum(udphdr);
  if (old_cksum != 0)
  {
    old_cksum = ip_update_cksum16(old_cksum, old_dst_port, dst_port);
    udp_set_cksum(udphdr, old_cksum);
  }
  udp_set_dst_port(udphdr, dst_port);
}

static inline void ip_set_dst_cksum_update(
  void *iphdr, uint16_t iplen, uint8_t proto, void *payhdr, uint16_t paylen, uint32_t dst)
{
  uint32_t old_dst = ip_dst(iphdr);
  uint16_t old_cksum = ip_hdr_cksum(iphdr);
  old_cksum = ip_update_cksum32(old_cksum, old_dst, dst);
  ip_set_hdr_cksum(iphdr, old_cksum);
  if (proto == 6)
  {
    old_cksum = tcp_cksum(payhdr);
    old_cksum = ip_update_cksum32(old_cksum, old_dst, dst);
    tcp_set_cksum(payhdr, old_cksum);
  }
  else if (proto == 17)
  {
    old_cksum = udp_cksum(payhdr);
    if (old_cksum != 0)
    {
      old_cksum = ip_update_cksum32(old_cksum, old_dst, dst);
      udp_set_cksum(payhdr, old_cksum);
    }
  }
  ip_set_dst(iphdr, dst);
}

static inline int ip_decr_ttl_cksum_update(void *pkt)
{
  uint8_t ttl;
  uint8_t proto;
  uint16_t whole_field_old, whole_field_new;
  uint16_t old_cksum = ip_hdr_cksum(pkt);
  ttl = ip_ttl(pkt);
  proto = ip_proto(pkt);
  if (ttl == 0)
  {
    abort();
  }
  whole_field_old = (uint16_t)((ttl<<8)|proto);
  ttl--;
  whole_field_new = (uint16_t)((ttl<<8)|proto);
  old_cksum = ip_update_cksum16(old_cksum, whole_field_old, whole_field_new);
  ip_set_hdr_cksum(pkt, old_cksum);
  ip_set_ttl(pkt, ttl);
  return ttl > 0;
}

static inline void tcp_set_ack_off_cksum_update(void *pkt)
{
  char *cpkt = pkt;
  uint16_t whole_field_old, whole_field_new;
  uint16_t cksum = tcp_cksum(pkt);
  whole_field_old = hdr_get16n(&cpkt[12]);
  hdr_set8h(&cpkt[13], (uint8_t)(hdr_get8h(&cpkt[13]) & ~(1<<4)));
  whole_field_new = hdr_get16n(&cpkt[12]);
  cksum = ip_update_cksum16(cksum, whole_field_old, whole_field_new);
  tcp_set_cksum(pkt, cksum);
}


static inline void tcp_disable_sack_cksum_update(
  void *pkt, void *sackhdr, size_t sacklen, int sixteen_bit_align)
{
  char *chdr = sackhdr;
  size_t curoff = 0;
  uint16_t cksum = tcp_cksum(pkt);
  if (sixteen_bit_align)
  {
    while (curoff + 2 <= sacklen)
    {
      uint16_t old_val = hdr_get16n(&chdr[curoff]);
      uint16_t new_val = 0x0101;
      cksum = ip_update_cksum16(cksum, old_val, new_val);
      hdr_set16n(&chdr[curoff], new_val);
      curoff += 2;
    }
    if (curoff + 1 == sacklen)
    {
      uint16_t old_val = hdr_get16n(&chdr[curoff]);
      uint16_t new_val = (uint16_t)((old_val & 0xFF) | 0x0100);
      cksum = ip_update_cksum16(cksum, old_val, new_val);
      hdr_set16n(&chdr[curoff], new_val);
      curoff += 1;
    }
  }
  else
  {
    while (curoff + 2 <= sacklen)
    {
      uint16_t old_val1 = hdr_get16n(&chdr[curoff - 1]);
      uint16_t old_val2 = hdr_get16n(&chdr[curoff + 1]);
      uint16_t new_val = 0x0101;
      uint16_t new_val1, new_val2;
      hdr_set16n(&chdr[curoff], new_val);
      new_val1 = hdr_get16n(&chdr[curoff - 1]);
      new_val2 = hdr_get16n(&chdr[curoff + 1]);
      cksum = ip_update_cksum16(cksum, old_val1, new_val1);
      cksum = ip_update_cksum16(cksum, old_val2, new_val2);
      curoff += 2;
    }
    if (curoff + 1 == sacklen)
    {
      uint16_t old_val1 = hdr_get16n(&chdr[curoff - 1]);
      uint16_t old_val2 = hdr_get16n(&chdr[curoff + 1]);
      uint16_t old_val = hdr_get16n(&chdr[curoff]);
      uint16_t new_val = (uint16_t)((old_val & 0xFF) | 0x0100);
      uint16_t new_val1, new_val2;
      hdr_set16n(&chdr[curoff], new_val);
      new_val1 = hdr_get16n(&chdr[curoff - 1]);
      new_val2 = hdr_get16n(&chdr[curoff + 1]);
      cksum = ip_update_cksum16(cksum, old_val1, new_val1);
      cksum = ip_update_cksum16(cksum, old_val2, new_val2);
      curoff += 1;
    }
  }
  tcp_set_cksum(pkt, cksum);
}

static inline void tcp_set_mss_cksum_update(
  void *pkt, struct tcp_information *opts, uint16_t mss)
{
  char *cpkt = pkt;
  uint16_t cksum = tcp_cksum(pkt);
  if ((opts->mssoff % 2) == 0)
  {
    uint16_t old_mss = hdr_get16n(&cpkt[opts->mssoff + 2]);
    cksum = ip_update_cksum16(cksum, old_mss, mss);
    hdr_set16n(&cpkt[opts->mssoff + 2], mss);
  }
  else
  {
    uint16_t old_val1 = hdr_get16n(&cpkt[opts->mssoff + 1]);
    uint16_t old_val2 = hdr_get16n(&cpkt[opts->mssoff + 3]);
    uint16_t new_val1, new_val2;
    hdr_set16n(&cpkt[opts->mssoff + 2], mss);
    new_val1 = hdr_get16n(&cpkt[opts->mssoff + 1]);
    new_val2 = hdr_get16n(&cpkt[opts->mssoff + 3]);
    cksum = ip_update_cksum16(cksum, old_val1, new_val1);
    cksum = ip_update_cksum16(cksum, old_val2, new_val2);
  }
  tcp_set_cksum(pkt, cksum);
}

static inline void tcp_adjust_sack_cksum_update(
  void *pkt, void *sackhdr, size_t sacklen, int sixteen_bit_align,
  uint32_t adjustment)
{
  char *chdr = sackhdr;
  size_t curoff = 2;
  uint16_t cksum = tcp_cksum(pkt);
  if (sixteen_bit_align)
  {
    while (curoff + 8 <= sacklen)
    {
      uint32_t old_start = hdr_get32n(&chdr[curoff+0]);
      uint32_t old_end = hdr_get32n(&chdr[curoff+4]);
      uint32_t new_start = old_start + adjustment;
      uint32_t new_end = old_end + adjustment;
      cksum = ip_update_cksum32(cksum, old_start, new_start);
      cksum = ip_update_cksum32(cksum, old_end, new_end);
      hdr_set32n(&chdr[curoff+0], new_start);
      hdr_set32n(&chdr[curoff+4], new_end);
      curoff += 8;
    }
  }
  else
  {
    while (curoff + 8 <= sacklen)
    {
      uint16_t old_val1 = hdr_get16n(&chdr[curoff - 1]);
      uint32_t old_val2 = hdr_get32n(&chdr[curoff + 1]);
      uint32_t old_val3 = hdr_get32n(&chdr[curoff + 5]);
      uint16_t new_val1;
      uint32_t new_val2, new_val3;
      uint32_t old_start = hdr_get32n(&chdr[curoff+0]);
      uint32_t old_end = hdr_get32n(&chdr[curoff+4]);
      uint32_t new_start = old_start + adjustment;
      uint32_t new_end = old_end + adjustment;
      hdr_set32n(&chdr[curoff+0], new_start);
      hdr_set32n(&chdr[curoff+4], new_end);
      new_val1 = hdr_get16n(&chdr[curoff - 1]);
      new_val2 = hdr_get32n(&chdr[curoff + 1]);
      new_val3 = hdr_get32n(&chdr[curoff + 5]);
      cksum = ip_update_cksum16(cksum, old_val1, new_val1);
      cksum = ip_update_cksum32(cksum, old_val2, new_val2);
      cksum = ip_update_cksum32(cksum, old_val3, new_val3);
    }
  }
  tcp_set_cksum(pkt, cksum);
}

static inline void tcp_adjust_tsval_cksum_update(
  void *pkt, struct sack_ts_headers *hdrs, uint32_t adjustment)
{
  char *cpkt = pkt;
  uint32_t oldval, newval;
  uint16_t cksum = tcp_cksum(pkt);
  if (hdrs->tsoff == 0)
  {
    return;
  }
  if ((hdrs->tsoff%2) == 0)
  {
    oldval = hdr_get32n(&cpkt[hdrs->tsoff+2]);
    newval = oldval + adjustment;
    hdr_set32n(&cpkt[hdrs->tsoff+2], newval);
    cksum = ip_update_cksum32(cksum, oldval, newval);
  }
  else
  {
    uint16_t oldval1, oldval2, oldval3;
    uint16_t newval1, newval2, newval3;
    oldval1 = hdr_get16n(&cpkt[hdrs->tsoff+1]);
    oldval2 = hdr_get16n(&cpkt[hdrs->tsoff+3]);
    oldval3 = hdr_get16n(&cpkt[hdrs->tsoff+5]);
    oldval = hdr_get32n(&cpkt[hdrs->tsoff+2]);
    newval = oldval + adjustment;
    hdr_set32n(&cpkt[hdrs->tsoff+2], newval);
    newval1 = hdr_get16n(&cpkt[hdrs->tsoff+1]);
    newval2 = hdr_get16n(&cpkt[hdrs->tsoff+3]);
    newval3 = hdr_get16n(&cpkt[hdrs->tsoff+5]);
    cksum = ip_update_cksum16(cksum, oldval1, newval1);
    cksum = ip_update_cksum16(cksum, oldval2, newval2);
    cksum = ip_update_cksum16(cksum, oldval3, newval3);
  }
  tcp_set_cksum(pkt, cksum);
}

static inline void tcp_adjust_tsecho_cksum_update(
  void *pkt, struct sack_ts_headers *hdrs, uint32_t adjustment)
{
  char *cpkt = pkt;
  uint32_t oldval, newval;
  uint16_t cksum = tcp_cksum(pkt);
  if (hdrs->tsoff == 0)
  {
    return;
  }
  if ((hdrs->tsoff%2) == 0)
  {
    oldval = hdr_get32n(&cpkt[hdrs->tsoff+6]);
    newval = oldval + adjustment;
    hdr_set32n(&cpkt[hdrs->tsoff+6], newval);
    cksum = ip_update_cksum32(cksum, oldval, newval);
  }
  else
  {
    uint16_t oldval1, oldval2, oldval3;
    uint16_t newval1, newval2, newval3;
    oldval1 = hdr_get16n(&cpkt[hdrs->tsoff+5]);
    oldval2 = hdr_get16n(&cpkt[hdrs->tsoff+7]);
    oldval3 = hdr_get16n(&cpkt[hdrs->tsoff+9]);
    oldval = hdr_get32n(&cpkt[hdrs->tsoff+6]);
    newval = oldval + adjustment;
    hdr_set32n(&cpkt[hdrs->tsoff+6], newval);
    newval1 = hdr_get16n(&cpkt[hdrs->tsoff+5]);
    newval2 = hdr_get16n(&cpkt[hdrs->tsoff+7]);
    newval3 = hdr_get16n(&cpkt[hdrs->tsoff+9]);
    cksum = ip_update_cksum16(cksum, oldval1, newval1);
    cksum = ip_update_cksum16(cksum, oldval2, newval2);
    cksum = ip_update_cksum16(cksum, oldval3, newval3);
  }
  tcp_set_cksum(pkt, cksum);
}

static inline void tcp_adjust_sack_cksum_update_2(
  void *pkt, struct sack_ts_headers *hdrs, uint32_t adjustment)
{
  char *cpkt = pkt;
  if (hdrs->sackoff == 0)
  {
    return;
  }
  tcp_adjust_sack_cksum_update(
    pkt, &cpkt[hdrs->sackoff], hdrs->sacklen, !(hdrs->sackoff%2), adjustment);
}

#endif
