#ifndef _IPHDR_H_
#define _IPHDR_H_

#include "hdr.h"
#include "dnshdr.h"
#include <stdlib.h>

#define PCP_RCODE_SUCCESS 0
#define PCP_RCODE_UNSUPP_VERSION 1
#define PCP_RCODE_NOT_AUTHORIZED 2
#define PCP_RCODE_MALFORMED_REQUEST 3
#define PCP_RCODE_UNSUPP_OPCODE 4
#define PCP_RCODE_UNSUPP_OPTION 5
#define PCP_RCODE_MALFORMED_OPTION 6
#define PCP_RCODE_NETWORK_FAILURE 7
#define PCP_RCODE_NO_RESOURCES 8
#define PCP_RCODE_UNSUPP_PROTOCOL 9
#define PCP_RCODE_USER_EX_QUOTA 10
#define PCP_RCODE_CANNOT_PROVIDE_EXTERNAL 11
#define PCP_RCODE_ADDRESS_MISMATCH 12
#define PCP_RCODE_EXCESSIVE_REMOTE_PEERS 13

#define PCP_OPCODE_ANNOUNCE 0
#define PCP_OPCODE_MAP 1
#define PCP_OPCODE_PEER 2

static inline uint8_t pcp_version(const void *vpkt)
{
  const unsigned char *pkt = vpkt;
  return pkt[0];
}
static inline void pcp_set_version(void *vpkt, uint8_t version)
{
  unsigned char *pkt = vpkt;
  pkt[0] = version;
}
static inline uint8_t pcp_r(const void *vpkt)
{
  const unsigned char *pkt = vpkt;
  return pkt[1] >> 7;
}
static inline void pcp_set_r(void *vpkt, int val)
{
  unsigned char *pkt = vpkt;
  pkt[1] &= ~(1<<7);
  pkt[1] |= (!!val)<<7;
}
static inline uint8_t pcp_opcode(const void *vpkt)
{
  const unsigned char *pkt = vpkt;
  return pkt[1] & ~(1<<7);
}
static inline void pcp_set_opcode(void *vpkt, uint8_t opcode)
{
  unsigned char *pkt = vpkt;
  pkt[1] |= opcode & ~(1<<7);
}
static inline void pcp_req_set_reserved(void *vpkt, uint16_t val)
{
  unsigned char *pkt = vpkt;
  hdr_set16n(&pkt[2], val);
}
static inline void pcp_resp_set_reserved(void *vpkt, uint8_t val)
{
  unsigned char *pkt = vpkt;
  pkt[2] = val;
}
static inline uint8_t pcp_resp_rcode(const void *vpkt)
{
  const unsigned char *pkt = vpkt;
  return pkt[3];
}
static inline void pcp_resp_set_rcode(void *vpkt, uint8_t rcode)
{
  unsigned char *pkt = vpkt;
  pkt[3] = rcode;
}
static inline uint32_t pcp_lifetime(const void *vpkt)
{
  const unsigned char *pkt = vpkt;
  return hdr_get32n(&pkt[4]);
}
static inline void pcp_set_lifetime(void *vpkt, uint32_t lifetime)
{
  unsigned char *pkt = vpkt;
  hdr_set32n(&pkt[4], lifetime);
}
static inline int pcp_req_is_ipv4(void *vpkt)
{
  unsigned char *pkt = vpkt;
  static const char compar[12] = {0,0,0,0,0,0,0,0,0,0,(char)0xff,(char)0xff};
  return memcmp(&pkt[8], compar, sizeof(compar)) == 0;
}
static inline uint32_t pcp_req_get_ipv4(void *vpkt)
{
  unsigned char *pkt = vpkt;
  return hdr_get32n(&pkt[8+12]);
}
static inline uint32_t pcp_resp_epoch_time(const void *vpkt)
{
  const unsigned char *pkt = vpkt;
  return hdr_get32n(&pkt[8]);
}
static inline void pcp_resp_set_epoch_time(void *vpkt, uint32_t epoch_time)
{
  unsigned char *pkt = vpkt;
  hdr_set32n(&pkt[8], epoch_time);
}
static inline void pcp_resp_zero_reserved2(void *vpkt)
{
  unsigned char *pkt = vpkt;
  memset(&pkt[12], 0, 96/8);
}
static inline const void *pcp_mapreq_nonce(const void *vpkt)
{
  const unsigned char *pkt = vpkt;
  return &pkt[24];
}
static inline uint8_t pcp_mapreq_protocol(const void *vpkt)
{
  const unsigned char *pkt = vpkt;
  return pkt[36];
}
static inline uint16_t pcp_mapreq_int_port(const void *vpkt)
{
  const unsigned char *pkt = vpkt;
  return hdr_get16n(&pkt[40]);
}
static inline uint16_t pcp_mapreq_sugg_ext_port(const void *vpkt)
{
  const unsigned char *pkt = vpkt;
  return hdr_get16n(&pkt[42]);
}
static inline const void *pcp_mapreq_sugg_ext_ip(const void *vpkt)
{
  const unsigned char *pkt = vpkt;
  return &pkt[44];
}
static inline const void *pcp_mapreq_options(const void *vpkt)
{
  const unsigned char *pkt = vpkt;
  return &pkt[60];
}
static inline void pcp_mapresp_set_nonce(void *vpkt, const void *nonce)
{
  unsigned char *cpkt = vpkt;
  memcpy(&cpkt[24], nonce, 96/8);
}
static inline void pcp_mapresp_set_protocol(void *vpkt, uint8_t proto)
{
  unsigned char *cpkt = vpkt;
  cpkt[36] = proto;
}
static inline void pcp_mapresp_zero_reserved(void *vpkt)
{
  unsigned char *cpkt = vpkt;
  cpkt[37] = 0;
  hdr_set16n(&cpkt[38], 0);
}
static inline void pcp_mapresp_set_int_port(void *vpkt, uint16_t int_port)
{
  unsigned char *cpkt = vpkt;
  hdr_set16n(&cpkt[40], int_port);
}
static inline void pcp_mapresp_set_ext_port(void *vpkt, uint16_t ext_port)
{
  unsigned char *cpkt = vpkt;
  hdr_set16n(&cpkt[42], ext_port);
}
static inline void pcp_mapresp_set_ext_ipv4(void *vpkt, uint32_t ext_ipv4)
{
  unsigned char *cpkt = vpkt;
  memset(&cpkt[44], 0, 10);
  memset(&cpkt[54], 0xff, 2);
  hdr_set32n(&cpkt[56], ext_ipv4);
}
#define PCP_OPTION_HEADER_LENGTH 4
#define PCP_OPTION_PREFER_FAILURE 2
static inline uint8_t pcp_option_code(const void *vpkt)
{
  const unsigned char *pkt = vpkt;
  return pkt[0];
}
static inline uint16_t pcp_option_paylength(const void *vpkt)
{
  const unsigned char *pkt = vpkt;
  return hdr_get16n(&pkt[2]);
}


static inline uint8_t icmp_type(const void *vpkt)
{
  const unsigned char *pkt = vpkt;
  return pkt[0];
}

static inline uint8_t icmp_code(const void *vpkt)
{
  const unsigned char *pkt = vpkt;
  return pkt[1];
}

static inline uint16_t icmp_checksum(const void *vpkt)
{
  const unsigned char *pkt = vpkt;
  return hdr_get16n(&pkt[2]);
}

static inline uint32_t icmp_header_data(const void *vpkt)
{
  const unsigned char *pkt = vpkt;
  return hdr_get32n(&pkt[4]);
}

static inline uint16_t icmp_echo_identifier(const void *vpkt)
{
  const unsigned char *pkt = vpkt;
  return hdr_get16n(&pkt[4]);
}

static inline void icmp_set_type(void *vpkt, uint8_t type)
{
  unsigned char *pkt = vpkt;
  pkt[0] = type;
}

static inline void icmp_set_code(void *vpkt, uint8_t code)
{
  unsigned char *pkt = vpkt;
  pkt[1] = code;
}

static inline void icmp_set_checksum(void *vpkt, uint16_t checksum)
{
  unsigned char *pkt = vpkt;
  hdr_set16n(&pkt[2], checksum);
}

static inline void icmp_set_header_data(void *vpkt, uint32_t header_data)
{
  unsigned char *pkt = vpkt;
  hdr_set32n(&pkt[4], header_data);
}

static inline void icmp_set_echo_identifier(void *vpkt, uint16_t echo_identifier)
{
  unsigned char *pkt = vpkt;
  hdr_set16n(&pkt[4], echo_identifier);
}

#define ICMP_HEADER_MINLEN 8
#define ICMP_L4_PAYLOAD_PORTS_MINLEN 4

static inline void *icmp_payload(void *vpkt)
{
  unsigned char *pkt = vpkt;
  return &pkt[8];
}

static inline const void *icmp_const_payload(const void *vpkt)
{
  const unsigned char *pkt = vpkt;
  return &pkt[8];
}

static inline int arp_is_valid_reqresp(const void *vpkt)
{
  uint16_t oper;
  const char *pkt = vpkt;
  if (hdr_get16n(&pkt[0]) != 1)
  {
    return 0;
  }
  if (hdr_get16n(&pkt[2]) != 0x0800)
  {
    return 0;
  }
  if (pkt[4] != 6)
  {
    return 0;
  }
  if (pkt[5] != 4)
  {
    return 0;
  }
  oper = hdr_get16n(&pkt[6]);
  if (oper != 1 && oper != 2)
  {
    return 0;
  }
  return 1;
}

static inline int arp_is_req(const void *vpkt)
{
  uint16_t oper;
  const char *pkt = vpkt;
  oper = hdr_get16n(&pkt[6]);
  return oper == 1;
}

static inline int arp_is_resp(const void *vpkt)
{
  uint16_t oper;
  const char *pkt = vpkt;
  oper = hdr_get16n(&pkt[6]);
  return oper == 2;
}

static inline void *arp_sha(void *pkt)
{
  char *cpkt = pkt;
  return &cpkt[8];
}

static inline void *arp_tha(void *pkt)
{
  char *cpkt = pkt;
  return &cpkt[18];
}

static inline const void *arp_const_sha(const void *pkt)
{
  const char *cpkt = pkt;
  return &cpkt[8];
}

static inline const void *arp_const_tha(const void *pkt)
{
  const char *cpkt = pkt;
  return &cpkt[18];
}

static inline uint32_t arp_spa(const void *pkt)
{
  const char *cpkt = pkt;
  return hdr_get32n(&cpkt[14]);
}

static inline uint32_t arp_tpa(const void *pkt)
{
  const char *cpkt = pkt;
  return hdr_get32n(&cpkt[24]);
}

static inline void arp_set_spa(void *pkt, uint32_t addr)
{
  char *cpkt = pkt;
  hdr_set32n(&cpkt[14], addr);
}

static inline void arp_set_ether(void *pkt)
{
  char *arp2 = pkt;
  hdr_set16n(&arp2[0], 1);
  hdr_set16n(&arp2[2], 0x0800);
  arp2[4] = 6;
  arp2[5] = 4;
}

static inline void arp_set_req(void *pkt)
{
  char *arp2 = pkt;
  hdr_set16n(&arp2[6], 1);
}

static inline void arp_set_resp(void *pkt)
{
  char *arp2 = pkt;
  hdr_set16n(&arp2[6], 2);
}

static inline void arp_set_tpa(void *pkt, uint32_t addr)
{
  char *cpkt = pkt;
  hdr_set32n(&cpkt[24], addr);
}

static inline void *ether_dst(void *pkt)
{
  char *cpkt = pkt;
  return &cpkt[0];
}

static inline void *ether_src(void *pkt)
{
  char *cpkt = pkt;
  return &cpkt[6];
}

static inline const void *ether_const_dst(const void *pkt)
{
  const char *cpkt = pkt;
  return &cpkt[0];
}

static inline const void *ether_const_src(const void *pkt)
{
  const char *cpkt = pkt;
  return &cpkt[6];
}

static inline uint16_t ether_type(const void *pkt)
{
  const char *cpkt = pkt;
  return hdr_get16n(&cpkt[12]);
}

static inline void ether_set_type(void *pkt, uint16_t type)
{
  char *cpkt = pkt;
  hdr_set16n(&cpkt[12], type);
}

static inline void *ether_payload(void *pkt)
{
  char *cpkt = pkt;
  return &cpkt[14];
}

static inline const void *ether_const_payload(const void *pkt)
{
  const char *cpkt = pkt;
  return &cpkt[14];
}

#define ETHER_HDR_LEN 14U

#define ETHER_TYPE_IP ((uint16_t)0x0800)
#define ETHER_TYPE_ARP ((uint16_t)0x0806)
#define ETHER_TYPE_IPV6 ((uint16_t)0x86DD)

#define IP_HDR_MINLEN 20U

static inline uint8_t ip_version(const void *pkt)
{
  const char *cpkt = pkt;
  return (hdr_get8h(&cpkt[0])>>4)&0xF;
}

static inline uint8_t ipv6_traffic_class(const void *pkt)
{
  const char *cpkt = pkt;
  return  (hdr_get8h(&cpkt[0])&0xF) |
         ((hdr_get8h(&cpkt[1])>>4)&0xF);
         
}

static inline void ipv6_set_traffic_class(void *pkt, uint8_t cls)
{
  char *cpkt = pkt;
  uint8_t ch;
  ch = hdr_get8h(&cpkt[0]);
  hdr_set8h(&cpkt[0], (ch&0xF0) | (cls>>4));
  ch = hdr_get8h(&cpkt[1]);
  hdr_set8h(&cpkt[1], (ch&0x0F) | ((cls&0xF) << 4));
}

static inline void ipv6_set_flow_label(void *pkt, uint32_t fl)
{
  char *cpkt = pkt;
  uint8_t ch;
  ch = hdr_get8h(&cpkt[1]);
  hdr_set8h(&cpkt[1], (ch&0xF0) | ((fl>>16)&0xF));
  hdr_set16n(&cpkt[2], fl&0xFFFF);
}

static inline void ip46_set_flow_label(void *pkt, uint32_t fl)
{
  if (ip_version(pkt) == 4)
  {
    if (fl != 0)
    {
      abort();
    }
  }
  else if (ip_version(pkt) == 6)
  {
    ipv6_set_flow_label(pkt, fl);
  }
  else
  {
    abort();
  }
}

static inline void ipv6_set_payload_len(void *pkt, uint16_t paylen)
{
  char *cpkt = pkt;
  hdr_set16n(&cpkt[4], paylen);
}

static inline void ipv6_set_nexthdr(void *pkt, uint8_t nexthdr)
{
  char *cpkt = pkt;
  hdr_set8h(&cpkt[6], nexthdr);
}

static inline void ipv6_set_hop_limit(void *pkt, uint8_t hl)
{
  char *cpkt = pkt;
  hdr_set8h(&cpkt[7], hl);
}

static inline uint32_t ipv6_flow_label(const void *pkt)
{
  const char *cpkt = pkt;
  return (((hdr_get8h(&cpkt[1]))&0xFU)<<16) | hdr_get16n(&cpkt[2]);
}

static inline uint32_t ip46_flow_label(const void *pkt)
{
  if (ip_version(pkt) == 4)
  {
    return 0;
  }
  else if (ip_version(pkt) == 6)
  {
    return ipv6_flow_label(pkt);
  }
  else
  {
    abort();
  }
}

static inline uint16_t ipv6_payload_len(const void *pkt)
{
  const char *cpkt = pkt;
  return hdr_get16n(&cpkt[4]);
}

static inline uint8_t ipv6_nexthdr(const void *pkt)
{
  const char *cpkt = pkt;
  return hdr_get8h(&cpkt[6]);
}

static inline void *ipv6_nexthdr_ptr(void *pkt)
{
  char *cpkt = pkt;
  return &cpkt[40];
}

static inline const void *ipv6_nexthdr_const_ptr(const void *pkt)
{
  const char *cpkt = pkt;
  return &cpkt[40];
}

static inline uint8_t ipv6_hop_limit(const void *pkt)
{
  const char *cpkt = pkt;
  return hdr_get8h(&cpkt[7]);
}

static inline void *ipv6_src(void *pkt)
{
  char *cpkt = pkt;
  return &cpkt[8];
}

static inline void *ipv6_dst(void *pkt)
{
  char *cpkt = pkt;
  return &cpkt[8+16];
}

static inline const void *ipv6_const_src(const void *pkt)
{
  const char *cpkt = pkt;
  return &cpkt[8];
}

static inline const void *ipv6_const_dst(const void *pkt)
{
  const char *cpkt = pkt;
  return &cpkt[8+16];
}

static inline void *ip_src_ptr(void *pkt)
{
  char *cpkt = pkt;
  return &cpkt[12];
}

static inline void *ip_dst_ptr(void *pkt)
{
  char *cpkt = pkt;
  return &cpkt[16];
}


static inline void *ip46_src(void *pkt)
{
  if (ip_version(pkt) == 4)
  {
    return ip_src_ptr(pkt);
  }
  else if (ip_version(pkt) == 6)
  {
    return ipv6_src(pkt);
  }
  else
  {
    abort();
  }
}

static inline void ip46_set_src(void *pkt, const void *addr)
{
  if (ip_version(pkt) == 4)
  {
    memcpy(ip_src_ptr(pkt), addr, 4);
  }
  else if (ip_version(pkt) == 6)
  {
    memcpy(ipv6_src(pkt), addr, 16);
  }
  else
  {
    abort();
  }
}

static inline void *ip46_dst(void *pkt)
{
  if (ip_version(pkt) == 4)
  {
    return ip_dst_ptr(pkt);
  }
  else if (ip_version(pkt) == 6)
  {
    return ipv6_dst(pkt);
  }
  else
  {
    abort();
  }
}

static inline void ip46_set_dst(void *pkt, const void *addr)
{
  if (ip_version(pkt) == 4)
  {
    memcpy(ip_dst_ptr(pkt), addr, 4);
  }
  else if (ip_version(pkt) == 6)
  {
    memcpy(ipv6_dst(pkt), addr, 16);
  }
  else
  {
    abort();
  }
}

static inline const void *ip_const_src_ptr(const void *pkt)
{
  const char *cpkt = pkt;
  return &cpkt[12];
}

static inline const void *ip_const_dst_ptr(const void *pkt)
{
  const char *cpkt = pkt;
  return &cpkt[16];
}

static inline const void *ip46_const_src(const void *pkt)
{
  if (ip_version(pkt) == 4)
  {
    return ip_const_src_ptr(pkt);
  }
  else if (ip_version(pkt) == 6)
  {
    return ipv6_const_src(pkt);
  }
  else
  {
    abort();
  }
}

static inline const void *ip46_const_dst(const void *pkt)
{
  if (ip_version(pkt) == 4)
  {
    return ip_const_dst_ptr(pkt);
  }
  else if (ip_version(pkt) == 6)
  {
    return ipv6_const_dst(pkt);
  }
  else
  {
    abort();
  }
}

static inline uint32_t ipv6_extlen(uint8_t nexthdr, uint8_t lenfield)
{
  if (nexthdr == 44) // FRAG
  {
    return 8;
  }
  if (nexthdr == 51) // AH
  {
    return ((uint32_t)(uint8_t)lenfield) * 4 + 8;
  }
  return ((uint32_t)(uint8_t)lenfield) * 8 + 8;
}

static inline int is_ipv6_nexthdr(uint8_t nexthdr)
{
  return (nexthdr == 0 || // hop-by-hop options, OK
          nexthdr == 60 || // destination options, OK
          nexthdr == 43 || // routing, OK
          nexthdr == 44 || // FRAG, OK
          nexthdr == 51); // AH, OK
          //nexthdr == 135 || // mobility,
          //nexthdr == 139 || // host identity protocol version 2
          //nexthdr == 140); // Shim6
}

static inline uint16_t ipv6_frag_off(const void *frag)
{
  const char *cfrag = frag;
  return (hdr_get16n(&cfrag[2])&0xFFF8);
}

static inline uint16_t ipv6_more_frags(const void *frag)
{
  const char *cfrag = frag;
  return !!(hdr_get16n(&cfrag[2])&1);
}

// NB: assumes ipv6 total length field has been validated
static inline void *ipv6_proto_hdr_2(
  void *ipv6, uint8_t *proto,
  int *is_fragmented_ptr, uint16_t *frag_hdr_off_ptr,
  uint16_t *proto_hdr_off_from_frag)
{
  unsigned char *cipv6 = ipv6;
  uint16_t plen = ipv6_payload_len(ipv6);
  uint32_t tlen = plen + 40U;
  uint16_t off = 40;
  uint8_t nexthdr = ipv6_nexthdr(ipv6);
  int is_fragmented = 0;
  uint16_t frag_hdr_off = 0;
  while (is_ipv6_nexthdr(nexthdr))
  {
    uint32_t extlen;
    if (off + 8U > tlen)
    {
      return NULL;
    }
    if (nexthdr == 44)
    {
      is_fragmented = 1;
      frag_hdr_off = off;
      if (ipv6_frag_off(&cipv6[off]) > 0)
      {
        break;
      }
    }
    nexthdr = cipv6[off];
    extlen = ipv6_extlen(nexthdr, cipv6[off + 1]);
    if (off + extlen > tlen)
    {
      return NULL;
    }
    off += extlen;
  }
  if (proto)
  {
    *proto = nexthdr;
  }
  if (is_fragmented_ptr)
  {
    *is_fragmented_ptr = is_fragmented;
  }
  if (is_fragmented)
  {
    if (frag_hdr_off_ptr)
    {
      *frag_hdr_off_ptr = frag_hdr_off;
    }
    if (proto_hdr_off_from_frag)
    {
      *proto_hdr_off_from_frag = off - frag_hdr_off;
    }
  }
  return &cipv6[off];
}
static inline void *ipv6_proto_hdr(
  void *ipv6, uint8_t *proto)
{
  return ipv6_proto_hdr_2(ipv6, proto, NULL, NULL, NULL);
}

// NB: assumes ipv6 total length field has been validated
static inline const void *ipv6_const_proto_hdr_2(
  const void *ipv6, uint8_t *proto,
  int *is_fragmented_ptr, uint16_t *frag_hdr_off_ptr,
  uint16_t *proto_hdr_off_from_frag)
{
  const unsigned char *cipv6 = ipv6;
  uint16_t plen = ipv6_payload_len(ipv6);
  uint32_t tlen = plen + 40U;
  uint16_t off = 40;
  uint8_t nexthdr = ipv6_nexthdr(ipv6);
  int is_fragmented = 0;
  uint16_t frag_hdr_off = 0;
  while (is_ipv6_nexthdr(nexthdr))
  {
    uint32_t extlen;
    if (off + 8U > tlen)
    {
      return NULL;
    }
    if (nexthdr == 44)
    {
      is_fragmented = 1;
      frag_hdr_off = off;
      if (ipv6_frag_off(&cipv6[off]) > 0)
      {
        break;
      }
    }
    nexthdr = cipv6[off];
    extlen = ipv6_extlen(nexthdr, cipv6[off + 1]);
    if (off + extlen > tlen)
    {
      return NULL;
    }
    off += extlen;
  }
  if (proto)
  {
    *proto = nexthdr;
  }
  if (is_fragmented_ptr)
  {
    *is_fragmented_ptr = is_fragmented;
  }
  if (is_fragmented)
  {
    if (frag_hdr_off_ptr)
    {
      *frag_hdr_off_ptr = frag_hdr_off;
    }
    if (proto_hdr_off_from_frag)
    {
      *proto_hdr_off_from_frag = off - frag_hdr_off;
    }
  }
  return &cipv6[off];
}
static inline const void *ipv6_const_proto_hdr(
  const void *ipv6, uint8_t *proto)
{
  return ipv6_const_proto_hdr_2(ipv6, proto, NULL, NULL, NULL);
}

static inline void ip_set_version(void *pkt, uint8_t version)
{
  unsigned char *cpkt = pkt;
  unsigned char uch = cpkt[0];
  uch &= ~0xF0;
  uch |= (version & 0xF) << 4;
  cpkt[0] = uch;
}

static inline uint8_t ip_hdr_len(const void *pkt)
{
  const char *cpkt = pkt;
  return ((hdr_get8h(&cpkt[0]))&0xF)*4;
}

static inline uint8_t ip46_hdr_len(const void *pkt)
{
  if (ip_version(pkt) == 4)
  {
    return ip_hdr_len(pkt);
  }
  else if (ip_version(pkt) == 6)
  {
    return 40;
  }
  abort();
}

static inline void ip_set_hdr_len(void *pkt, uint8_t hdr_len)
{
  unsigned char *cpkt = pkt;
  unsigned char uch = cpkt[0];
  if (hdr_len % 4 != 0)
  {
    abort();
  }
  hdr_len /= 4;
  uch &= ~0xF;
  uch |= hdr_len & 0xF;
  cpkt[0] = uch;
}

static inline void ip46_set_hdr_len(void *pkt, uint8_t hdr_len)
{
  if (ip_version(pkt) == 4)
  {
    ip_set_hdr_len(pkt, hdr_len);
  }
  else if (ip_version(pkt) == 6)
  {
    if (hdr_len != 40)
    {
      abort();
    }
  }
  else
  {
    abort();
  }
}

static inline void ip46_set_min_hdr_len(void *pkt)
{
  if (ip_version(pkt) == 4)
  {
    ip_set_hdr_len(pkt, 20);
  }
  else if (ip_version(pkt) == 6)
  {
  }
  else
  {
    abort();
  }
}

static inline uint16_t ip_total_len(const void *pkt)
{
  const char *cpkt = pkt;
  return hdr_get16n(&cpkt[2]);
}

static inline void ip_set_total_len(void *pkt, uint16_t total_len)
{
  char *cpkt = pkt;
  hdr_set16n(&cpkt[2], total_len);
}

static inline void ip46_set_total_len(void *pkt, uint16_t total_len)
{
  if (ip_version(pkt) == 4)
  {
    ip_set_total_len(pkt, total_len);
  }
  else if (ip_version(pkt) == 6)
  {
    if (total_len < 40)
    {
      abort();
    }
    ipv6_set_payload_len(pkt, total_len - 40);
  }
  else
  {
    abort();
  }
}

static inline void ip46_set_payload_len(void *pkt, uint16_t payload_len)
{
  if (ip_version(pkt) == 4)
  {
    ip_set_total_len(pkt, payload_len + 20);
  }
  else if (ip_version(pkt) == 6)
  {
    ipv6_set_payload_len(pkt, payload_len);
  }
  else
  {
    abort();
  }
}

static inline uint16_t ip46_total_len(const void *pkt)
{
  if (ip_version(pkt) == 4)
  {
    return ip_total_len(pkt);
  }
  else if (ip_version(pkt) == 6)
  {
    return ipv6_payload_len(pkt) + 40;
  }
  else
  {
    abort();
  }
}

static inline uint16_t ip46_payload_len(const void *pkt)
{
  if (ip_version(pkt) == 4)
  {
    return ip_total_len(pkt) - ip_hdr_len(pkt);
  }
  else if (ip_version(pkt) == 6)
  {
    return ipv6_payload_len(pkt);
  }
  else
  {
    abort();
  }
}

static inline int ip_more_frags(const void *pkt)
{
  const char *cpkt = pkt;
  return hdr_get8h(&cpkt[6]) & (1<<5);
}

static inline void ip_set_more_frags(void *pkt, int bit)
{
  char *cpkt = pkt;
  uint8_t u8;
  bit = !!bit;
  u8 = hdr_get8h(&cpkt[6]);
  u8 &= ~(1<<5);
  u8 |= bit<<5;
  hdr_set8h(&cpkt[6], u8);
}

static inline int ip_dont_frag(const void *pkt)
{
  const char *cpkt = pkt;
  return hdr_get8h(&cpkt[6]) & (1<<6);
}

static inline void ip_set_dont_frag(void *pkt, int bit)
{
  char *cpkt = pkt;
  uint8_t u8;
  bit = !!bit;
  u8 = hdr_get8h(&cpkt[6]);
  u8 &= ~(1<<6);
  u8 |= bit<<6;
  hdr_set8h(&cpkt[6], u8);
}

static inline void ip46_set_dont_frag(void *pkt, int bit)
{
  if (ip_version(pkt) == 4)
  {
    ip_set_dont_frag(pkt, bit);
  }
  else if (ip_version(pkt) == 6)
  {
    if (!bit)
    {
      abort();
    }
  }
  else
  {
    abort();
  }
}

static inline int ip_rsvd_bit(const void *pkt)
{
  const char *cpkt = pkt;
  return hdr_get8h(&cpkt[6]) & (1<<7);
}

static inline void ip_set_rsvd_bit(void *pkt, int bit)
{
  char *cpkt = pkt;
  uint8_t u8;
  bit = !!bit;
  u8 = hdr_get8h(&cpkt[6]);
  u8 &= ~(1<<7);
  u8 |= bit<<7;
  hdr_set8h(&cpkt[6], u8);
}

static inline uint16_t ip_id(const void *pkt)
{
  const char *cpkt = pkt;
  return hdr_get16n(&cpkt[4]);
}

static inline void ip_set_id(void *pkt, uint16_t id)
{
  char *cpkt = pkt;
  hdr_set16n(&cpkt[4], id);
}

static inline void ip46_set_id(void *pkt, uint16_t ipid)
{
  if (ip_version(pkt) == 4)
  {
    ip_set_id(pkt, ipid);
  }
  else if (ip_version(pkt) == 6)
  {
    if (ipid)
    {
      abort();
    }
  }
  else
  {
    abort();
  }
}

static inline uint16_t ip_frag_off(const void *pkt)
{
  const char *cpkt = pkt;
  return (hdr_get16n(&cpkt[6])&0x1FFF)*8;
}

static inline void ip_set_frag_off(void *pkt, uint16_t frag_off)
{
  char *cpkt = pkt;
  unsigned char c6;
  if (frag_off % 8 != 0)
  {
    abort();
  }
  frag_off /= 8;
  c6 = (unsigned char)cpkt[6];
  c6 &= ~0x1F;
  c6 |= (frag_off>>8) & 0x1F;
  cpkt[6] = (char)c6;
  cpkt[7] = (char)(unsigned char)(frag_off&0xFF);
}

static inline uint8_t ip_ttl(const void *pkt)
{
  const char *cpkt = pkt;
  return hdr_get8h(&cpkt[8]);
}

static inline void ip_set_ttl(void *pkt, uint8_t ttl)
{
  char *cpkt = pkt;
  hdr_set8h(&cpkt[8], ttl);
}

static inline int ip_decr_ttl(void *pkt)
{
  uint8_t ttl;
  ttl = ip_ttl(pkt);
  if (ttl == 0)
  {
    abort();
  }
  ttl--;
  ip_set_ttl(pkt, ttl);
  return ttl > 0;
}

static inline uint8_t ip_proto(const void *pkt)
{
  const char *cpkt = pkt;
  return hdr_get8h(&cpkt[9]);
}

static inline uint8_t ip46_proto(const void *pkt)
{
  if (ip_version(pkt) == 4)
  {
    return ip_proto(pkt);
  }
  else if (ip_version(pkt) == 6)
  {
    return ipv6_nexthdr(pkt);
  }
  else
  {
    abort();
  }
}

static inline void ip_set_proto(void *pkt, uint8_t proto)
{
  char *cpkt = pkt;
  hdr_set8h(&cpkt[9], proto);
}

static inline void ip46_set_proto(void *pkt, uint8_t proto)
{
  if (ip_version(pkt) == 4)
  {
    ip_set_proto(pkt, proto);
  }
  else if (ip_version(pkt) == 6)
  {
    ipv6_set_nexthdr(pkt, proto);
  }
  else
  {
    abort();
  }
}

static inline uint8_t ip46_ttl(const void *pkt)
{
  if (ip_version(pkt) == 4)
  {
    return ip_ttl(pkt);
  }
  else if (ip_version(pkt) == 6)
  {
    return ipv6_hop_limit(pkt);
  }
  else
  {
    abort();
  }
}

static inline void ip46_set_ttl(void *pkt, uint8_t ttl)
{
  if (ip_version(pkt) == 4)
  {
    ip_set_ttl(pkt, ttl);
  }
  else if (ip_version(pkt) == 6)
  {
    ipv6_set_hop_limit(pkt, ttl);
  }
  else
  {
    abort();
  }
}

static inline uint16_t ip_hdr_cksum(const void *pkt)
{
  const char *cpkt = pkt;
  return hdr_get16n(&cpkt[10]);
}

static inline void ip_set_hdr_cksum(void *pkt, uint16_t hdr_cksum)
{
  char *cpkt = pkt;
  hdr_set16n(&cpkt[10], hdr_cksum);
}

static inline uint32_t ip_src(const void *pkt)
{
  const char *cpkt = pkt;
  return hdr_get32n(&cpkt[12]);
}

static inline uint32_t ip_dst(const void *pkt)
{
  const char *cpkt = pkt;
  return hdr_get32n(&cpkt[16]);
}

static inline void ip_set_src(void *pkt, uint32_t src)
{
  char *cpkt = pkt;
  hdr_set32n(&cpkt[12], src);
}

static inline void ip_set_dst(void *pkt, uint32_t dst)
{
  char *cpkt = pkt;
  hdr_set32n(&cpkt[16], dst);
}

static inline void *ip_payload(void *pkt)
{
  return ((char*)pkt) + ip_hdr_len(pkt);
}

static inline void *ip46_payload(void *pkt)
{
  return ((char*)pkt) + ip46_hdr_len(pkt);
}

static inline const void *ip_const_payload(const void *pkt)
{
  return ((const char*)pkt) + ip_hdr_len(pkt);
}

static inline const void *ip46_const_payload(const void *pkt)
{
  return ((const char*)pkt) + ip46_hdr_len(pkt);
}

static inline uint16_t tcp_src_port(const void *pkt)
{
  const char *cpkt = pkt;
  return hdr_get16n(&cpkt[0]);
}

static inline uint16_t tcp_dst_port(const void *pkt)
{
  const char *cpkt = pkt;
  return hdr_get16n(&cpkt[2]);
}

static inline void tcp_set_src_port(void *pkt, uint16_t src_port)
{
  char *cpkt = pkt;
  hdr_set16n(&cpkt[0], src_port);
}

static inline void tcp_set_dst_port(void *pkt, uint16_t dst_port)
{
  char *cpkt = pkt;
  hdr_set16n(&cpkt[2], dst_port);
}

static inline int tcp_ack(const void *pkt)
{
  const char *cpkt = pkt;
  return !!(hdr_get8h(&cpkt[13]) & (1<<4));
}

static inline void tcp_set_ack_on(void *pkt)
{
  char *cpkt = pkt;
  hdr_set8h(&cpkt[13], hdr_get8h(&cpkt[13]) | (1<<4));
}

static inline void tcp_set_ack_off(void *pkt)
{
  char *cpkt = pkt;
  hdr_set8h(&cpkt[13], hdr_get8h(&cpkt[13]) & ~(1<<4));
}

static inline int tcp_rst(const void *pkt)
{
  const char *cpkt = pkt;
  return !!(hdr_get8h(&cpkt[13]) & (1<<2));
}

static inline void tcp_set_rst_on(void *pkt)
{
  char *cpkt = pkt;
  hdr_set8h(&cpkt[13], hdr_get8h(&cpkt[13]) | (1<<2));
}

static inline int tcp_syn(const void *pkt)
{
  const char *cpkt = pkt;
  return !!(hdr_get8h(&cpkt[13]) & (1<<1));
}

static inline void tcp_set_syn_on(void *pkt)
{
  char *cpkt = pkt;
  hdr_set8h(&cpkt[13], hdr_get8h(&cpkt[13]) | (1<<1));
}

static inline int tcp_fin(const void *pkt)
{
  const char *cpkt = pkt;
  return !!(hdr_get8h(&cpkt[13]) & (1<<0));
}

static inline void tcp_set_fin_on(void *pkt)
{
  char *cpkt = pkt;
  hdr_set8h(&cpkt[13], hdr_get8h(&cpkt[13]) | (1<<0));
}

static inline uint16_t tcp_cksum(const void *pkt)
{
  const char *cpkt = pkt;
  return hdr_get16n(&cpkt[16]);
}

static inline void tcp_set_cksum(void *pkt, uint16_t checksum)
{
  char *cpkt = pkt;
  hdr_set16n(&cpkt[16], checksum);
}

static inline uint16_t udp_src_port(const void *pkt)
{
  const char *cpkt = pkt;
  return hdr_get16n(&cpkt[0]);
}

static inline uint16_t udp_dst_port(const void *pkt)
{
  const char *cpkt = pkt;
  return hdr_get16n(&cpkt[2]);
}

static inline void udp_set_src_port(void *pkt, uint16_t src_port)
{
  char *cpkt = pkt;
  hdr_set16n(&cpkt[0], src_port);
}

static inline void udp_set_dst_port(void *pkt, uint16_t dst_port)
{
  char *cpkt = pkt;
  hdr_set16n(&cpkt[2], dst_port);
}

static inline uint16_t udp_total_len(const void *pkt)
{
  const char *cpkt = pkt;
  return hdr_get16n(&cpkt[4]);
}

static inline void udp_set_total_len(void *pkt, uint16_t total_len)
{
  char *cpkt = pkt;
  hdr_set16n(&cpkt[4], total_len);
}

static inline uint16_t udp_cksum(const void *pkt)
{
  const char *cpkt = pkt;
  return hdr_get16n(&cpkt[6]);
}

static inline void udp_set_cksum(void *pkt, uint16_t cksum)
{
  char *cpkt = pkt;
  hdr_set16n(&cpkt[6], cksum);
}

static inline uint32_t tcp_seq_number(const void *pkt)
{
  const char *cpkt = pkt;
  return hdr_get32n(&cpkt[4]);
}

static inline uint32_t tcp_ack_number(const void *pkt)
{
  const char *cpkt = pkt;
  return hdr_get32n(&cpkt[8]);
}

static inline void tcp_set_seq_number(void *pkt, uint32_t seq_number)
{
  char *cpkt = pkt;
  hdr_set32n(&cpkt[4], seq_number);
}

static inline void tcp_set_ack_number(void *pkt, uint32_t ack_number)
{
  char *cpkt = pkt;
  hdr_set32n(&cpkt[8], ack_number);
}

static inline uint16_t tcp_window(const void *pkt)
{
  const char *cpkt = pkt;
  return hdr_get16n(&cpkt[14]);
}

static inline void tcp_set_window(void *pkt, uint16_t window)
{
  char *cpkt = pkt;
  hdr_set16n(&cpkt[14], window);
}

static inline void tcp_set_data_offset(void *pkt, uint8_t data_off)
{
  uint8_t val;
  char *cpkt = pkt;
  if (data_off % 4 != 0 || data_off > 60)
  {
    abort();
  }
  val = hdr_get8h(&cpkt[12]);
  val &= ~0xF0;
  val |= ((data_off/4)<<4);
  hdr_set8h(&cpkt[12], val);
}

static inline uint8_t tcp_data_offset(const void *pkt)
{
  const char *cpkt = pkt;
  return (hdr_get8h(&cpkt[12])>>4)*4;
}

struct sack_ts_headers {
  uint8_t sackoff;
  uint8_t sacklen;
  uint8_t tsoff;
};

void tcp_find_sack_ts_headers(
  void *pkt, struct sack_ts_headers *hdrs);

void *tcp_find_sack_header(
  void *pkt, size_t *sacklen, int *sixteen_bit_align);

static inline uint32_t tcp_tsval(
  const void *pkt, struct sack_ts_headers *hdrs)
{
  const char *cpkt = pkt;
  if (hdrs->tsoff < 20)
  {
    abort();
  }
  return hdr_get32n(&cpkt[hdrs->tsoff + 2]);
}

static inline uint32_t tcp_tsecho(
  const void *pkt, struct sack_ts_headers *hdrs)
{
  const char *cpkt = pkt;
  if (hdrs->tsoff < 20)
  {
    abort();
  }
  return hdr_get32n(&cpkt[hdrs->tsoff + 6]);
}

struct tcp_information {
  uint8_t options_valid;
  uint8_t wscale;
  uint16_t mss;
  uint8_t sack_permitted;
  uint8_t mssoff; // from beginning of TCP header
  uint8_t ts_present;
  uint32_t ts;
  uint32_t tsecho;
};

void tcp_parse_options(
  void *pkt,
  struct tcp_information *info);

#endif
