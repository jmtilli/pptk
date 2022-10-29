#ifndef _DNSHDR_H_
#define _DNSHDR_H_

#include "hdr.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

static inline uint16_t dns_id(const void *vdns)
{
  unsigned const char *cdns = vdns;
  return hdr_get16n(&cdns[0]);
}
static inline void dns_set_id(void *vdns, uint16_t id)
{
  unsigned char *cdns = vdns;
  hdr_set16n(&cdns[0], id);
}
static inline uint8_t dns_qr(const void *vdns)
{
  unsigned const char *cdns = vdns;
  return !!(cdns[2] & (1<<7));
}
static inline void dns_set_qr(void *vdns, uint8_t bit)
{
  unsigned char *cdns = vdns;
  cdns[2] &= (uint8_t)~(1<<7);
  cdns[2] = (uint8_t)(cdns[2] | ((!!bit)<<7));
}
#define DNS_OPCODE_QUERY 0
#define DNS_OPCODE_IQUERY 1
#define DNS_OPCODE_STATUS 2
static inline uint8_t dns_opcode(const void *vdns)
{
  unsigned const char *cdns = vdns;
  return (cdns[2] & 0x78) >> 3;
}
static inline void dns_set_opcode(void *vdns, uint8_t bits)
{
  unsigned char *cdns = vdns;
  cdns[2] &= (uint8_t)~0x78;
  cdns[2] = (uint8_t)(cdns[2] | ((bits&0xF)<<3));
}
static inline uint8_t dns_aa(const void *vdns)
{
  unsigned const char *cdns = vdns;
  return !!(cdns[2] & (1<<2));
}
static inline void dns_set_aa(void *vdns, uint8_t bit)
{
  unsigned char *cdns = vdns;
  cdns[2] &= (uint8_t)~(1<<2);
  cdns[2] = (uint8_t)(cdns[2] | ((!!bit)<<2));
}
static inline uint8_t dns_tc(const void *vdns)
{
  unsigned const char *cdns = vdns;
  return !!(cdns[2] & (1<<1));
}
static inline void dns_set_tc(void *vdns, uint8_t bit)
{
  unsigned char *cdns = vdns;
  cdns[2] &= (uint8_t)~(1<<1);
  cdns[2] = (uint8_t)(cdns[2] | ((!!bit)<<1));
}
static inline uint8_t dns_rd(const void *vdns)
{
  unsigned const char *cdns = vdns;
  return !!(cdns[2] & (1<<0));
}
static inline void dns_set_rd(void *vdns, uint8_t bit)
{
  unsigned char *cdns = vdns;
  cdns[2] &= (uint8_t)~(1<<0);
  cdns[2] |= (uint8_t)(cdns[2] | ((!!bit)<<0));
}
static inline uint8_t dns_ra(const void *vdns)
{
  unsigned const char *cdns = vdns;
  return !!(cdns[3] & (1<<7));
}
static inline void dns_set_ra(void *vdns, uint8_t bit)
{
  unsigned char *cdns = vdns;
  cdns[3] &= (uint8_t)~(1<<7);
  cdns[3] = (uint8_t)(cdns[3] | ((!!bit)<<7));
}
static inline uint8_t dns_z(const void *vdns)
{
  unsigned const char *cdns = vdns;
  return (cdns[3] & 0x70) >> 4;
}
static inline void dns_set_z(void *vdns)
{
  unsigned char *cdns = vdns;
  cdns[3] &= (uint8_t)~0x70;
}
static inline uint8_t dns_rcode(const void *vdns)
{
  unsigned const char *cdns = vdns;
  return (cdns[3] & 0x0F);
}
static inline void dns_set_rcode(void *vdns, uint8_t bits)
{
  unsigned char *cdns = vdns;
  cdns[3] &= (uint8_t)~0x0F;
  cdns[3] = (uint8_t)(cdns[3] | (bits&0x0F));
}
static inline uint16_t dns_qdcount(const void *vdns)
{
  unsigned const char *cdns = vdns;
  return hdr_get16n(&cdns[4]);
}
static inline uint16_t dns_ancount(const void *vdns)
{
  unsigned const char *cdns = vdns;
  return hdr_get16n(&cdns[6]);
}
static inline uint16_t dns_nscount(const void *vdns)
{
  unsigned const char *cdns = vdns;
  return hdr_get16n(&cdns[8]);
}
static inline uint16_t dns_arcount(const void *vdns)
{
  unsigned const char *cdns = vdns;
  return hdr_get16n(&cdns[10]);
}
static inline void dns_set_qdcount(void *vdns, uint16_t val)
{
  unsigned char *cdns = vdns;
  return hdr_set16n(&cdns[4], val);
}
static inline void dns_set_ancount(void *vdns, uint16_t val)
{
  unsigned char *cdns = vdns;
  return hdr_set16n(&cdns[6], val);
}
static inline void dns_set_nscount(void *vdns, uint16_t val)
{
  unsigned char *cdns = vdns;
  return hdr_set16n(&cdns[8], val);
}
static inline void dns_set_arcount(void *vdns, uint16_t val)
{
  unsigned char *cdns = vdns;
  return hdr_set16n(&cdns[10], val);
}

static inline void dns_next_init_an(void *vdns, uint16_t *off, uint16_t *remcnt)
{
  dns_set_ancount(vdns, *remcnt);
  *off = 12; 
}
static inline void dns_next_init_ns(void *vdns, uint16_t *off, uint16_t *remcnt)
{
  dns_set_nscount(vdns, *remcnt);
}
static inline void dns_next_init_ar(void *vdns, uint16_t *off, uint16_t *remcnt)
{
  dns_set_arcount(vdns, *remcnt);
}

static inline void dns_next_init_qd(const void *vdns, uint16_t *off, uint16_t *remcnt,
                                    uint16_t plen)
{
  if (plen < 12)
  {
    abort();
  }
  *off = 12;
  *remcnt = dns_qdcount(vdns);
}

static inline void dns_next_init_an_ask(const void *vdns, uint16_t *off, uint16_t *remcnt,
                                        uint16_t plen)
{
  if (plen < *off)
  {
    abort();
  }
  *remcnt = dns_ancount(vdns);
}

int dns_next_an_ask(const void *vdns, uint16_t *off, uint16_t *remcnt,
                    uint16_t plen,
                    char *buf, size_t bufsiz, uint16_t *qtype,
                    uint16_t *qclass, uint32_t *ttl,
                    char *datbuf, size_t datbufsiz, size_t *datbuflen);

int dns_put_next(void *vdns, uint16_t *off, uint16_t *remcnt,
                 uint16_t plen,
                 char *buf,
                 uint16_t qtype, uint16_t qclass, uint32_t ttl,
                 uint16_t rdlength, void *rdata);

int dns_put_next_qr(void *vdns, uint16_t *off, uint16_t *remcnt,
                    uint16_t plen,
                    char *buf,
                    uint16_t qtype, uint16_t qclass);

int dns_next(const void *vdns, uint16_t *off, uint16_t *remcnt,
             uint16_t plen,
             char *buf, size_t bufsiz, uint16_t *qtype,
             uint16_t *qclass);

int recursive_resolve(const char *pkt, size_t recvd, const char *name,
                      uint16_t qclassexp, uint16_t *qtypeptr,
                      char *databuf, size_t databufsiz, size_t *datalen);

#endif
