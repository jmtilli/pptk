#ifndef _ARP_H_
#define _ARP_H_

#include "packet.h"
#include "ports.h"
#include "hashtable.h"
#include "linkedlist.h"
#include "containerof.h"
#include "siphash.h"
#include "hashseed.h"
#include "timerlink.h"

struct arp_entry {
  struct hash_list_node node;
  uint32_t ip;
  char mac[6];
  int valid;
  struct linked_list_head list;
  struct timer_link timer;
  uint64_t last_tx;
};

void arp_entry_expiry_fn(struct timer_link *timer, struct timer_linkheap *heap, void *userdata, void *threaddata);

static inline uint32_t ip_hash(uint32_t ip)
{
  return (uint32_t)siphash64(hash_seed_get(), ip);
}

static inline uint32_t arp_entry_hash(struct arp_entry *e)
{
  return ip_hash(e->ip);
}

uint32_t arp_entry_hash_fn(struct hash_list_node *node, void *userdata);

struct arp_cache {
  struct hash_table hash;
  struct allocif *intf;
};

static inline void arp_cache_init(struct arp_cache *cache, struct allocif *intf)
{
  if (hash_table_init(&cache->hash, 1024, arp_entry_hash_fn, NULL) != 0)
  {
    abort();
  }
  cache->intf = intf;
}

void arp_cache_drain(struct arp_entry *entry, struct port *port);

static inline struct arp_entry *arp_cache_get_accept_invalid(
  struct arp_cache *cache, uint32_t ip)
{
  uint32_t hashval = ip_hash(ip);
  struct hash_list_node *node;
  struct arp_entry *entry;
  HASH_TABLE_FOR_EACH_POSSIBLE(&cache->hash, node, hashval)
  {
    entry = CONTAINER_OF(node, struct arp_entry, node);
    if (entry->ip == ip)
    {
      return entry;
    }
  }
  return NULL;
}

static inline struct arp_entry *arp_cache_get(
  struct arp_cache *cache, uint32_t ip)
{
  struct arp_entry *e;
  e = arp_cache_get_accept_invalid(cache, ip);
  if (e == NULL || !e->valid)
  {
    return NULL;
  }
  return e;
}

struct arp_entry *arp_cache_put_packet(
  struct arp_cache *cache, uint32_t ip, struct packet *pkt,
  struct timer_linkheap *timers, uint64_t time64);

void arp_cache_put(
  struct arp_cache *cache, struct port *port, uint32_t ip, const char *mac,
  struct timer_linkheap *timers, uint64_t time64);

#endif
