#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "llalloc.h"
#include "iphdr.h"
#include "packet.h"
#include "ipcksum.h"
#include "ipfrag.h"
#include "containerof.h"
#include "ipreass.h"

void reassctx_init(struct reassctx *ctx)
{
  linked_list_head_init(&ctx->hole_list);
  linked_list_head_init(&ctx->packet_list);
  ctx->first_hole.first = 0;
  ctx->first_hole.last = 65535;
  ctx->most_restricting_last = 65535;
  linked_list_add_tail(&ctx->first_hole.node, &ctx->hole_list);
}

void reassctx_free(struct allocif *loc, struct reassctx *ctx)
{
  struct linked_list_node *iter, *tmp;
  LINKED_LIST_FOR_EACH_SAFE(iter, tmp, &ctx->packet_list)
  {
    struct packet *pkt = CONTAINER_OF(iter, struct packet, node);
    linked_list_delete(&pkt->node);
    allocif_free(loc, pkt);
  }
}

struct packet *
reassctx_reassemble(struct allocif *loc, struct reassctx *ctx)
{
  struct packet *first_packet;
  const char *ether, *ip;
  char *ether2, *ip2, *pay2;
  size_t sz;
  uint16_t hdr_len;
  struct packet *pkt;
  struct linked_list_node *iter;
  if (linked_list_is_empty(&ctx->packet_list))
  {
    abort();
  }
  first_packet = CONTAINER_OF(ctx->packet_list.node.next, struct packet, node);
  ether = first_packet->data;
  ip = ether_const_payload(ether);
  hdr_len = ip_hdr_len(ip);
  sz = ETHER_HDR_LEN + hdr_len + ctx->most_restricting_last + 1;
  pkt = allocif_alloc(loc, packet_size(sz));
  if (pkt == NULL)
  {
    return NULL;
  }
  pkt->sz = sz;
  pkt->direction = first_packet->direction;
  pkt->data = packet_calc_data(pkt);
  ether2 = pkt->data;
  memcpy(ether2, ether, ETHER_HDR_LEN + hdr_len);
  ip2 = ether_payload(ether2);
  ip_set_frag_off(ip2, 0);
  ip_set_more_frags(ip2, 0);
  ip_set_total_len(ip2, hdr_len + ctx->most_restricting_last + 1);
  ip_set_hdr_cksum_calc(ip2, hdr_len);
  pay2 = ip_payload(ip2);
  LINKED_LIST_FOR_EACH(iter, &ctx->packet_list)
  {
    struct packet *pktorig = CONTAINER_OF(iter, struct packet, node);
    const char *etherorig, *iporig, *payorig;
    uint16_t first, len;
    etherorig = pktorig->data;
    iporig = ether_const_payload(etherorig);
    payorig = ip_const_payload(iporig);
    first = ip_frag_off(iporig);
    len = ip_total_len(iporig) - ip_hdr_len(iporig);
    if (first + len - 1 > ctx->most_restricting_last)
    {
      memcpy(pay2 + first, payorig, 1U + ctx->most_restricting_last - first);
    }
    else
    {
      memcpy(pay2 + first, payorig, len);
    }
  }
  return pkt;
}

#if 0
static void linktest(struct reassctx *ctx)
{
  struct linked_list_node *iter;
  printf("start iter\n");
  LINKED_LIST_FOR_EACH(iter, &ctx->hole_list)
  {
    struct hole *hole = CONTAINER_OF(iter, struct hole, node);
    printf("hole %d-%d\n", hole->first, hole->last);
  }
}
#endif

void reassctx_add(struct reassctx *ctx, struct packet *pkt)
{
  const char *ether = pkt->data;
  const char *ip = ether_const_payload(ether);
  uint16_t data_first;
  uint16_t data_last;
  struct linked_list_node *iter, *tmp;
  linked_list_add_tail(&pkt->node, &ctx->packet_list);
  //linktest(ctx);
  if (pkt->sz < 34 ||
      ip_total_len(ip) <= ip_hdr_len(ip) ||
      (size_t)(ip_total_len(ip) + 14) > pkt->sz)
  {
    return;
  }
  data_first = ip_frag_off(ip);
  if (ip_total_len(ip) - (ip_hdr_len(ip) + 1) + ip_frag_off(ip) > 65535)
  {
    return;
  }
  data_last = ip_total_len(ip) - (ip_hdr_len(ip) + 1) + ip_frag_off(ip);
  if (!ip_more_frags(ip) && ctx->most_restricting_last > data_last)
  {
    ctx->most_restricting_last = data_last;
    LINKED_LIST_FOR_EACH_SAFE(iter, tmp, &ctx->hole_list)
    {
      struct hole *hole = CONTAINER_OF(iter, struct hole, node);
      if (hole->first > ctx->most_restricting_last)
      {
        linked_list_delete(&hole->node);
        continue;
      }
      if (hole->last > ctx->most_restricting_last)
      {
        hole->last = ctx->most_restricting_last;
        continue;
      }
    }
  }
#if 0
  else
  {
    if (data_last < 7)
    {
      return;
    }
    data_last = (data_last + 1) / 8 * 8 - 1;
  }
#endif
  //printf("first %d last %d\n", data_first, data_last);
  LINKED_LIST_FOR_EACH_SAFE(iter, tmp, &ctx->hole_list)
  {
    struct hole *hole = CONTAINER_OF(iter, struct hole, node);
    if (data_last == hole->last)
    {
      if (data_first <= hole->first)
      {
        linked_list_delete(&hole->node);
        return;
      }
      else
      {
        hole->last = data_first - 1;
        return;
      }
    }
    else if (data_last < hole->last)
    {
      if (data_first <= hole->first)
      {
        if (data_last + 1 > hole->first)
        {
          hole->first = data_last + 1;
        }
        return;
      }
      else
      {
        struct hole *hole_before = &pkt->u.hole;
        linked_list_add_before(&hole_before->node, &hole->node);
        hole_before->first = hole->first;
        hole_before->last = data_first - 1;
        hole->first = data_last + 1;
        return;
      }
    }
    else
    {
      if (data_first <= hole->first)
      {
        linked_list_delete(&hole->node);
        continue;
      }
      else
      {
        if (hole->last > data_first - 1)
        {
          hole->last = data_first - 1;
        }
        continue;
      }
    }
  }
}
