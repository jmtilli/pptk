#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "llalloc.h"
#include "iphdr.h"
#include "packet.h"
#include "ipcksum.h"
#include "ipfrag.h"
#include "containerof.h"
#include "iprbexplicit.h"

static int
rb_hole_tree_cmp(struct rb_tree_node *a, struct rb_tree_node *b, void *ud)
{
  struct rbhole *ha = CONTAINER_OF(a, struct rbhole, node);
  struct rbhole *hb = CONTAINER_OF(b, struct rbhole, node);
  if (ha->last < hb->first)
  {
    return -1;
  }
  if (hb->last < ha->first)
  {
    return 1;
  }
  abort();
}

void rb_explicit_reassctx_init(struct rb_explicit_reassctx *ctx, int ipv6)
{
  rb_tree_init(&ctx->hole_tree, rb_hole_tree_cmp, NULL);
  linked_list_head_init(&ctx->packet_list);
  ctx->first_hole.first = 0;
  ctx->first_hole.last = 65535;
  ctx->most_restricting_last = 65535;
  ctx->ipv6 = ipv6;
  rb_tree_insert(&ctx->hole_tree, &ctx->first_hole.node);
}

void rb_explicit_reassctx_free(struct allocif *loc, struct rb_explicit_reassctx *ctx)
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
rb_explicit_reassctx_reassemble(struct allocif *loc, struct rb_explicit_reassctx *ctx)
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
      memcpy(pay2 + first, payorig, 1 + (size_t)ctx->most_restricting_last - first);
    }
    else
    {
      memcpy(pay2 + first, payorig, len);
    }
  }
  return pkt;
}

#if 0
static void linktest(struct rb_explicit_reassctx *ctx)
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

static void repair_most_restricting(struct rb_explicit_reassctx *ctx)
{
  struct rb_tree_node *node;
  struct rbhole *hole;
  for (;;)
  {
    node = rb_tree_rightmost(&ctx->hole_tree);
    if (node == NULL)
    {
      return;
    }
    hole = CONTAINER_OF(node, struct rbhole, node);
    if (hole->first > ctx->most_restricting_last)
    {
      rb_tree_delete(&ctx->hole_tree, node);
    }
    else
    {
      break;
    }
  }
  if (hole->last > ctx->most_restricting_last)
  {
    hole->last = ctx->most_restricting_last;
  }
}

#undef PRINT_TREE

#ifdef PRINT_TREE
static void print_tree(struct rb_tree_node *node)
{
  struct rbhole *hole;
  if (node == NULL)
  {
    return;
  }
  print_tree(node->left);
  hole = CONTAINER_OF(node, struct rbhole, node);
  printf("%d:%d\n", hole->first, hole->last); 
  print_tree(node->right);
}
#endif

static void add_data(struct rb_explicit_reassctx *ctx,
                     uint16_t data_first, uint16_t data_last,
                     struct rbhole *new_hole,
                     int *mod,
                     int *overlap)
{
  struct rb_tree_node *node;
  struct rbhole *hole;
  const int ipv6 = ctx->ipv6;

back:
  node = rb_tree_root(&ctx->hole_tree);
  hole = CONTAINER_OF(node, struct rbhole, node);
  while (node != NULL)
  {
    if (hole->last < data_first)
    {
      node = node->right;
      hole = CONTAINER_OF(node, struct rbhole, node);
      continue;
    }
    if (hole->first > data_last)
    {
      node = node->left;
      hole = CONTAINER_OF(node, struct rbhole, node);
      continue;
    }
    break;
  }
  if (ipv6)
  {
    if (node == NULL || hole->first > data_first || hole->last < data_last)
    {
      *overlap = 1;
      return;
    }
  }
  if (node == NULL)
  {
    return;
  }
  if (hole->last > data_last && hole->first < data_first)
  {
    new_hole->first = data_last + 1;
    new_hole->last = hole->last;
    hole->last = data_first - 1;
#ifdef EXTRA_DEBUG
    if (!rb_tree_valid(&ctx->hole_tree))
    {
      printf("Invalid1\n");
      abort();
    }
#endif
    if (hole->node.right == NULL)
    {
#ifdef EXTRA_DEBUG
      printf("Easy!\n");
#endif
      hole->node.right = &new_hole->node;
      new_hole->node.is_black = 0;
      new_hole->node.parent = &hole->node;
      new_hole->node.left = NULL;
      new_hole->node.right = NULL;
      rb_tree_insert_repair(&ctx->hole_tree, &new_hole->node);
#ifdef EXTRA_DEBUG
      if (!rb_tree_valid(&ctx->hole_tree))
      {
        printf("Invalid2\n");
        abort();
      }
#endif
      *mod = 1;
      return;
    }
    node = node->right;
    while (node->left != NULL)
    {
      node = node->left;
    }
    hole = CONTAINER_OF(node, struct rbhole, node);
    hole->node.left = &new_hole->node;
    new_hole->node.is_black = 0;
    new_hole->node.parent = &hole->node;
    new_hole->node.left = NULL;
    new_hole->node.right = NULL;
    rb_tree_insert_repair(&ctx->hole_tree, &new_hole->node);
#ifdef EXTRA_DEBUG
    if (!rb_tree_valid(&ctx->hole_tree))
    {
      printf("Invalid3\n");
      abort();
    }
#endif
    //rb_tree_insert(&ctx->hole_tree, &new_hole->node);
    *mod = 1;
    return;
  }
  if (hole->last <= data_last && hole->first >= data_first)
  {
    rb_tree_delete(&ctx->hole_tree, node);
    *mod = 1;
    if (!ipv6)
    {
      goto back;
    }
  }
  if (hole->last <= data_last && hole->last + 1 > data_first)
  {
    hole->last = data_first - 1;
    *mod = 1;
    if (!ipv6)
    {
      goto back;
    }
  }
  if (hole->first >= data_first && hole->first < data_last + 1)
  {
    hole->first = data_last + 1;
    *mod = 1;
    if (!ipv6)
    {
      goto back;
    }
  }
}

void rb_explicit_reassctx_add(struct allocif *loc,
                              struct rb_explicit_reassctx *ctx, struct packet *pkt,
                              int *overlapptr)
{
  const char *ether = pkt->data;
  const char *ip = ether_const_payload(ether);
  uint16_t data_first;
  uint16_t data_last;
  int mod = 0;
  int overlap = 0;
  //linktest(ctx);
  if (pkt->sz < 34 ||
      ip_total_len(ip) <= ip_hdr_len(ip) ||
      (size_t)(ip_total_len(ip) + 14) > pkt->sz)
  {
    allocif_free(loc, pkt);
    return;
  }
  data_first = ip_frag_off(ip);
  if (ip_total_len(ip) - (ip_hdr_len(ip) + 1) + ip_frag_off(ip) > 65535)
  {
    allocif_free(loc, pkt);
    return;
  }
  data_last = ip_total_len(ip) - (ip_hdr_len(ip) + 1) + ip_frag_off(ip);
  if (!ip_more_frags(ip) && ctx->most_restricting_last > data_last)
  {
    ctx->most_restricting_last = data_last;
    repair_most_restricting(ctx);
    mod = 1;
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
#ifdef PRINT_TREE
  printf("-----\n");
  printf("first %d last %d\n", data_first, data_last); // FIXME comment out
#endif
  add_data(ctx, data_first, data_last, &pkt->u.rbhole, &mod, &overlap);
#ifdef PRINT_TREE
  print_tree(ctx->hole_tree.root);
  printf("-----\n");
#endif
  if (overlapptr)
  {
    *overlapptr = overlap;
  }
  if (mod && !overlap)
  {
    linked_list_add_tail(&pkt->node, &ctx->packet_list);
  }
  else
  {
    allocif_free(loc, pkt);
  }
}
