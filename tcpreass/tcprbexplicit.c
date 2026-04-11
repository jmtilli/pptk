#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "llalloc.h"
#include "iphdr.h"
#include "packet.h"
#include "ipcksum.h"
#include "containerof.h"
#include "tcprbexplicit.h"

static inline int seq_valid(uint32_t x, uint32_t y)
{
  int32_t result = (int32_t)(x-y);
  if (result > 512*1024*1024 || result < -512*1024*1024)
  {
    return 0;
  }
  if (result > 0)
  {
    return 1;
  }
  if (result < 0)
  {
    return 1;
  }
  return 1;
}

static inline int seq_cmp(uint32_t x, uint32_t y)
{
  int32_t result = (int32_t)(x-y);
  if (result > 512*1024*1024 || result < -512*1024*1024)
  {
    abort();
  }
  if (result > 0)
  {
    return 1;
  }
  if (result < 0)
  {
    return -1;
  }
  return result;
}

static int
rb_packet_tree_cmp(struct rb_tree_node *a, struct rb_tree_node *b, void *ud)
{
  struct rbtcppositive *ha = CONTAINER_OF(a, struct rbtcppositive, node);
  struct rbtcppositive *hb = CONTAINER_OF(b, struct rbtcppositive, node);
  if (seq_cmp(ha->last, hb->first) < 0)
  {
    return -1;
  }
  if (seq_cmp(hb->last, ha->first) < 0)
  {
    return 1;
  }
  abort();
}

void tcp_rb_explicit_reassctx_init(struct tcp_rb_explicit_reassctx *ctx,
                                   uint32_t isn)
{
  rb_tree_init(&ctx->packet_tree, rb_packet_tree_cmp, NULL);
  ctx->last_fed_seq_plus_1 = isn + 1;
}

void tcp_rb_explicit_reassctx_free(struct allocif *loc, struct tcp_rb_explicit_reassctx *ctx)
{
  while (rb_tree_root(&ctx->packet_tree) != NULL)
  {
    struct rb_tree_node *root = rb_tree_root(&ctx->packet_tree);
    struct rbtcppositive *positive;
    rb_tree_delete(&ctx->packet_tree, root);
    positive = CONTAINER_OF(root, struct rbtcppositive, node);
    allocif_free(loc, CONTAINER_OF(positive, struct packet, u.rbtcppositive));
  }
}

static void repair_after_passthrough(struct allocif *loc,
                                     struct tcp_rb_explicit_reassctx *ctx)
{
  struct rb_tree_node *node;
  struct rbtcppositive *positive;
  for (;;)
  {
    node = rb_tree_leftmost(&ctx->packet_tree);
    if (node == NULL)
    {
      return;
    }
    positive = CONTAINER_OF(node, struct rbtcppositive, node);
    if (seq_cmp(positive->last, ctx->last_fed_seq_plus_1) < 0)
    {
      rb_tree_delete(&ctx->packet_tree, node);
      allocif_free(loc, CONTAINER_OF(positive, struct packet, u.rbtcppositive));
    }
    else
    {
      break;
    }
  }
  if (seq_cmp(positive->first, ctx->last_fed_seq_plus_1) < 0)
  {
    positive->first = ctx->last_fed_seq_plus_1;
  }
}

#undef PRINT_TREE

#ifdef PRINT_TREE
static void print_tree(struct rb_tree_node *node)
{
  struct rbtcppositive *positive;
  if (node == NULL)
  {
    return;
  }
  print_tree(node->left);
  positive = CONTAINER_OF(node, struct rbtcppositive, node);
  printf("%u:%u\n", positive->first, positive->last); 
  print_tree(node->right);
}
#endif

static int add_data(struct allocif *loc,
                    struct tcp_rb_explicit_reassctx *ctx,
                    uint32_t data_first, uint32_t data_last,
                    int *mod)
{
  struct rb_tree_node *node;
  struct rbtcppositive *positive;

back:
  node = rb_tree_root(&ctx->packet_tree);
  positive = CONTAINER_OF(node, struct rbtcppositive, node);
  while (node != NULL)
  {
    if (seq_cmp(positive->last, data_first) < 0)
    {
      node = node->right;
      positive = CONTAINER_OF(node, struct rbtcppositive, node);
      continue;
    }
    if (seq_cmp(positive->first, data_last) > 0)
    {
      node = node->left;
      positive = CONTAINER_OF(node, struct rbtcppositive, node);
      continue;
    }
    break;
  }
  if (node == NULL)
  {
    return 0;
  }
  if (seq_cmp(positive->last, data_last) <= 0 && seq_cmp(positive->first, data_first) >= 0)
  {
    rb_tree_delete(&ctx->packet_tree, node);
    allocif_free(loc, CONTAINER_OF(positive, struct packet, u.rbtcppositive));
    if (mod)
    {
      *mod = 1;
    }
    goto back;
  }
  if (seq_cmp(positive->last, data_last) <= 0 && seq_cmp(positive->last + 1, data_first) > 0)
  {
    positive->last = data_first - 1;
    if (mod)
    {
      *mod = 1;
    }
    goto back;
  }
  if (seq_cmp(positive->first, data_first) >= 0 && seq_cmp(positive->first, data_last + 1) < 0)
  {
    positive->first = data_last + 1;
    if (mod)
    {
      *mod = 1;
    }
    goto back;
  }
  if (seq_cmp(positive->last, data_last) >= 0 && seq_cmp(positive->first, data_first) <= 0)
  {
    return -EEXIST;
  }
  return 0;
}

struct packet *
tcp_rb_explicit_reassctx_fetch(struct tcp_rb_explicit_reassctx *ctx)
{
  struct rb_tree_node *node;
  struct rbtcppositive *positive;

  node = rb_tree_leftmost(&ctx->packet_tree);
  positive = CONTAINER_OF(node, struct rbtcppositive, node);
  if (positive == NULL)
  {
    return NULL;
  }
  if (positive->first == ctx->last_fed_seq_plus_1)
  {
    rb_tree_delete(&ctx->packet_tree, node);
    ctx->last_fed_seq_plus_1 = positive->last+1;
    return CONTAINER_OF(positive, struct packet, u.rbtcppositive);
  }
  return NULL;
}

struct packet *
tcp_rb_explicit_reassctx_add(struct allocif *loc,
                             struct tcp_rb_explicit_reassctx *ctx,
                             struct packet *pkt)
{
  const char *ether = pkt->data;
  const char *ip = ether_const_payload(ether);
  const char *tcp;
  uint32_t data_first;
  uint32_t data_last;
  if (ether_type(ether) != 0x0800)
  {
    allocif_free(loc, pkt);
    printf("1\n");
    return NULL;
  }
  //linktest(ctx);
  if (pkt->sz < 34 ||
      ip_total_len(ip) <= ip_hdr_len(ip) ||
      (size_t)(ip_total_len(ip) + 14) > pkt->sz ||
      ip_proto(ip) != 6)
  {
    allocif_free(loc, pkt);
    printf("2\n");
    return NULL;
  }
  tcp = ip_const_payload(ip);
  if (ip_total_len(ip) - ip_hdr_len(ip) < 20 ||
      ip_total_len(ip) - ip_hdr_len(ip) <= tcp_data_offset(tcp))
  {
    allocif_free(loc, pkt);
    printf("3\n");
    return NULL;
  }
  data_first = tcp_seq_number(tcp);
  data_last = data_first + ip_total_len(ip) - ip_hdr_len(ip) - tcp_data_offset(tcp);
  if (seq_cmp(data_last, ctx->last_fed_seq_plus_1) < 0)
  {
    allocif_free(loc, pkt);
    printf("4\n");
    return NULL;
  }
  if (!seq_valid(data_first, ctx->last_fed_seq_plus_1) ||
      !seq_valid(data_last, ctx->last_fed_seq_plus_1))
  {
    allocif_free(loc, pkt);
    printf("5\n");
    return NULL;
  }
  if (seq_cmp(data_first, ctx->last_fed_seq_plus_1) <= 0)
  {
    uint32_t old_last_fed_seq_plus_1 = ctx->last_fed_seq_plus_1;
    ctx->last_fed_seq_plus_1 = data_last+1;
    repair_after_passthrough(loc, ctx);
    pkt->u.rbtcppositive.first = old_last_fed_seq_plus_1;
    pkt->u.rbtcppositive.last = data_last;
    return pkt;
  }
  //printf("%u:%u / %u\n", data_first, data_last, ctx->last_fed_seq_plus_1);
#ifdef PRINT_TREE
  printf("-----\n");
  printf("first %d last %d\n", data_first, data_last); // FIXME comment out
  printf("-----\n");
  print_tree(ctx->packet_tree.root);
  printf("-----\n");
#endif
  if (add_data(loc, ctx, data_first, data_last, NULL) != -EEXIST)
  {
    pkt->u.rbtcppositive.first = data_first;
    pkt->u.rbtcppositive.last = data_last;
    rb_tree_insert(&ctx->packet_tree, &pkt->u.rbtcppositive.node);
  }
  else
  {
    allocif_free(loc, pkt);
  }
#ifdef PRINT_TREE
  printf("-----\n");
  print_tree(ctx->packet_tree.root);
  printf("-----\n");
#endif
  return NULL;
}
