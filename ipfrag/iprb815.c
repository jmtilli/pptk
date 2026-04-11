#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "llalloc.h"
#include "hdr.h"
#include "iphdr.h"
#include "packet.h"
#include "ipcksum.h"
#include "ipfrag.h"
#include "containerof.h"
#include "iprb815.h"

#undef PRINT_TREE

#ifdef PRINT_TREE
static void print_tree_i(struct rb815ctx *ctx, uint16_t loc, int indent)
{
  int i;
  struct rb815hole hole;
  if (loc == RB815_HOLE_NULL)
  {
    return;
  }
  memcpy(&hole, &ctx->pkt[loc], sizeof(hole));
  if (hole.left_valid)
  {
    print_tree_i(ctx, hole.left_div_8*8, indent+1);
  }
  for (i = 0; i < indent; i++)
  {
    printf(" ");
  }
  printf("%d:%d (%d)\n", loc, loc + hole.len - 1, hole.parent_valid ? hole.parent_div_8*8 : RB815_HOLE_NULL);
  if (hole.right_valid)
  {
    print_tree_i(ctx, hole.right_div_8*8, indent+1);
  }
}

static void print_tree(struct rb815ctx *ctx, uint16_t loc)
{
  return print_tree_i(ctx, loc, 0);
}
#endif

void rb815ctx_init(struct rb815ctx *ctx)
{
  memset(ctx->pkt, 0, sizeof(ctx->pkt));
  memset(ctx->pkt_header, 0, sizeof(ctx->pkt_header));
  rb815ctx_init_fast(ctx);
}

void rb815ctx_init_fast(struct rb815ctx *ctx)
{
  struct rb815hole hole = RB815HOLE_EMPTY;
  hole.len = 65535;
  hole.left_valid = 0;
  hole.right_valid = 0;
  hole.parent_valid = 0;
  hole.is_black = 1;
  ctx->root_hole = 0;
  ctx->most_restricting_last = 65535;
  ctx->hdr_len = 0;
  memcpy(&ctx->pkt[0], &hole, sizeof(hole));
}

static inline uint16_t get_sibling_loc(struct rb815ctx *ctx, uint16_t loc)
{
  struct rb815hole hole = RB815HOLE_EMPTY;
  uint16_t parent_loc;
  memcpy(&hole, &ctx->pkt[loc], sizeof(hole));
  if (!hole.parent_valid)
  {
    return RB815_HOLE_NULL;
  }
  parent_loc = hole.parent_div_8 * 8;
  memcpy(&hole, &ctx->pkt[parent_loc], sizeof(hole));
  if (hole.left_valid && loc == hole.left_div_8 * 8)
  {
    return hole.right_valid ? (hole.right_div_8 * 8) : RB815_HOLE_NULL;
  }
  if (hole.right_valid && loc == hole.right_div_8 * 8)
  {
    return hole.left_valid ? (hole.left_div_8 * 8) : RB815_HOLE_NULL;
  }
  abort();
}

static inline uint16_t
get_sibling_loc_parent(struct rb815ctx *ctx, uint16_t loc, uint16_t parent_loc)
{
  struct rb815hole hole = RB815HOLE_EMPTY;
  if (parent_loc == RB815_HOLE_NULL)
  {
    return RB815_HOLE_NULL;
  }
  memcpy(&hole, &ctx->pkt[parent_loc], sizeof(hole));
  if (hole.left_valid && loc == hole.left_div_8 * 8)
  {
    return hole.right_valid ? (hole.right_div_8 * 8) : RB815_HOLE_NULL;
  }
  if (hole.right_valid && loc == hole.right_div_8 * 8)
  {
    return hole.left_valid ? (hole.left_div_8 * 8) : RB815_HOLE_NULL;
  }
  printf("ErrorErrorError2 loc %d parent %d\n", loc, parent_loc);
  printf("parent left %d %d\n", hole.left_valid, hole.left_div_8*8);
  printf("parent right %d %d\n", hole.right_valid, hole.right_div_8*8);
  abort();
}

static int rb815_subtree_ptrs_valid(struct rb815ctx *ctx, uint16_t loc)
{
  struct rb815hole hole = RB815HOLE_EMPTY, left = RB815HOLE_EMPTY, right = RB815HOLE_EMPTY;
  int resultl = 0, resultr = 0;
  memcpy(&hole, &ctx->pkt[loc], sizeof(hole));
  if (hole.left_valid)
  {
    memcpy(&left, &ctx->pkt[hole.left_div_8*8], sizeof(left));
    if (!left.parent_valid || left.parent_div_8*8 != loc)
    {
      printf("Left parent validity\n");
      return 0;
    }
    resultl = rb815_subtree_ptrs_valid(ctx, hole.left_div_8*8);
    if (resultl == 0)
    {
      printf("Left subtree validity\n");
      return 0;
    }
  }
  if (hole.right_valid)
  {
    memcpy(&right, &ctx->pkt[hole.right_div_8*8], sizeof(right));
    if (!right.parent_valid || right.parent_div_8*8 != loc)
    {
      printf("Right parent validity\n");
      return 0;
    }
    resultr = rb815_subtree_ptrs_valid(ctx, hole.right_div_8*8);
    if (resultr == 0)
    {
      printf("Right subtree validity\n");
      return 0;
    }
  }
  return 1;
}

static __attribute__((unused)) int rb815_tree_ptrs_valid(struct rb815ctx *ctx)
{
  struct rb815hole hole = RB815HOLE_EMPTY;
  if (ctx->root_hole == RB815_HOLE_NULL)
  { 
    return 1;
  }
  memcpy(&hole, &ctx->pkt[ctx->root_hole], sizeof(hole));
  if (hole.parent_valid)
  { 
    printf("Parent validity problem 1\n");
    return 0;
  }
  if (rb815_subtree_ptrs_valid(ctx, ctx->root_hole) == 0)
  { 
    printf("Subtree validity problem 1\n");
    return 0;
  }
  return 1;
}

#if 0
static int rb815_tree_valid(struct rb815ctx *ctx)
{
  if (tree->root == NULL)
  { 
    return 1;
  }
  if (tree->root->parent != NULL)
  { 
    return 0;
  }
  if (rb_subtree_height(tree->root) < 0)
  { 
    return 0;
  }
  return 1;
}
#endif

static inline void
exchange(struct rb815ctx *ctx, uint16_t n1_loc, uint16_t n2_loc)
{
  struct rb815hole n1;
  struct rb815hole n2;
  uint16_t n1_parent_loc;
  struct rb815hole n1_parent;
  uint16_t n1_left_loc;
  struct rb815hole n1_left;
  uint16_t n1_right_loc;
  struct rb815hole n1_right;
  uint16_t n2_parent_loc;
  struct rb815hole n2_parent;
  uint16_t n2_left_loc;
  struct rb815hole n2_left;
  uint16_t n2_right_loc;
  struct rb815hole n2_right;
  int n1_is_black;
  int n2_is_black;
  memcpy(&n1, &ctx->pkt[n1_loc], sizeof(n1));
  memcpy(&n2, &ctx->pkt[n2_loc], sizeof(n2));
  n1_is_black = n1.is_black;
  n2_is_black = n2.is_black;
  n1_left_loc = n1.left_valid ? (n1.left_div_8*8) : RB815_HOLE_NULL;
  n1_right_loc = n1.right_valid ? (n1.right_div_8*8) : RB815_HOLE_NULL;
  n1_parent_loc = n1.parent_valid ? (n1.parent_div_8*8) : RB815_HOLE_NULL;
  n2_left_loc = n2.left_valid ? (n2.left_div_8*8) : RB815_HOLE_NULL;
  n2_right_loc = n2.right_valid ? (n2.right_div_8*8) : RB815_HOLE_NULL;
  n2_parent_loc = n2.parent_valid ? (n2.parent_div_8*8) : RB815_HOLE_NULL;
  if (n1_left_loc != RB815_HOLE_NULL)
  {
    memcpy(&n1_left, &ctx->pkt[n1_left_loc], sizeof(n1_left));
  }
  if (n1_right_loc != RB815_HOLE_NULL)
  {
    memcpy(&n1_right, &ctx->pkt[n1_right_loc], sizeof(n1_right));
  }
  if (n1_parent_loc != RB815_HOLE_NULL)
  {
    memcpy(&n1_parent, &ctx->pkt[n1_parent_loc], sizeof(n1_parent));
  }
  if (n2_left_loc != RB815_HOLE_NULL)
  {
    memcpy(&n2_left, &ctx->pkt[n2_left_loc], sizeof(n2_left));
  }
  if (n2_right_loc != RB815_HOLE_NULL)
  {
    memcpy(&n2_right, &ctx->pkt[n2_right_loc], sizeof(n2_right));
  }
  if (n2_parent_loc != RB815_HOLE_NULL)
  {
    memcpy(&n2_parent, &ctx->pkt[n2_parent_loc], sizeof(n2_parent));
  }
  if (n2.parent_valid && n2.parent_div_8*8 == n1_loc &&
      n1.left_div_8*8 == n2_loc)
  {
#ifdef PRINT_TREE
    printf("Exchange-1 %d<->%d\n", n1_loc, n2_loc);
    printf("n1_loc=%d\n", n1_loc);
    printf("n1_left_loc=%d\n", n1_left_loc);
    printf("n1_right_loc=%d\n", n1_right_loc);
    printf("n1_parent_loc=%d\n", n1_parent_loc);
    printf("n2_loc=%d\n", n2_loc);
    printf("n2_left_loc=%d\n", n2_left_loc);
    printf("n2_right_loc=%d\n", n2_right_loc);
    printf("n2_parent_loc=%d\n", n2_parent_loc);
#endif
    n1.left_valid = n2.left_valid;
    n1.left_div_8 = n2.left_div_8;
    n1.right_valid = n2.right_valid;
    n1.right_div_8 = n2.right_div_8;
    n1.parent_valid = 1;
    n1.parent_div_8 = n2_loc/8;
    if (n2_left_loc != RB815_HOLE_NULL)
    {
      n2_left.parent_valid = 1;
      n2_left.parent_div_8 = n1_loc/8;
    }
    if (n2_right_loc != RB815_HOLE_NULL)
    {
      n2_right.parent_valid = 1;
      n2_right.parent_div_8 = n1_loc/8;
    }
    n2.left_valid = 1;
    n2.left_div_8 = n1_loc/8;
    n2.right_valid = (n1_right_loc != RB815_HOLE_NULL);
    n2.right_div_8 = n1_right_loc/8;
    n2.parent_valid = (n1_parent_loc != RB815_HOLE_NULL);
    n2.parent_div_8 = n1_parent_loc/8;
    if (n1_right_loc != RB815_HOLE_NULL)
    {
      n1_right.parent_valid = 1;
      n1_right.parent_div_8 = n2_loc/8;
    }
    if (!n2.parent_valid)
    {
#ifdef PRINT_TREE
      printf("installing new root hole\n");
#endif
      ctx->root_hole = n2_loc;
    }
    else if (n1_parent.left_valid && n1_parent.left_div_8*8 == n1_loc)
    {
      n1_parent.left_valid = 1;
      n1_parent.left_div_8 = n2_loc/8;
    }
    else if (n1_parent.right_valid && n1_parent.right_div_8*8 == n1_loc)
    {
      n1_parent.right_valid = 1;
      n1_parent.right_div_8 = n2_loc/8;
    }
    else
    {
      printf("shouldn't reach\n"),
      abort();
    }
    n1.is_black = n2_is_black;
    n2.is_black = n1_is_black;
    memcpy(&ctx->pkt[n1_loc], &n1, sizeof(n1));
    memcpy(&ctx->pkt[n2_loc], &n2, sizeof(n2));
#if 0 // Unmodified duplicate
    if (n1_left_loc != RB815_HOLE_NULL)
    {
      memcpy(&ctx->pkt[n1_left_loc], &n1_left, sizeof(n1_left));
    }
#endif
    if (n1_right_loc != RB815_HOLE_NULL)
    {
      memcpy(&ctx->pkt[n1_right_loc], &n1_right, sizeof(n1_right));
    }
    if (n1_parent_loc != RB815_HOLE_NULL)
    {
      memcpy(&ctx->pkt[n1_parent_loc], &n1_parent, sizeof(n1_parent));
    }
    if (n2_left_loc != RB815_HOLE_NULL)
    {
      memcpy(&ctx->pkt[n2_left_loc], &n2_left, sizeof(n2_left));
    }
    if (n2_right_loc != RB815_HOLE_NULL)
    {
      memcpy(&ctx->pkt[n2_right_loc], &n2_right, sizeof(n2_right));
    }
#if 0 // Unmodified duplicate
    if (n2_parent_loc != RB815_HOLE_NULL)
    {
      memcpy(&ctx->pkt[n2_parent_loc], &n2_parent, sizeof(n2_parent));
    }
#endif
    return;
  }
  if (n2.parent_valid && n2.parent_div_8*8 == n1_loc &&
      n1.right_div_8*8 == n2_loc)
  {
#ifdef PRINT_TREE
    printf("Exchange-2 %d<->%d\n", n1_loc, n2_loc);
    printf("n1_loc=%d\n", n1_loc);
    printf("n1_left_loc=%d\n", n1_left_loc);
    printf("n1_right_loc=%d\n", n1_right_loc);
    printf("n1_parent_loc=%d\n", n1_parent_loc);
    printf("n2_loc=%d\n", n2_loc);
    printf("n2_left_loc=%d\n", n2_left_loc);
    printf("n2_right_loc=%d\n", n2_right_loc);
    printf("n2_parent_loc=%d\n", n2_parent_loc);
#endif
    n1.left_valid = n2.left_valid;
    n1.left_div_8 = n2.left_div_8;
    n1.right_valid = n2.right_valid;
    n1.right_div_8 = n2.right_div_8;
    n1.parent_valid = 1;
    n1.parent_div_8 = n2_loc/8;
    if (n2_left_loc != RB815_HOLE_NULL)
    {
      n2_left.parent_valid = 1;
      n2_left.parent_div_8 = n1_loc/8;
    }
    if (n2_right_loc != RB815_HOLE_NULL)
    {
      n2_right.parent_valid = 1;
      n2_right.parent_div_8 = n1_loc/8;
    }
    n2.left_valid = (n1_left_loc != RB815_HOLE_NULL);
    n2.left_div_8 = n1_left_loc / 8;
    n2.right_valid = 1;
    n2.right_div_8 = n1_loc / 8;
    n2.parent_valid = (n1_parent_loc != RB815_HOLE_NULL);
    n2.parent_div_8 = n1_parent_loc/8;
    if (n1_left_loc != RB815_HOLE_NULL)
    {
      n1_left.parent_valid = 1;
      n1_left.parent_div_8 = n2_loc/8;
    }
    if (!n2.parent_valid)
    {
      ctx->root_hole = n2_loc;
    }
    else if (n1_parent.left_valid && n1_parent.left_div_8*8 == n1_loc)
    {
      n1_parent.left_valid = 1;
      n1_parent.left_div_8 = n2_loc/8;
    }
    else if (n1_parent.right_valid && n1_parent.right_div_8*8 == n1_loc)
    {
      n1_parent.right_valid = 1;
      n1_parent.right_div_8 = n2_loc/8;
    }
    else
    {
      printf("shouldn't reach\n"),
      abort();
    }
    n1.is_black = n2_is_black;
    n2.is_black = n1_is_black;
    memcpy(&ctx->pkt[n1_loc], &n1, sizeof(n1));
    memcpy(&ctx->pkt[n2_loc], &n2, sizeof(n2));
    if (n1_left_loc != RB815_HOLE_NULL)
    {
      memcpy(&ctx->pkt[n1_left_loc], &n1_left, sizeof(n1_left));
    }
#if 0 // Unmodified duplicate
    if (n1_right_loc != RB815_HOLE_NULL)
    {
      memcpy(&ctx->pkt[n1_right_loc], &n1_right, sizeof(n1_right));
    }
#endif
    if (n1_parent_loc != RB815_HOLE_NULL)
    {
      memcpy(&ctx->pkt[n1_parent_loc], &n1_parent, sizeof(n1_parent));
    }
    if (n2_left_loc != RB815_HOLE_NULL)
    {
      memcpy(&ctx->pkt[n2_left_loc], &n2_left, sizeof(n2_left));
    }
    if (n2_right_loc != RB815_HOLE_NULL)
    {
      memcpy(&ctx->pkt[n2_right_loc], &n2_right, sizeof(n2_right));
    }
#if 0 // Unmodified duplicate
    if (n2_parent_loc != RB815_HOLE_NULL)
    {
      memcpy(&ctx->pkt[n2_parent_loc], &n2_parent, sizeof(n2_parent));
    }
#endif
    return;
  }
  if (n1_parent_loc == n2_loc)
  {
    exchange(ctx, n2_loc, n1_loc);
    return;
  }
#ifdef PRINT_TREE
  printf("Exchange-3 %d<->%d\n", n1_loc, n2_loc);
  printf("n1_loc=%d\n", n1_loc);
  printf("n1_left_loc=%d\n", n1_left_loc);
  printf("n1_right_loc=%d\n", n1_right_loc);
  printf("n1_parent_loc=%d\n", n1_parent_loc);
  printf("n2_loc=%d\n", n2_loc);
  printf("n2_left_loc=%d\n", n2_left_loc);
  printf("n2_right_loc=%d\n", n2_right_loc);
  printf("n2_parent_loc=%d\n", n2_parent_loc);
#endif
  if (n1_parent_loc != RB815_HOLE_NULL)
  {
    if (n1_parent.left_valid && n1_parent.left_div_8*8 == n1_loc)
    {
      n1_parent.left_valid = 1;
      n1_parent.left_div_8 = n2_loc/8;
    }
    else if (n1_parent.right_valid && n1_parent.right_div_8*8 == n1_loc)
    {
      n1_parent.right_valid = 1;
      n1_parent.right_div_8 = n2_loc/8;
    }
    else
    {
      printf("1\n");
      abort();
    }
    memcpy(&ctx->pkt[n1_parent_loc], &n1_parent, sizeof(n1_parent));
  }
  if (n2_parent_loc != RB815_HOLE_NULL)
  {
    if (n2_parent.left_valid && n2_parent.left_div_8*8 == n2_loc)
    {
      n2_parent.left_valid = 1;
      n2_parent.left_div_8 = n1_loc/8;
    }
    else if (n2_parent.right_valid && n2_parent.right_div_8*8 == n2_loc)
    {
      n2_parent.right_valid = 1;
      n2_parent.right_div_8 = n1_loc/8;
    }
    else
    {
      printf("2\n");
      abort();
    }
    memcpy(&ctx->pkt[n2_parent_loc], &n2_parent, sizeof(n2_parent));
  }

  // Reload
  if (n1_left_loc != RB815_HOLE_NULL)
  {
    memcpy(&n1_left, &ctx->pkt[n1_left_loc], sizeof(n1_left));
  }
  if (n1_right_loc != RB815_HOLE_NULL)
  {
    memcpy(&n1_right, &ctx->pkt[n1_right_loc], sizeof(n1_right));
  }
  if (n1_parent_loc != RB815_HOLE_NULL)
  {
    memcpy(&n1_parent, &ctx->pkt[n1_parent_loc], sizeof(n1_parent));
  }
  if (n2_left_loc != RB815_HOLE_NULL)
  {
    memcpy(&n2_left, &ctx->pkt[n2_left_loc], sizeof(n2_left));
  }
  if (n2_right_loc != RB815_HOLE_NULL)
  {
    memcpy(&n2_right, &ctx->pkt[n2_right_loc], sizeof(n2_right));
  }
  if (n2_parent_loc != RB815_HOLE_NULL)
  {
    memcpy(&n2_parent, &ctx->pkt[n2_parent_loc], sizeof(n2_parent));
  }


  n2.parent_valid = (n1_parent_loc != RB815_HOLE_NULL);
  n2.parent_div_8 = n1_parent_loc/8;
  n2.left_valid = (n1_left_loc != RB815_HOLE_NULL);
  n2.left_div_8 = n1_left_loc/8;
  n2.right_valid = (n1_right_loc != RB815_HOLE_NULL);
  n2.right_div_8 = n1_right_loc/8;
  n1.parent_valid = (n2_parent_loc != RB815_HOLE_NULL);
  n1.parent_div_8 = n2_parent_loc/8;
  n1.left_valid = (n2_left_loc != RB815_HOLE_NULL);
  n1.left_div_8 = n2_left_loc/8;
  n1.right_valid = (n2_right_loc != RB815_HOLE_NULL);
  n1.right_div_8 = n2_right_loc/8;
  if (n2_left_loc != RB815_HOLE_NULL)
  {
    n2_left.parent_valid = 1;
    n2_left.parent_div_8 = n1_loc/8;
  }
  if (n2_right_loc != RB815_HOLE_NULL)
  {
    n2_right.parent_valid = 1;
    n2_right.parent_div_8 = n1_loc/8;
  }
  if (n1_left_loc != RB815_HOLE_NULL)
  {
    n1_left.parent_valid = 1;
    n1_left.parent_div_8 = n2_loc/8;
  }
  if (n1_right_loc != RB815_HOLE_NULL)
  {
    n1_right.parent_valid = 1;
    n1_right.parent_div_8 = n2_loc/8;
  }
  if (n2_parent_loc == RB815_HOLE_NULL)
  {
    if (n1_parent_loc == RB815_HOLE_NULL)
    {
      abort();
    }
    ctx->root_hole = n1_loc;
  }
  if (n1_parent_loc == RB815_HOLE_NULL)
  {
    ctx->root_hole = n2_loc;
  }
  n1.is_black = n2_is_black;
  n2.is_black = n1_is_black;
  memcpy(&ctx->pkt[n1_loc], &n1, sizeof(n1));
  memcpy(&ctx->pkt[n2_loc], &n2, sizeof(n2));
  if (n1_left_loc != RB815_HOLE_NULL)
  {
    memcpy(&ctx->pkt[n1_left_loc], &n1_left, sizeof(n1_left));
  }
  if (n1_right_loc != RB815_HOLE_NULL)
  {
    memcpy(&ctx->pkt[n1_right_loc], &n1_right, sizeof(n1_right));
  }
#if 0 // Already stored
  if (n1_parent_loc != RB815_HOLE_NULL)
  {
    memcpy(&ctx->pkt[n1_parent_loc], &n1_parent, sizeof(n1_parent));
  }
#endif
  if (n2_left_loc != RB815_HOLE_NULL)
  {
    memcpy(&ctx->pkt[n2_left_loc], &n2_left, sizeof(n2_left));
  }
  if (n2_right_loc != RB815_HOLE_NULL)
  {
    memcpy(&ctx->pkt[n2_right_loc], &n2_right, sizeof(n2_right));
  }
#if 0 // Already stored
  if (n2_parent_loc != RB815_HOLE_NULL)
  {
    memcpy(&ctx->pkt[n2_parent_loc], &n2_parent, sizeof(n2_parent));
  }
#endif
}

static inline uint16_t get_uncle_loc(struct rb815ctx *ctx, uint16_t loc)
{
  struct rb815hole hole = RB815HOLE_EMPTY;
  memcpy(&hole, &ctx->pkt[loc], sizeof(hole));
  if (!hole.parent_valid)
  {
    return RB815_HOLE_NULL;
  }
  return get_sibling_loc(ctx, hole.parent_div_8 * 8);
}

static inline void rotate_left(struct rb815ctx *ctx, uint16_t loc)
{
  struct rb815hole hole = RB815HOLE_EMPTY;
  uint16_t parent_loc;
  struct rb815hole parent = RB815HOLE_EMPTY;
  uint16_t q_loc;
  struct rb815hole q = RB815HOLE_EMPTY;
  uint16_t a_loc;
  struct rb815hole a = RB815HOLE_EMPTY;
  uint16_t b_loc;
  struct rb815hole b = RB815HOLE_EMPTY;
  uint16_t c_loc;
  struct rb815hole c = RB815HOLE_EMPTY;
  memcpy(&hole, &ctx->pkt[loc], sizeof(hole));
  parent_loc = hole.parent_valid ? (hole.parent_div_8 * 8) : RB815_HOLE_NULL;
  if (parent_loc != RB815_HOLE_NULL)
  {
    memcpy(&parent, &ctx->pkt[parent_loc], sizeof(parent));
  }
  if (!hole.right_valid)
  {
    abort();
  }
  q_loc = hole.right_div_8*8;
  memcpy(&q, &ctx->pkt[q_loc], sizeof(q));
  a_loc = hole.left_valid ? (hole.left_div_8 * 8) : RB815_HOLE_NULL;
  b_loc = q.left_valid ? (q.left_div_8 * 8) : RB815_HOLE_NULL;
  c_loc = q.right_valid ? (q.right_div_8 * 8) : RB815_HOLE_NULL;
  if (a_loc != RB815_HOLE_NULL)
  {
    memcpy(&a, &ctx->pkt[a_loc], sizeof(a));
    hole.left_valid = 1;
    hole.left_div_8 = a_loc/8;
    a.parent_valid = 1;
    a.parent_div_8 = loc/8;
  }
  else
  {
    hole.left_valid = 0;
  }
  if (b_loc != RB815_HOLE_NULL)
  {
    memcpy(&b, &ctx->pkt[b_loc], sizeof(b));
    hole.right_valid = 1;
    hole.right_div_8 = b_loc/8;
    b.parent_valid = 1;
    b.parent_div_8 = loc/8;
  }
  else
  {
    hole.right_valid = 0;
  }
  q.left_valid = 1;
  q.left_div_8 = loc/8;
  hole.parent_valid = 1;
  hole.parent_div_8 = q_loc/8;
  if (c_loc != RB815_HOLE_NULL)
  {
    memcpy(&c, &ctx->pkt[c_loc], sizeof(c));
    q.right_valid = 1;
    q.right_div_8 = c_loc/8;
    c.parent_valid = 1;
    c.parent_div_8 = q_loc/8;
  }
  else
  {
    q.right_valid = 0;
  }
  if (parent_loc == RB815_HOLE_NULL)
  {
    ctx->root_hole = q_loc;
    q.parent_valid = 0;
  }
  else if (parent.left_valid && loc == parent.left_div_8 * 8)
  {
    parent.left_valid = 1;
    parent.left_div_8 = q_loc/8;
    q.parent_valid = 1;
    q.parent_div_8 = parent_loc/8;
  }
  else if (parent.right_valid && loc == parent.right_div_8 * 8)
  {
    parent.right_valid = 1;
    parent.right_div_8 = q_loc/8;
    q.parent_valid = 1;
    q.parent_div_8 = parent_loc/8;
  }
  else
  {
    abort();
  }
  if (a_loc != RB815_HOLE_NULL)
  {
    memcpy(&ctx->pkt[a_loc], &a, sizeof(a));
  }
  if (b_loc != RB815_HOLE_NULL)
  {
    memcpy(&ctx->pkt[b_loc], &b, sizeof(b));
  }
  if (c_loc != RB815_HOLE_NULL)
  {
    memcpy(&ctx->pkt[c_loc], &c, sizeof(c));
  }
  memcpy(&ctx->pkt[loc], &hole, sizeof(hole));
  memcpy(&ctx->pkt[q_loc], &q, sizeof(q));
  if (parent_loc != RB815_HOLE_NULL)
  {
    memcpy(&ctx->pkt[parent_loc], &parent, sizeof(parent));
  }
}

static inline void rotate_right(struct rb815ctx *ctx, uint16_t loc)
{
  struct rb815hole hole = RB815HOLE_EMPTY;
  uint16_t parent_loc;
  struct rb815hole parent = RB815HOLE_EMPTY;
  uint16_t p_loc;
  struct rb815hole p = RB815HOLE_EMPTY;
  uint16_t a_loc;
  struct rb815hole a = RB815HOLE_EMPTY;
  uint16_t b_loc;
  struct rb815hole b = RB815HOLE_EMPTY;
  uint16_t c_loc;
  struct rb815hole c = RB815HOLE_EMPTY;
  memcpy(&hole, &ctx->pkt[loc], sizeof(hole));
  parent_loc = hole.parent_valid ? (hole.parent_div_8 * 8) : RB815_HOLE_NULL;
  if (parent_loc != RB815_HOLE_NULL)
  {
    memcpy(&parent, &ctx->pkt[parent_loc], sizeof(parent));
  }
  if (!hole.left_valid)
  {
    abort();
  }
  p_loc = hole.left_div_8*8;
  memcpy(&p, &ctx->pkt[p_loc], sizeof(p));
  a_loc = p.left_valid ? (p.left_div_8 * 8) : RB815_HOLE_NULL;
  b_loc = p.right_valid ? (p.right_div_8 * 8) : RB815_HOLE_NULL;
  c_loc = hole.right_valid ? (hole.right_div_8 * 8) : RB815_HOLE_NULL;
#if PRINT_TREE
  printf("loc %d parent %d p %d a %d b %d c %d\n", loc, parent_loc, p_loc, a_loc, b_loc, c_loc);
  print_tree(ctx, ctx->root_hole);
#endif
  if (a_loc != RB815_HOLE_NULL)
  {
    memcpy(&a, &ctx->pkt[a_loc], sizeof(a));
    p.left_valid = 1;
    p.left_div_8 = a_loc/8;
    a.parent_valid = 1;
    a.parent_div_8 = p_loc/8;
  }
  else
  {
    p.left_valid = 0;
  }
  if (b_loc != RB815_HOLE_NULL)
  {
    memcpy(&b, &ctx->pkt[b_loc], sizeof(b));
    hole.left_valid = 1;
    hole.left_div_8 = b_loc/8;
    b.parent_valid = 1;
    b.parent_div_8 = loc/8;
  }
  else
  {
    hole.left_valid = 0;
  }
  p.right_valid = 1;
  p.right_div_8 = loc/8;
  hole.parent_valid = 1;
  hole.parent_div_8 = p_loc/8;
  if (c_loc != RB815_HOLE_NULL)
  {
    memcpy(&c, &ctx->pkt[c_loc], sizeof(c));
    hole.right_valid = 1;
    hole.right_div_8 = c_loc/8;
    c.parent_valid = 1;
    c.parent_div_8 = loc/8;
  }
  else
  {
    hole.right_valid = 0;
  }
  if (parent_loc == RB815_HOLE_NULL)
  {
    ctx->root_hole = p_loc;
    p.parent_valid = 0;
  }
  else if (parent.left_valid && loc == parent.left_div_8 * 8)
  {
    parent.left_valid = 1;
    parent.left_div_8 = p_loc/8;
    p.parent_valid = 1;
    p.parent_div_8 = parent_loc/8;
  }
  else if (parent.right_valid && loc == parent.right_div_8 * 8)
  {
    parent.right_valid = 1;
    parent.right_div_8 = p_loc/8;
    p.parent_valid = 1;
    p.parent_div_8 = parent_loc/8;
  }
  else
  {
#if PRINT_TREE
    printf("ErrorErrorError loc %d parent %d\n", loc, parent_loc);
    printf("parent left %d %d\n", parent.left_valid, parent.left_div_8*8);
    printf("parent right %d %d\n", parent.right_valid, parent.right_div_8*8);
    print_tree(ctx, ctx->root_hole);
#endif
    abort();
  }
  if (a_loc != RB815_HOLE_NULL)
  {
    memcpy(&ctx->pkt[a_loc], &a, sizeof(a));
  }
  if (b_loc != RB815_HOLE_NULL)
  {
    memcpy(&ctx->pkt[b_loc], &b, sizeof(b));
  }
  if (c_loc != RB815_HOLE_NULL)
  {
    memcpy(&ctx->pkt[c_loc], &c, sizeof(c));
  }
  memcpy(&ctx->pkt[loc], &hole, sizeof(hole));
  memcpy(&ctx->pkt[p_loc], &p, sizeof(p));
  if (parent_loc != RB815_HOLE_NULL)
  {
    memcpy(&ctx->pkt[parent_loc], &parent, sizeof(parent));
  }
}

static void rb815_tree_insert_repair(struct rb815ctx *ctx, uint16_t loc)
{
  struct rb815hole hole = RB815HOLE_EMPTY;
  uint16_t parent_loc;
  struct rb815hole parent = RB815HOLE_EMPTY;
  uint16_t uncle_loc;
  struct rb815hole uncle = RB815HOLE_EMPTY;
  uint16_t grandparent_loc;
  struct rb815hole grandparent = RB815HOLE_EMPTY;
  struct rb815hole gpl = RB815HOLE_EMPTY, gpr = RB815HOLE_EMPTY;
  memcpy(&hole, &ctx->pkt[loc], sizeof(hole));
  if (!hole.parent_valid)
  {
    hole.is_black = 1;
    memcpy(&ctx->pkt[loc], &hole, sizeof(hole));
    return;
  }
  parent_loc = hole.parent_div_8 * 8;
  memcpy(&parent, &ctx->pkt[parent_loc], sizeof(parent));
  if (parent.is_black)
  {
    // Do nothing
    return;
  }
  uncle_loc = get_uncle_loc(ctx, loc);
  if (uncle_loc != RB815_HOLE_NULL)
  {
    memcpy(&uncle, &ctx->pkt[uncle_loc], sizeof(uncle));
    if (!uncle.is_black)
    {
      if (!parent.parent_valid)
      {
        abort();
      }
      grandparent_loc = parent.parent_div_8 * 8;
      memcpy(&grandparent, &ctx->pkt[grandparent_loc], sizeof(grandparent));
      parent.is_black = 1;
      uncle.is_black = 1;
      grandparent.is_black = 0;
      memcpy(&ctx->pkt[parent_loc], &parent, sizeof(parent));
      memcpy(&ctx->pkt[uncle_loc], &uncle, sizeof(uncle));
      memcpy(&ctx->pkt[grandparent_loc], &grandparent, sizeof(grandparent));
      rb815_tree_insert_repair(ctx, grandparent_loc); // Tail rec.
      return;
    }
  }

  if (!parent.parent_valid)
  {
    abort();
  }
  grandparent_loc = parent.parent_div_8 * 8;
  memcpy(&grandparent, &ctx->pkt[grandparent_loc], sizeof(grandparent));
  if (grandparent.left_valid)
  {
    memcpy(&gpl, &ctx->pkt[grandparent.left_div_8*8], sizeof(gpl));
  }
  if (grandparent.right_valid)
  {
    memcpy(&gpr, &ctx->pkt[grandparent.right_div_8*8], sizeof(gpr));
  }
  if (grandparent.left_valid && loc == gpl.right_div_8 * 8)
  {
    rotate_left(ctx, parent_loc);
    memcpy(&hole, &ctx->pkt[loc], sizeof(hole));
    memcpy(&parent, &ctx->pkt[parent_loc], sizeof(parent));
    memcpy(&grandparent, &ctx->pkt[grandparent_loc], sizeof(grandparent));
    if (!hole.left_valid)
    {
      abort();
    }
    loc = hole.left_div_8 * 8;
    memcpy(&hole, &ctx->pkt[loc], sizeof(hole));
  }
  else if (grandparent.right_valid && loc == gpr.left_div_8 * 8)
  {
    rotate_right(ctx, parent_loc);
    memcpy(&hole, &ctx->pkt[loc], sizeof(hole));
    memcpy(&parent, &ctx->pkt[parent_loc], sizeof(parent));
    memcpy(&grandparent, &ctx->pkt[grandparent_loc], sizeof(grandparent));
    if (!hole.right_valid)
    {
      abort();
    }
    loc = hole.right_div_8 * 8;
    memcpy(&hole, &ctx->pkt[loc], sizeof(hole));
  }
  if (!hole.parent_valid)
  {
    abort();
  }
  parent_loc = hole.parent_div_8 * 8;
  memcpy(&parent, &ctx->pkt[parent_loc], sizeof(parent));
  if (!parent.parent_valid)
  {
    abort();
  }
  grandparent_loc = parent.parent_div_8 * 8;
  memcpy(&grandparent, &ctx->pkt[grandparent_loc], sizeof(grandparent));
  if (parent.left_valid && loc == parent.left_div_8 * 8)
  {
    rotate_right(ctx, grandparent_loc);
    memcpy(&parent, &ctx->pkt[parent_loc], sizeof(parent));
    memcpy(&grandparent, &ctx->pkt[grandparent_loc], sizeof(grandparent));
  }
  else
  {
    rotate_left(ctx, grandparent_loc);
    memcpy(&parent, &ctx->pkt[parent_loc], sizeof(parent));
    memcpy(&grandparent, &ctx->pkt[grandparent_loc], sizeof(grandparent));
  }
  parent.is_black = 1;
  grandparent.is_black = 0;
  memcpy(&ctx->pkt[parent_loc], &parent, sizeof(parent));
  memcpy(&ctx->pkt[grandparent_loc], &grandparent, sizeof(grandparent));
}

#if 0
static int
rb815_hole_tree_cmp(struct rb815ctx *ctx, uint16_t a, uint16_t b)
{
  struct rb815hole ha;
  struct rb815hole hb;
  memcpy(&ha, &ctx->pkt[a], sizeof(ha));
  memcpy(&hb, &ctx->pkt[b], sizeof(hb));
  if (a+ha.len-1 < b)
  {
    return -1;
  }
  if (b+hb.len-1 < a)
  {
    return 1;
  }
  abort();
}
#endif

static uint16_t rb815_tree_rightmost(struct rb815ctx *ctx)
{
  struct rb815hole hole;
  uint16_t loc = ctx->root_hole;
  if (loc == RB815_HOLE_NULL)
  {
    return loc;
  }
  memcpy(&hole, &ctx->pkt[loc], sizeof(hole));
  while (hole.right_valid)
  {
    loc = hole.right_div_8 * 8;
    memcpy(&hole, &ctx->pkt[loc], sizeof(hole));
  }
  return loc;
}

static void
delete_case6(struct rb815ctx *ctx, uint16_t loc, uint16_t parent_loc)
{
  uint16_t s_loc = get_sibling_loc_parent(ctx, loc, parent_loc);
  struct rb815hole s;
  struct rb815hole parent;
  uint16_t s_left_loc = RB815_HOLE_NULL;
  uint16_t s_right_loc = RB815_HOLE_NULL;
  struct rb815hole s_left;
  struct rb815hole s_right;
  if (s_loc == RB815_HOLE_NULL || parent_loc == RB815_HOLE_NULL)
  {
    abort();
  }
  memcpy(&parent, &ctx->pkt[parent_loc], sizeof(parent));
  memcpy(&s, &ctx->pkt[s_loc], sizeof(s));
  s_left_loc = s.left_valid ? (s.left_div_8*8) : RB815_HOLE_NULL;
  s_right_loc = s.right_valid ? (s.right_div_8*8) : RB815_HOLE_NULL;
  if (s_left_loc != RB815_HOLE_NULL)
  {
    memcpy(&s_left, &ctx->pkt[s_left_loc], sizeof(s_left));
  }
  if (s_right_loc != RB815_HOLE_NULL)
  {
    memcpy(&s_right, &ctx->pkt[s_right_loc], sizeof(s_right));
  }
  if (parent.left_valid && parent.left_div_8*8 == loc)
  {
    s_right.is_black = 1;
    memcpy(&ctx->pkt[s_right_loc], &s_right, sizeof(s_right));
    rotate_left(ctx, parent_loc);
  }
  else
  {
    s_left.is_black = 1;
    memcpy(&ctx->pkt[s_left_loc], &s_left, sizeof(s_left));
    rotate_right(ctx, parent_loc);
  }
}

static void
delete_case5(struct rb815ctx *ctx, uint16_t loc, uint16_t parent_loc)
{
  uint16_t s_loc = get_sibling_loc_parent(ctx, loc, parent_loc);
  struct rb815hole s;
  struct rb815hole parent;
  uint16_t s_left_loc = RB815_HOLE_NULL;
  uint16_t s_right_loc = RB815_HOLE_NULL;
  struct rb815hole s_left;
  struct rb815hole s_right;
  if (s_loc == RB815_HOLE_NULL || parent_loc == RB815_HOLE_NULL)
  {
    abort();
  }
  memcpy(&parent, &ctx->pkt[parent_loc], sizeof(parent));
  memcpy(&s, &ctx->pkt[s_loc], sizeof(s));
  s_left_loc = s.left_valid ? (s.left_div_8*8) : RB815_HOLE_NULL;
  s_right_loc = s.right_valid ? (s.right_div_8*8) : RB815_HOLE_NULL;
  if (s_left_loc != RB815_HOLE_NULL)
  {
    memcpy(&s_left, &ctx->pkt[s_left_loc], sizeof(s_left));
  }
  if (s_right_loc != RB815_HOLE_NULL)
  {
    memcpy(&s_right, &ctx->pkt[s_right_loc], sizeof(s_right));
  }
  if (s.is_black)
  {
    if (parent.left_valid && parent.left_div_8*8 == loc &&
        (s_right_loc == RB815_HOLE_NULL || s_right.is_black) &&
        (s_left_loc != RB815_HOLE_NULL && !s_left.is_black))
    {
      s.is_black = 0;
      s_left.is_black = 1;
      memcpy(&ctx->pkt[s_loc], &s, sizeof(s));
      memcpy(&ctx->pkt[s_left_loc], &s_left, sizeof(s_left));
      rotate_right(ctx, s_loc);
    }
    else if (parent.right_valid && parent.right_div_8*8 == loc &&
        (s_left_loc == RB815_HOLE_NULL || s_left.is_black) &&
        (s_right_loc != RB815_HOLE_NULL && !s_right.is_black))
    {
      s.is_black = 0;
      s_right.is_black = 1;
      memcpy(&ctx->pkt[s_loc], &s, sizeof(s));
      memcpy(&ctx->pkt[s_right_loc], &s_right, sizeof(s_right));
      rotate_left(ctx, s_loc);
    }
  }
  delete_case6(ctx, loc, parent_loc);
}

static void
delete_case4(struct rb815ctx *ctx, uint16_t loc, uint16_t parent_loc)
{
  uint16_t s_loc = get_sibling_loc_parent(ctx, loc, parent_loc);
  struct rb815hole s;
  uint16_t s_left_loc = RB815_HOLE_NULL;
  uint16_t s_right_loc = RB815_HOLE_NULL;
  struct rb815hole s_left = RB815HOLE_EMPTY;
  struct rb815hole s_right = RB815HOLE_EMPTY;
  struct rb815hole parent;
  memcpy(&parent, &ctx->pkt[parent_loc], sizeof(parent));
  if (s_loc != RB815_HOLE_NULL)
  {
    memcpy(&s, &ctx->pkt[s_loc], sizeof(s));
    s_left_loc = s.left_valid ? (s.left_div_8*8) : RB815_HOLE_NULL;
    s_right_loc = s.right_valid ? (s.right_div_8*8) : RB815_HOLE_NULL;
    if (s_left_loc != RB815_HOLE_NULL)
    {
      memcpy(&s_left, &ctx->pkt[s_left_loc], sizeof(s_left));
    }
    if (s_right_loc != RB815_HOLE_NULL)
    {
      memcpy(&s_right, &ctx->pkt[s_right_loc], sizeof(s_right));
    }
  }
  if ((!parent.is_black) &&
      (s_loc == RB815_HOLE_NULL || s.is_black) &&
      (s_left_loc == RB815_HOLE_NULL || s_left.is_black) &&
      (s_right_loc == RB815_HOLE_NULL || s_right.is_black))
  {
    s.is_black = 0;
    parent.is_black = 1;
    memcpy(&ctx->pkt[s_loc], &s, sizeof(s));
    memcpy(&ctx->pkt[parent_loc], &parent, sizeof(parent));
  }
  else
  {
    delete_case5(ctx, loc, parent_loc);
  }
}

static void
delete_case1(struct rb815ctx *ctx, uint16_t loc, uint16_t parent_loc);

static void
delete_case3(struct rb815ctx *ctx, uint16_t loc, uint16_t parent_loc)
{
  uint16_t s_loc = get_sibling_loc_parent(ctx, loc, parent_loc);
  struct rb815hole s;
  uint16_t s_left_loc = RB815_HOLE_NULL;
  uint16_t s_right_loc = RB815_HOLE_NULL;
  struct rb815hole s_left = RB815HOLE_EMPTY;
  struct rb815hole s_right = RB815HOLE_EMPTY;
  struct rb815hole parent;
  memcpy(&parent, &ctx->pkt[parent_loc], sizeof(parent));
  if (s_loc != RB815_HOLE_NULL)
  {
    memcpy(&s, &ctx->pkt[s_loc], sizeof(s));
    s_left_loc = s.left_valid ? (s.left_div_8*8) : RB815_HOLE_NULL;
    s_right_loc = s.right_valid ? (s.right_div_8*8) : RB815_HOLE_NULL;
    if (s_left_loc != RB815_HOLE_NULL)
    {
      memcpy(&s_left, &ctx->pkt[s_left_loc], sizeof(s_left));
    }
    if (s_right_loc != RB815_HOLE_NULL)
    {
      memcpy(&s_right, &ctx->pkt[s_right_loc], sizeof(s_right));
    }
  }
  if (parent.is_black &&
      (s_loc == RB815_HOLE_NULL || s.is_black) &&
      (s_left_loc == RB815_HOLE_NULL || s_left.is_black) &&
      (s_right_loc == RB815_HOLE_NULL || s_right.is_black))
  {
    s.is_black = 0;
    memcpy(&ctx->pkt[s_loc], &s, sizeof(s));
    delete_case1(ctx, parent_loc,
      parent.parent_valid ? (parent.parent_div_8*8) : RB815_HOLE_NULL);
  }
  else
  {
    delete_case4(ctx, loc, parent_loc);
  }
}

static void
delete_case2(struct rb815ctx *ctx, uint16_t loc, uint16_t parent_loc)
{
  uint16_t s_loc = get_sibling_loc_parent(ctx, loc, parent_loc);
  struct rb815hole s;
  struct rb815hole parent;
  memcpy(&parent, &ctx->pkt[parent_loc], sizeof(parent));
  if (s_loc != RB815_HOLE_NULL)
  {
    memcpy(&s, &ctx->pkt[s_loc], sizeof(s));
  }
  if (s_loc != RB815_HOLE_NULL && !s.is_black)
  {
    parent.is_black = 0;
    s.is_black = 1;
    memcpy(&ctx->pkt[parent_loc], &parent, sizeof(parent));
    memcpy(&ctx->pkt[s_loc], &s, sizeof(s));
    if (parent.left_valid && loc == parent.left_div_8*8)
    {
      rotate_left(ctx, parent_loc);
    }
    else
    {
      rotate_right(ctx, parent_loc);
    }
  }
  delete_case3(ctx, loc, parent_loc);
}

static void
delete_case1(struct rb815ctx *ctx, uint16_t loc, uint16_t parent_loc)
{
#ifdef PRINT_TREE
  printf("case1 loc %d\n", loc);
#endif
  if (parent_loc != RB815_HOLE_NULL)
  {
    delete_case2(ctx, loc, parent_loc);
  }
}

static void __attribute__((unused))
rb815_tree_delete_one_child(struct rb815ctx *ctx, uint16_t loc)
{
  struct rb815hole node;
  struct rb815hole child;
  uint16_t child_loc;
  struct rb815hole parent;
  uint16_t parent_loc;
  memcpy(&node, &ctx->pkt[loc], sizeof(node));
  parent_loc = node.parent_valid ? (node.parent_div_8*8) : RB815_HOLE_NULL;
  if (parent_loc != RB815_HOLE_NULL)
  {
    memcpy(&parent, &ctx->pkt[parent_loc], sizeof(parent));
  }
  if (!node.right_valid)
  {
    child_loc = node.left_valid ? (node.left_div_8*8) : RB815_HOLE_NULL;
  }
  else
  {
    child_loc = node.right_valid ? (node.right_div_8*8) : RB815_HOLE_NULL;
  }
  if (child_loc != RB815_HOLE_NULL)
  {
    memcpy(&child, &ctx->pkt[child_loc], sizeof(child));
  }
  if (parent_loc == RB815_HOLE_NULL)
  {
    ctx->root_hole = child_loc;
    if (child_loc != RB815_HOLE_NULL)
    {
      child.parent_valid = 0;
    }
  }
  else if (parent.left_valid && parent.left_div_8*8 == loc)
  {
    parent.left_valid = (child_loc != RB815_HOLE_NULL);
    parent.left_div_8 = child_loc/8;
    if (child_loc != RB815_HOLE_NULL)
    {
      child.parent_valid = 1;
      child.parent_div_8 = parent_loc/8;
    }
  }
  else if (parent.right_valid && parent.right_div_8*8 == loc)
  {
    parent.right_valid = (child_loc != RB815_HOLE_NULL);
    parent.right_div_8 = child_loc/8;
    if (child_loc != RB815_HOLE_NULL)
    {
      child.parent_valid = 1;
      child.parent_div_8 = parent_loc/8;
    }
  }
  if (child_loc != RB815_HOLE_NULL)
  {
    //child->is_black = node.is_black; // XXX
  }
  if (child_loc != RB815_HOLE_NULL)
  {
    memcpy(&ctx->pkt[child_loc], &child, sizeof(child));
  }
  if (parent_loc != RB815_HOLE_NULL)
  {
    memcpy(&ctx->pkt[parent_loc], &parent, sizeof(parent));
  }
  if (node.is_black)
  {
    if (child_loc != RB815_HOLE_NULL && !child.is_black)
    {
      child.is_black = 1;
      memcpy(&ctx->pkt[child_loc], &child, sizeof(child));
    }
    else
    {
#ifdef PRINT_TREE
      printf("child_loc %d\n", child_loc);
#endif
      if (child_loc != RB815_HOLE_NULL) // XXX
      {
        delete_case1(ctx, child_loc, parent_loc);
      }
    }
  }
}

static void __attribute__((unused))
rb815_tree_delete(struct rb815ctx *ctx, uint16_t loc)
{
  struct rb815hole node;
  memcpy(&node, &ctx->pkt[loc], sizeof(node));
#ifdef PRINT_TREE
  printf("deleting hole %d:%d\n", loc, loc+node.len-1);
#endif
  if (node.left_valid && node.right_valid)
  {
    struct rb815hole hole2;
    uint16_t loc2 = node.left_div_8*8;
    memcpy(&hole2, &ctx->pkt[loc2], sizeof(hole2));
    while (hole2.right_valid)
    {
      loc2 = hole2.right_div_8 * 8;
      memcpy(&hole2, &ctx->pkt[loc2], sizeof(hole2));
    }
#ifdef PRINT_TREE
    printf("Exchanging %d<->%d\n", loc, loc2);
    printf("before exchange validity %d\n", rb815_tree_ptrs_valid(ctx));
#endif
    exchange(ctx, loc, loc2);
#ifdef PRINT_TREE
    printf("after exchange validity %d\n", rb815_tree_ptrs_valid(ctx));
    printf("Exchanged, root %d:\n", ctx->root_hole);
    print_tree(ctx, ctx->root_hole);
    printf("------\n");
    printf("before delete_one_child validity %d\n", rb815_tree_ptrs_valid(ctx));
#endif
    rb815_tree_delete_one_child(ctx, loc);
#ifdef PRINT_TREE
    printf("after delete_one_child validity %d\n", rb815_tree_ptrs_valid(ctx));
    printf("Deleted, root %d:\n", ctx->root_hole);
    print_tree(ctx, ctx->root_hole);
    printf("------\n");
#endif
    return;
  }
#ifdef PRINT_TREE
  printf("Already has one child\n");
  printf("before delete_one_child validity %d\n", rb815_tree_ptrs_valid(ctx));
#endif
  rb815_tree_delete_one_child(ctx, loc);
#ifdef PRINT_TREE
  printf("after delete_one_child validity %d\n", rb815_tree_ptrs_valid(ctx));
#endif
}

struct packet *rb815ctx_reassemble(struct allocif *loc, struct rb815ctx *ctx)
{
  struct packet *pkt;
  size_t sz;
  char *ether2, *ip2, *pay2;
  sz = ctx->hdr_len + ctx->most_restricting_last + 1;
  pkt = allocif_alloc(loc, packet_size(sz));
  if (pkt == NULL)
  {
    return NULL;
  }
  pkt->sz = sz;
  pkt->direction = ctx->direction;
  pkt->data = packet_calc_data(pkt);
  ether2 = pkt->data;
  //printf("hdr_len %zu\n", (size_t)ctx->hdr_len);
  memcpy(ether2, ctx->pkt_header, ctx->hdr_len);
  ip2 = ether_payload(ether2);
  ip_set_frag_off(ip2, 0);
  ip_set_more_frags(ip2, 0);
  ip_set_total_len(ip2, ctx->hdr_len - 14 + ctx->most_restricting_last + 1);
  ip_set_hdr_cksum_calc(ip2, ctx->hdr_len - 14);
  pay2 = ether2 + ctx->hdr_len;
  memcpy(pay2, ctx->pkt, (size_t)ctx->most_restricting_last + 1);
  return pkt;
}

static void repair_most_restricting(struct rb815ctx *ctx)
{
  uint16_t loc;
  struct rb815hole hole;
  for (;;)
  {
    if (ctx->root_hole == RB815_HOLE_NULL)
    {
      return;
    }
    loc = rb815_tree_rightmost(ctx);
    memcpy(&hole, &ctx->pkt[loc], sizeof(hole));
    if (loc > ctx->most_restricting_last)
    {
      rb815_tree_delete(ctx, loc);
    }
    else
    {
      break;
    }
  }
  if (loc + hole.len - 1 > ctx->most_restricting_last)
  {
    hole.len = ctx->most_restricting_last - loc + 1;
  }
  memcpy(&ctx->pkt[loc], &hole, sizeof(hole));
}

static void add_data(struct rb815ctx *ctx,
                     uint16_t data_first, uint16_t data_last,
                     int *mod)
{
  uint16_t loc;
  struct rb815hole hole;

back:
  loc = ctx->root_hole;
  memcpy(&hole, &ctx->pkt[loc], sizeof(hole));
  while (loc != RB815_HOLE_NULL)
  {
    if (loc + hole.len - 1 < data_first)
    {
      loc = hole.right_valid ? (hole.right_div_8*8) : RB815_HOLE_NULL;
      memcpy(&hole, &ctx->pkt[loc], sizeof(hole));
      continue;
    }
    if (loc > data_last)
    {
      loc = hole.left_valid ? (hole.left_div_8*8) : RB815_HOLE_NULL;
      memcpy(&hole, &ctx->pkt[loc], sizeof(hole));
      continue;
    }
    break;
  }
  if (loc == RB815_HOLE_NULL)
  {
    return;
  }
  if (loc + hole.len - 1 > data_last && loc < data_first)
  {
    struct rb815hole new_hole = RB815HOLE_EMPTY;
    uint16_t new_loc;
    new_loc = data_last + 1;
    // new_hole->last = hole->last
    // new_hole->begin + new_hole->len - 1 = hole->last
    // new_hole->begin + new_hole->len = hole->last + 1
    // new_hole->len = hole->last + 1 - new_hole->begin
    // new_hole->len = hole->begin + hole->len - 1 + 1 - new_hole->begin
    new_hole.len = loc + hole.len - new_loc;
    hole.len = data_first - loc;
#ifdef EXTRA_DEBUG
    if (!rb815_tree_valid(ctx))
    {
      printf("Invalid1\n");
      abort();
    }
#endif
    if (!hole.right_valid)
    {
#ifdef EXTRA_DEBUG
      printf("Easy!\n");
#endif
      if ((new_loc % 8 != 0) || (loc % 8 != 0))
      {
        abort();
      }
      hole.right_div_8 = new_loc / 8;
      hole.right_valid = 1;
      new_hole.is_black = 0;
      new_hole.parent_valid = 1;
      new_hole.parent_div_8 = loc / 8;
      new_hole.left_valid = 0;
      new_hole.right_valid = 0;
#ifdef PRINT_TREE
      printf("before memcpys validity %d\n", rb815_tree_ptrs_valid(ctx));
#endif
      memcpy(&ctx->pkt[loc], &hole, sizeof(hole));
      memcpy(&ctx->pkt[new_loc], &new_hole, sizeof(new_hole));
#ifdef PRINT_TREE
      printf("after memcpys validity %d\n", rb815_tree_ptrs_valid(ctx));
#endif
      rb815_tree_insert_repair(ctx, new_loc);
#ifdef PRINT_TREE
      printf("after repair validity %d\n", rb815_tree_ptrs_valid(ctx));
#endif
#ifdef EXTRA_DEBUG
      if (!rb815_tree_valid(ctx))
      {
        printf("Invalid2\n");
        abort();
      }
#endif
      *mod = 1;
      return;
    }
    memcpy(&ctx->pkt[loc], &hole, sizeof(hole)); // XXX
    loc = hole.right_div_8 * 8;
    memcpy(&hole, &ctx->pkt[loc], sizeof(hole));
    while (hole.left_valid)
    {
      loc = hole.left_div_8 * 8;
      memcpy(&hole, &ctx->pkt[loc], sizeof(hole));
    }
    if ((new_loc % 8 != 0) || (loc % 8 != 0))
    {
      abort();
    }
    hole.left_div_8 = new_loc / 8;
    hole.left_valid = 1;
    new_hole.is_black = 0;
    new_hole.parent_valid = 1;
    new_hole.parent_div_8 = loc / 8;
    new_hole.left_valid = 0;
    new_hole.right_valid = 0;
#ifdef PRINT_TREE
    printf("Before memcpys validity %d\n", rb815_tree_ptrs_valid(ctx));
#endif
    memcpy(&ctx->pkt[loc], &hole, sizeof(hole));
    memcpy(&ctx->pkt[new_loc], &new_hole, sizeof(new_hole));
#ifdef PRINT_TREE
    printf("After memcpys validity %d\n", rb815_tree_ptrs_valid(ctx));
#endif
    rb815_tree_insert_repair(ctx, new_loc);
#ifdef PRINT_TREE
    printf("After repair validity %d\n", rb815_tree_ptrs_valid(ctx));
#endif
#ifdef EXTRA_DEBUG
    if (!rb815_tree_valid(ctx))
    {
      printf("Invalid3\n");
      abort();
    }
#endif
    //rb815_tree_insert(ctx, &new_hole->node);
    *mod = 1;
    return;
  }
  if (loc + hole.len - 1 <= data_last && loc >= data_first)
  {
#ifdef PRINT_TREE
    printf("Deleting\n");
#endif
    rb815_tree_delete(ctx, loc);
#ifdef PRINT_TREE
    printf("Deleted\n");
#endif
    *mod = 1;
    goto back;
  }
  if (loc + hole.len - 1 <= data_last && loc + hole.len > data_first)
  {
    hole.len = data_first - loc;
#ifdef PRINT_TREE
    printf("End-shrinking\n");
#endif
    memcpy(&ctx->pkt[loc], &hole, sizeof(hole));
#ifdef PRINT_TREE
    printf("End-shrinked\n");
#endif
    *mod = 1;
    goto back;
  }
  if (loc >= data_first && loc < data_last + 1)
  {
    struct rb815hole parent_hole;
    uint16_t parent_loc;
    uint16_t new_loc;
    new_loc = data_last + 1;
#ifdef PRINT_TREE
    printf("Hole-moving\n");
#endif
    if (new_loc % 8 != 0)
    {
      abort();
    }
    hole.len -= (new_loc - loc);
    memcpy(&ctx->pkt[new_loc], &hole, sizeof(hole));
    if (hole.left_valid)
    {
      uint16_t left_loc = hole.left_div_8*8;
      struct rb815hole left_hole;
      memcpy(&left_hole, &ctx->pkt[left_loc], sizeof(left_hole));
      left_hole.parent_div_8 = new_loc/8;
      memcpy(&ctx->pkt[left_loc], &left_hole, sizeof(left_hole));
    }
    if (hole.right_valid)
    {
      uint16_t right_loc = hole.right_div_8*8;
      struct rb815hole right_hole;
      memcpy(&right_hole, &ctx->pkt[right_loc], sizeof(right_hole));
      right_hole.parent_div_8 = new_loc/8;
      memcpy(&ctx->pkt[right_loc], &right_hole, sizeof(right_hole));
    }
    if (!hole.parent_valid)
    {
      ctx->root_hole = new_loc;
      *mod = 1;
#ifdef PRINT_TREE
      printf("Hole-moved-root\n");
#endif
      goto back;
    }
    parent_loc = hole.parent_div_8*8;
    memcpy(&parent_hole, &ctx->pkt[parent_loc], sizeof(parent_hole));
    if (parent_hole.left_valid && parent_hole.left_div_8*8 == loc)
    {
      parent_hole.left_div_8 = new_loc / 8;
    }
    else if (parent_hole.right_valid && parent_hole.right_div_8*8 == loc)
    {
      parent_hole.right_div_8 = new_loc / 8;
    }
    else
    {
      abort();
    }
    memcpy(&ctx->pkt[parent_loc], &parent_hole, sizeof(parent_hole));
#ifdef PRINT_TREE
    printf("Hole-moved\n");
#endif
    *mod = 1;
    goto back;
  }
}

void rb815ctx_add(struct rb815ctx *ctx, struct packet *pkt)
{
  const char *ether = pkt->data;
  const char *ip = ether_const_payload(ether);
  uint16_t data_first;
  uint16_t data_last;
  int mod = 0;
  //linktest(ctx);
  if (pkt->sz < 34 ||
      ip_total_len(ip) <= ip_hdr_len(ip) ||
      (size_t)(ip_total_len(ip) + 14) > pkt->sz)
  {
    return;
  }
  if (ctx->hdr_len == 0)
  {
    ctx->hdr_len = 14 + (size_t)ip_hdr_len(ip);
    memcpy(ctx->pkt_header, ether, ctx->hdr_len);
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
    repair_most_restricting(ctx);
    mod = 1;
  }
  else
  {
    if (data_last < 7)
    {
      return;
    }
    data_last = (data_last + 1) / 8 * 8 - 1;
  }
#ifdef PRINT_TREE
  printf("-----\n");
  printf("first %d last %d\n", data_first, data_last); // FIXME comment out
  printf("before add_data validity %d\n", rb815_tree_ptrs_valid(ctx));
#endif
  add_data(ctx, data_first, data_last, &mod);
#ifdef PRINT_TREE
  printf("after add_data validity %d\n", rb815_tree_ptrs_valid(ctx));
  print_tree(ctx, ctx->root_hole);
  printf("-----\n");
#endif
  if (mod)
  {
    memcpy(&ctx->pkt[data_first], ip_const_payload(ip), (size_t)data_last - (size_t)data_first + 1);
  }
}
