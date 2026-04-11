#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "rbtree.h"
#include "time64.h"
#include "containerof.h"

struct test_entry {
  struct rb_tree_node node;
  int i;
};

static int cmp(struct rb_tree_node *n1, struct rb_tree_node *n2, void *userdata)
{
  struct test_entry *e1 = CONTAINER_OF(n1, struct test_entry, node);
  struct test_entry *e2 = CONTAINER_OF(n2, struct test_entry, node);
  if (e1->i > e2->i)
  {
    return 1;
  }
  if (e1->i < e2->i)
  {
    return -1;
  }
  return 0;
}

static inline int cmp_inline(struct rb_tree_node *n1, struct rb_tree_node *n2, void *userdata)
{
  struct test_entry *e1 = CONTAINER_OF(n1, struct test_entry, node);
  struct test_entry *e2 = CONTAINER_OF(n2, struct test_entry, node);
  if (e1->i > e2->i)
  {
    return 1;
  }
  if (e1->i < e2->i)
  {
    return -1;
  }
  return 0;
}

static void insert_random(struct rb_tree *tree)
{
  struct test_entry *e = malloc(sizeof(*e));
  e->i = rand();
  //printf("inserting %d\n", e->i);
  rb_tree_insert(tree, &e->node);
}

static void print_tree(struct rb_tree *tree);

static void delete_random(struct rb_tree *tree)
{
  struct rb_tree_node *node = rb_tree_root(tree);
  if (node == NULL)
  {
    return;
  }
  for (;;)
  {
    int tri = rand()%3;
    if (tri == 0)
    {
      //printf("deleting %d\n", CONTAINER_OF(node, struct test_entry, node)->i);
      rb_tree_delete(tree, node);
      free(CONTAINER_OF(node, struct test_entry, node));
      return;
    }
    else if (tri == 1)
    {
      if (node->left == NULL)
      {
        //printf("deleting %d\n", CONTAINER_OF(node, struct test_entry, node)->i);
        rb_tree_delete(tree, node);
        free(CONTAINER_OF(node, struct test_entry, node));
        return;
      }
      node = node->left;
    }
    else
    {
      if (node->right == NULL)
      {
        //printf("deleting %d\n", CONTAINER_OF(node, struct test_entry, node)->i);
        rb_tree_delete(tree, node);
        free(CONTAINER_OF(node, struct test_entry, node));
        return;
      }
      node = node->right;
    }
  }
}

static void indent(int level)
{
  int i;
  for (i = 0; i < level; i++)
  {
    printf(" ");
  }
}

static void print_node(int level, struct rb_tree_node *node)
{
  struct test_entry *e = CONTAINER_OF(node, struct test_entry, node);
  indent(level);
  printf("is_black: %d\n", node->is_black);
  indent(level);
  printf("i: %d\n", e->i);
  indent(level);
  printf("left:\n");
  if (node->left != NULL)
  {
    print_node(level+2, node->left);
  }
  indent(level);
  printf("right:\n");
  if (node->right != NULL)
  {
    print_node(level+2, node->right);
  }
}

static void print_tree(struct rb_tree *tree)
{
  if (rb_tree_root(tree) != NULL)
  {
    print_node(0, rb_tree_root(tree));
  }
}

static inline int cmp_asym(int i, struct rb_tree_node *n, void *ud)
{
  struct test_entry *e2 = CONTAINER_OF(n, struct test_entry, node);
  if (i > e2->i)
  {
    return 1;
  }
  if (i < e2->i)
  {
    return -1;
  }
  return 0;
}
static inline int cmp_asym_void(const void *vi, struct rb_tree_node *n, void *ud)
{
  const int *i = vi;
  struct test_entry *e2 = CONTAINER_OF(n, struct test_entry, node);
  if (*i > e2->i)
  {
    return 1;
  }
  if (*i < e2->i)
  {
    return -1;
  }
  return 0;
}

static int insert_deterministic(struct rb_tree_nocmp *tree, int i)
{
  struct test_entry *e = malloc(sizeof(*e));
  e->i = i;
  //printf("inserting %d\n", e->i);
  return rb_tree_nocmp_insert_nonexist(tree, cmp, NULL, &e->node);
}

static inline struct rb_tree_node *
my_tree_nocmp_find(struct rb_tree_nocmp *tree, int i)
{
  struct test_entry tofind;
  tofind.i = i;
  return rb_tree_nocmp_find(tree, cmp_inline, NULL, &tofind.node);
}

static void findperf1(struct rb_tree_nocmp *tree)
{
  int i;
  uint64_t begin, end;
  begin = gettime64();
  for (i = 0; i < 10*1000*1000; i++)
  {
    if (my_tree_nocmp_find(tree, 4) != NULL)
    {
      printf("err\n");
      abort();
    }
  }
  end = gettime64();
  printf("%g MPPS\n", 1e7/(end-begin));
}

static void findperf2(struct rb_tree_nocmp *tree)
{
  int i;
  uint64_t begin, end;
  begin = gettime64();
  for (i = 0; i < 10*1000*1000; i++)
  {
    if (RB_TREE_NOCMP_FIND(tree, cmp_asym, NULL, 4) != NULL)
    {
      printf("err\n");
      abort();
    }
  }
  end = gettime64();
  printf("%g MPPS\n", 1e7/(end-begin));
  begin = gettime64();
  for (i = 0; i < 10*1000*1000; i++)
  {
    int val = 4;
    if (rb_tree_nocmp_find_asym(tree, cmp_asym_void, NULL, &val) != NULL)
    {
      printf("err\n");
      abort();
    }
  }
  end = gettime64();
  printf("%g MPPS\n", 1e7/(end-begin));
}

static void insperf1(struct rb_tree_nocmp *tree)
{
  int i;
  uint64_t begin, end;
  struct test_entry node;
  node.i = 5;
  begin = gettime64();
  for (i = 0; i < 100*1000*1000; i++)
  {
    if (rb_tree_nocmp_insert_nonexist(tree, cmp_inline, NULL, &node.node) != -EEXIST)
    {
      printf("err\n");
      abort();
    }
  }
  end = gettime64();
  printf("%g MPPS\n", 1e8/(end-begin));
}

static void insperf2(struct rb_tree_nocmp *tree)
{
  int i;
  uint64_t begin, end;
  struct test_entry node;
  node.i = 5;
  begin = gettime64();
  for (i = 0; i < 100*1000*1000; i++)
  {
    if (RB_TREE_NOCMP_INSERT_NONEXIST(tree, cmp_inline, NULL, &node.node) != -EEXIST)
    {
      printf("err\n");
      abort();
    }
  }
  end = gettime64();
  printf("%g MPPS\n", 1e8/(end-begin));
}

static void nocmptest(void)
{
  struct rb_tree_nocmp tree = {};
  int val;
  rb_tree_nocmp_init(&tree);
  if (RB_TREE_NOCMP_FIND(&tree, cmp_asym, NULL, 2) != NULL)
  {
    printf("1\n");
    abort();
  }
  val = 2;
  if (rb_tree_nocmp_find_asym(&tree, cmp_asym_void, NULL, &val) != NULL)
  {
    printf("1\n");
    abort();
  }
  if (my_tree_nocmp_find(&tree, 2) != NULL)
  {
    printf("1\n");
    abort();
  }
  if (insert_deterministic(&tree, 43) != 0)
  {
    printf("1.5\n");
    abort();
  }
  if (insert_deterministic(&tree, 23) != 0)
  {
    printf("1.5\n");
    abort();
  }
  if (insert_deterministic(&tree, 5) != 0)
  {
    printf("1.5\n");
    abort();
  }
  if (insert_deterministic(&tree, 97) != 0)
  {
    printf("1.5\n");
    abort();
  }
  if (insert_deterministic(&tree, 22) != 0)
  {
    printf("1.5\n");
    abort();
  }
  if (insert_deterministic(&tree, 97) != -EEXIST)
  {
    printf("1.5\n");
    abort();
  }
  if (insert_deterministic(&tree, 30) != 0)
  {
    printf("1.5\n");
    abort();
  }
  if (insert_deterministic(&tree, 23) != -EEXIST)
  {
    printf("1.5\n");
    abort();
  }
  if (insert_deterministic(&tree, 79) != 0)
  {
    printf("1.5\n");
    abort();
  }
  if (insert_deterministic(&tree, 97) != -EEXIST)
  {
    printf("1.5\n");
    abort();
  }
  if (RB_TREE_NOCMP_FIND(&tree, cmp_asym, NULL, 43) == NULL)
  {
    printf("2\n");
    abort();
  }
  val = 43;
  if (rb_tree_nocmp_find_asym(&tree, cmp_asym_void, NULL, &val) == NULL)
  {
    printf("2\n");
    abort();
  }
  if (RB_TREE_NOCMP_FIND(&tree, cmp_asym, NULL, 23) == NULL)
  {
    printf("2\n");
    abort();
  }
  val = 23;
  if (rb_tree_nocmp_find_asym(&tree, cmp_asym_void, NULL, &val) == NULL)
  {
    printf("2\n");
    abort();
  }
  if (RB_TREE_NOCMP_FIND(&tree, cmp_asym, NULL, 5) == NULL)
  {
    printf("2\n");
    abort();
  }
  val = 5;
  if (rb_tree_nocmp_find_asym(&tree, cmp_asym_void, NULL, &val) == NULL)
  {
    printf("2\n");
    abort();
  }
  if (RB_TREE_NOCMP_FIND(&tree, cmp_asym, NULL, 97) == NULL)
  {
    printf("2\n");
    abort();
  }
  val = 97;
  if (rb_tree_nocmp_find_asym(&tree, cmp_asym_void, NULL, &val) == NULL)
  {
    printf("2\n");
    abort();
  }
  if (RB_TREE_NOCMP_FIND(&tree, cmp_asym, NULL, 22) == NULL)
  {
    printf("2\n");
    abort();
  }
  val = 22;
  if (rb_tree_nocmp_find_asym(&tree, cmp_asym_void, NULL, &val) == NULL)
  {
    printf("2\n");
    abort();
  }
  if (RB_TREE_NOCMP_FIND(&tree, cmp_asym, NULL, 30) == NULL)
  {
    printf("2\n");
    abort();
  }
  val = 30;
  if (rb_tree_nocmp_find_asym(&tree, cmp_asym_void, NULL, &val) == NULL)
  {
    printf("2\n");
    abort();
  }
  if (RB_TREE_NOCMP_FIND(&tree, cmp_asym, NULL, 79) == NULL)
  {
    printf("2\n");
    abort();
  }
  val = 79;
  if (rb_tree_nocmp_find_asym(&tree, cmp_asym_void, NULL, &val) == NULL)
  {
    printf("2\n");
    abort();
  }

  if (my_tree_nocmp_find(&tree, 43) == NULL)
  {
    printf("2\n");
    abort();
  }
  if (my_tree_nocmp_find(&tree, 23) == NULL)
  {
    printf("2\n");
    abort();
  }
  if (my_tree_nocmp_find(&tree, 5) == NULL)
  {
    printf("2\n");
    abort();
  }
  if (my_tree_nocmp_find(&tree, 97) == NULL)
  {
    printf("2\n");
    abort();
  }
  if (my_tree_nocmp_find(&tree, 22) == NULL)
  {
    printf("2\n");
    abort();
  }
  if (my_tree_nocmp_find(&tree, 30) == NULL)
  {
    printf("2\n");
    abort();
  }
  if (my_tree_nocmp_find(&tree, 79) == NULL)
  {
    printf("2\n");
    abort();
  }
  findperf1(&tree);
  findperf2(&tree);
  insperf1(&tree);
  insperf2(&tree);
}

int main(int argc, char **argv)
{
  struct rb_tree tree = {};
  int i;
  rb_tree_init(&tree, cmp, NULL);
  for (i = 0; i < 1000*1000; i++)
  {
    if (i % 1000 == 0)
    {
      printf("i = %d\n", i);
    }
    //print_tree(&tree);
    if (rand() % 2)
    {
      delete_random(&tree);
    }
    else
    {
      insert_random(&tree);
    }
    if (i % 1000 == 0 && !rb_tree_valid(&tree))
    {
      printf("invalid\n");
      print_tree(&tree);
      abort();
    }
  }
  nocmptest();
}
