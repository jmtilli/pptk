#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "avltree.h"
#include "containerof.h"
#include "avltreetest.h"

static int cmp(struct avl_tree_node *n1, struct avl_tree_node *n2, void *userdata)
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

static void insert_random(struct avl_tree *tree)
{
  struct test_entry *e = malloc(sizeof(*e));
  e->i = rand() % 100;
  //printf("inserting %d\n", e->i);
  avl_tree_insert(tree, &e->node);
}

static void __attribute__((unused)) delete_random(struct avl_tree *tree)
{
  struct avl_tree_node *node = tree->root;
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
      avl_tree_delete(tree, node);
      free(CONTAINER_OF(node, struct test_entry, node));
      return;
    }
    else if (tri == 1)
    {
      if (node->left == NULL)
      {
        //printf("deleting %d\n", CONTAINER_OF(node, struct test_entry, node)->i);
        avl_tree_delete(tree, node);
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
        avl_tree_delete(tree, node);
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

static void print_node(int level, struct avl_tree_node *node)
{
  struct test_entry *e = CONTAINER_OF(node, struct test_entry, node);
  indent(level);
  printf("balance: %d\n", node->balance);
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

void print_tree(struct avl_tree *tree)
{
  if (tree->root != NULL)
  {
    print_node(0, tree->root);
  }
}

int main(int argc, char **argv)
{
  struct avl_tree tree = AVL_TREE_EMPTY;
  int i;
  avl_tree_init(&tree, cmp, NULL);
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
      //insert_random(&tree);
    }
    else
    {
      insert_random(&tree);
    }
    if (i % 1000 == 0 && !avl_tree_valid(&tree))
    {
      printf("invalid\n");
      print_tree(&tree);
      abort();
    }
  }
}
