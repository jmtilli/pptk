#ifndef _AVLTREE_H_
#define _AVLTREE_H_

struct avl_tree_node {
  int balance;
  struct avl_tree_node *left;
  struct avl_tree_node *right;
  struct avl_tree_node *parent;
};

typedef int (*avl_tree_cmp)(struct avl_tree_node *a, struct avl_tree_node *b, void *ud);

struct avl_tree {
  struct avl_tree_node *root;
  avl_tree_cmp cmp;
  void *cmp_userdata;
};
#define AVL_TREE_EMPTY {.cmp_userdata=(void*)0}

static inline void avl_tree_init(struct avl_tree *tree, avl_tree_cmp cmp, void *cmp_userdata)
{
  tree->root = NULL;
  tree->cmp = cmp;
  tree->cmp_userdata = cmp_userdata;
}

int avl_tree_valid(struct avl_tree *tree);

struct avl_tree_node *avl_tree_leftmost(struct avl_tree *tree);

struct avl_tree_node *avl_tree_rightmost(struct avl_tree *tree);

void avl_tree_insert(struct avl_tree *tree, struct avl_tree_node *node);

void avl_tree_delete(struct avl_tree *tree, struct avl_tree_node *node);

#endif
