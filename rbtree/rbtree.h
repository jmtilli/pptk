#ifndef _RBTREE_H_
#define _RBTREE_H_

#include <errno.h>

struct rb_tree_node {
  int is_black;
  struct rb_tree_node *left;
  struct rb_tree_node *right;
  struct rb_tree_node *parent;
};

typedef int (*rb_tree_cmp)(struct rb_tree_node *a, struct rb_tree_node *b, void *ud);
typedef int (*rb_tree_cmp_asym)(const void *a, struct rb_tree_node *b, void *ud);

struct rb_tree_nocmp {
  struct rb_tree_node *root;
};
#define RB_TREE_NOCMP_EMPTY {.root=(struct rb_tree_node*)0}

struct rb_tree {
  struct rb_tree_nocmp nocmp;
  rb_tree_cmp cmp;
  void *cmp_userdata;
};
#define RB_TREE_EMPTY {.cmp_userdata=(void*)0}

static inline void rb_tree_nocmp_init(struct rb_tree_nocmp *tree)
{
  tree->root = NULL;
}

static inline void rb_tree_init(struct rb_tree *tree, rb_tree_cmp cmp, void *cmp_userdata)
{
  rb_tree_nocmp_init(&tree->nocmp);
  tree->cmp = cmp;
  tree->cmp_userdata = cmp_userdata;
}

static inline struct rb_tree_node *rb_tree_nocmp_root(struct rb_tree_nocmp *tree)
{
  return tree->root;
}

static inline struct rb_tree_node *rb_tree_root(struct rb_tree *tree)
{
  return rb_tree_nocmp_root(&tree->nocmp);
}

int rb_tree_nocmp_valid(struct rb_tree_nocmp *tree);

static inline int rb_tree_valid(struct rb_tree *tree)
{
  return rb_tree_nocmp_valid(&tree->nocmp);
}

struct rb_tree_node *rb_tree_nocmp_leftmost(struct rb_tree_nocmp *tree);

static inline struct rb_tree_node *rb_tree_leftmost(struct rb_tree *tree)
{
  return rb_tree_nocmp_leftmost(&tree->nocmp);
}

struct rb_tree_node *rb_tree_nocmp_rightmost(struct rb_tree_nocmp *tree);

static inline struct rb_tree_node *rb_tree_rightmost(struct rb_tree *tree)
{
  return rb_tree_nocmp_rightmost(&tree->nocmp);
}

void rb_tree_nocmp_insert_repair(struct rb_tree_nocmp *tree, struct rb_tree_node *node);

static inline void rb_tree_insert_repair(struct rb_tree *tree, struct rb_tree_node *node)
{
  rb_tree_nocmp_insert_repair(&tree->nocmp, node);
}

void rb_tree_insert(struct rb_tree *tree, struct rb_tree_node *node);

void rb_tree_nocmp_delete(struct rb_tree_nocmp *tree, struct rb_tree_node *node);

static inline void rb_tree_delete(struct rb_tree *tree, struct rb_tree_node *node)
{
  rb_tree_nocmp_delete(&tree->nocmp, node);
}

#define RB_TREE_NOCMP_FIND(tree, cmp, cmp_userdata, tofind) \
  ({ \
    struct rb_tree_nocmp *__rb_tree_find_tree = (tree); \
    struct rb_tree_node *__rb_tree_find_node = __rb_tree_find_tree->root; \
    while (__rb_tree_find_node != NULL) \
    { \
      int __rb_tree_find_res = \
        (cmp)((tofind), __rb_tree_find_node, (cmp_userdata)); \
      if (__rb_tree_find_res < 0) \
      { \
        __rb_tree_find_node = __rb_tree_find_node->left; \
      } \
      else if (__rb_tree_find_res > 0) \
      { \
        __rb_tree_find_node = __rb_tree_find_node->right; \
      } \
      else \
      { \
        break; \
      } \
    } \
    __rb_tree_find_node; \
  })

/*
 * NB: this is slower than the macro version
 */
static inline struct rb_tree_node *rb_tree_nocmp_find(
  struct rb_tree_nocmp *tree, rb_tree_cmp cmp, void *cmp_userdata,
  struct rb_tree_node *tofind)
{
  struct rb_tree_node *node = tree->root;
  while (node != NULL)
  {
    int res = cmp(tofind, node, cmp_userdata);
    if (res < 0)
    {
      node = node->left;
    }
    else if (res > 0)
    {
      node = node->right;
    }
    else
    {
      break;
    }
  }
  return node;
}
static inline struct rb_tree_node *rb_tree_nocmp_find_asym(
  const struct rb_tree_nocmp *tree, rb_tree_cmp_asym cmp, void *cmp_userdata,
  const void *tofind)
{
  struct rb_tree_node *node = tree->root;
  while (node != NULL)
  {
    int res = cmp(tofind, node, cmp_userdata);
    if (res < 0)
    {
      node = node->left;
    }
    else if (res > 0)
    {
      node = node->right;
    }
    else
    {
      break;
    }
  }
  return node;
}

static inline int rb_tree_nocmp_insert_nonexist(
  struct rb_tree_nocmp *tree, rb_tree_cmp cmp, void *cmp_userdata,
  struct rb_tree_node *toinsert)
{
  void *cmp_ud = cmp_userdata;
  struct rb_tree_node *node = tree->root;
  int finalres = 0;

  toinsert->is_black = 0;
  toinsert->left = NULL;
  toinsert->right = NULL;
  if (node == NULL)
  {
    tree->root = toinsert;
    toinsert->parent = NULL;
    rb_tree_nocmp_insert_repair(tree, toinsert);
  }
  while (node != NULL)
  {
    int res = cmp(toinsert, node, cmp_ud);
    if (res < 0)
    {
      if (node->left == NULL)
      {
        node->left = toinsert;
        toinsert->parent = node;
        rb_tree_nocmp_insert_repair(tree, toinsert);
        break;
      }
      node = node->left;
    }
    else if (res > 0)
    {
      if (node->right == NULL)
      {
        node->right = toinsert;
        toinsert->parent = node;
        rb_tree_nocmp_insert_repair(tree, toinsert);
        break;
      }
      node = node->right;
    }
    else
    {
      finalres = -EEXIST;
      break;
    }
  }
  return finalres;
}

/*
 * NB: this is slower than the non-macro version
 */
#define RB_TREE_NOCMP_INSERT_NONEXIST(tree, cmp, cmp_userdata, toinsert) \
  ({ \
    struct rb_tree_nocmp *__rb_tree_insert_tree = (tree); \
    rb_tree_cmp __rb_tree_insert_cmp = (cmp); \
    void *__rb_tree_insert_cmp_ud = (cmp_userdata); \
    struct rb_tree_node *__rb_tree_insert_toinsert = (toinsert); \
    struct rb_tree_node *__rb_tree_insert_node = __rb_tree_insert_tree->root; \
    int __rb_tree_insert_finalres = 0; \
    __rb_tree_insert_toinsert->is_black = 0; \
    __rb_tree_insert_toinsert->left = NULL; \
    __rb_tree_insert_toinsert->right = NULL; \
    if (__rb_tree_insert_node == NULL) \
    { \
      __rb_tree_insert_tree->root = __rb_tree_insert_toinsert; \
      __rb_tree_insert_toinsert->parent = NULL; \
      rb_tree_nocmp_insert_repair(__rb_tree_insert_tree, \
                                  __rb_tree_insert_toinsert); \
    } \
    while (__rb_tree_insert_node != NULL) \
    { \
      int __rb_tree_insert_res = \
        __rb_tree_insert_cmp(__rb_tree_insert_toinsert, __rb_tree_insert_node, \
                             __rb_tree_insert_cmp_ud); \
      if (__rb_tree_insert_res < 0) \
      { \
        if (__rb_tree_insert_node->left == NULL) \
        { \
          __rb_tree_insert_node->left = __rb_tree_insert_toinsert; \
          __rb_tree_insert_toinsert->parent = __rb_tree_insert_node; \
          rb_tree_nocmp_insert_repair(__rb_tree_insert_tree, \
                                      __rb_tree_insert_toinsert); \
          break; \
        } \
        __rb_tree_insert_node = __rb_tree_insert_node->left; \
      } \
      else if (__rb_tree_insert_res > 0) \
      { \
        if (__rb_tree_insert_node->right == NULL) \
        { \
          __rb_tree_insert_node->right = __rb_tree_insert_toinsert; \
          __rb_tree_insert_toinsert->parent = __rb_tree_insert_node; \
          rb_tree_nocmp_insert_repair(__rb_tree_insert_tree, \
                                      __rb_tree_insert_toinsert); \
          break; \
        } \
        __rb_tree_insert_node = __rb_tree_insert_node->right; \
      } \
      else \
      { \
        __rb_tree_insert_finalres = -EEXIST; \
        break; \
      } \
    } \
    __rb_tree_insert_finalres; \
  })

#endif
