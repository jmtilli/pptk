#include <stdint.h>
#include "murmur.h"
#include "siphash.h"
#include "hashlist.h"
#include "rbtree.h"
#include "containerof.h"
#include "time64.h"

#define NUM 256

struct hash_sip_entry {
  struct hash_list_node node;
  uint32_t key;
};

struct hash_rb_entry {
  struct rb_tree_node node;
  uint32_t key;
};

static inline uint32_t murmur_weak(uint32_t key)
{
  return !!murmur32(0x12345678U, key);
}

static inline int cmp_asym(uint32_t i1, struct rb_tree_node *n2, void *ud)
{
  struct hash_rb_entry *e2 = CONTAINER_OF(n2, struct hash_rb_entry, node);
  if (i1 > e2->key)
  {
    return 1;
  }
  if (i1 < e2->key)
  {
    return -1;
  }
  return 0;
}
static inline int cmp_asym_void(const void *vi1, struct rb_tree_node *n2, void *ud)
{
  const uint32_t *i1 = vi1;
  struct hash_rb_entry *e2 = CONTAINER_OF(n2, struct hash_rb_entry, node);
  if (*i1 > e2->key)
  {
    return 1;
  }
  if (*i1 < e2->key)
  {
    return -1;
  }
  return 0;
}

static int cmp(struct rb_tree_node *n1, struct rb_tree_node *n2, void *ud)
{
  struct hash_rb_entry *e1 = CONTAINER_OF(n1, struct hash_rb_entry, node);
  struct hash_rb_entry *e2 = CONTAINER_OF(n2, struct hash_rb_entry, node);
  if (e1->key > e2->key)
  {
    return 1;
  }
  if (e1->key < e2->key)
  {
    return -1;
  }
  return 0;
}

static inline uint32_t siphash_strong(uint32_t key)
{
  static const char secret[16] = {0};
  return siphash64(secret, key);
}

struct hash_list_head bucketssip[NUM] = {};
struct rb_tree_nocmp bucketsrb[NUM] = {};
struct hash_sip_entry entriessip[NUM] = {};
struct hash_rb_entry entriesrb[NUM] = {};

int main(int argc, char **argv)
{
  size_t i;
  int j;
  uint64_t begin, end;
  begin = gettime64();
  for (i = 0; i < NUM; i++)
  {
    uint32_t hashval = siphash_strong(i);
    entriessip[i].key = i;
    hash_list_add_head(&entriessip[i].node, &bucketssip[hashval%NUM]);
  }
  end = gettime64();
  printf("sip-ins %g us\n", (double)(end - begin));
  begin = gettime64();
  for (i = 0; i < NUM; i++)
  {
    uint32_t hashval = murmur_weak(i);
    entriesrb[i].key = i;
    rb_tree_nocmp_insert_nonexist(&bucketsrb[hashval%NUM],
                                  cmp, NULL, &entriesrb[i].node);
  }
  end = gettime64();
  printf("rb-ins %g us\n", (double)(end - begin));
  begin = gettime64();
  for (j = 0; j < 1048576/NUM; j++)
  for (i = 0; i < NUM; i++)
  {
    uint32_t hashval = siphash_strong(i+NUM);
    struct hash_list_node *node;
    HASH_LIST_FOR_EACH(node, &bucketssip[hashval%NUM])
    {
      struct hash_sip_entry *e =
        CONTAINER_OF(node, struct hash_sip_entry, node);
      if (e->key == (uint32_t)(i+NUM))
      {
        abort();
      }
    }
  }
  end = gettime64();
  printf("sip-find %g us\n", (double)(end - begin));
  begin = gettime64();
  for (j = 0; j < 1048576/NUM; j++)
  for (i = 0; i < NUM; i++)
  {
    uint32_t hashval = murmur_weak(i+NUM);
    entriesrb[i].key = i;
    if (RB_TREE_NOCMP_FIND(&bucketsrb[hashval%NUM], cmp_asym, NULL, i + NUM) != NULL)
    {
      abort();
    }
  }
  end = gettime64();
  printf("rb-find %g us\n", (double)(end - begin));
  begin = gettime64();
  for (j = 0; j < 1048576/NUM; j++)
  for (i = 0; i < NUM; i++)
  {
    uint32_t hashval = murmur_weak(i+NUM);
    uint32_t iplusNUM = i+NUM;
    entriesrb[i].key = i;
    if (rb_tree_nocmp_find_asym(&bucketsrb[hashval%NUM], cmp_asym_void, NULL, &iplusNUM) != NULL)
    {
      abort();
    }
  }
  end = gettime64();
  printf("rb-find %g us\n", (double)(end - begin));
  return 0;
}
