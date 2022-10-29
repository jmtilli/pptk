#define _GNU_SOURCE
#include <pthread.h>
#include "hashtable.h"
#include "linkedlist.h"
#include "hashlist.h"
#include "iphdr.h"
#include "containerof.h"
#include "siphash.h"
#include "hashseed.h"
#include "ipcksum.h"
#include <sys/poll.h>
#include "time64.h"
#include "ldp.h"

struct ldp_interface **intfs;
pthread_t *thrs;
struct thrctx *thrctxs;
size_t num_intfs;
size_t num_thrs;

struct hash_table table;

struct linked_list_head oldest_to_newest;

pthread_mutex_t gbl_mtx = PTHREAD_MUTEX_INITIALIZER;

struct thrctx {
  int id;
};

struct entry {
  struct hash_list_node e;
  struct linked_list_node n;
  char mac[6];
  int port;
  uint64_t time64;
  uint32_t bucket;
};

static inline uint32_t mac_hash(const char mac[6])
{
  return (uint32_t)siphash_buf(hash_seed_get(), mac, 6);
}

static inline uint32_t hash(struct entry *e)
{
  return mac_hash(e->mac);
}

static uint32_t mac_hash_fn(struct hash_list_node *e, void *userdata)
{
  return hash(CONTAINER_OF(e, struct entry, e));
}

static inline int fast_mac_equals(const char mac1[6], const char mac2[6])
{
  if (hdr_get32h(mac1) != hdr_get32h(mac2))
  {
    return 0;
  }
  if (hdr_get16h(mac1+4) != hdr_get16h(mac2+4))
  {
    return 0;
  }
  return 1;
}

static int port_get(const char mac[6])
{
  uint32_t hashval = mac_hash(mac);
  struct hash_list_node *x;
  int port = -1;

  hash_table_lock_bucket(&table, hashval);
  HASH_TABLE_FOR_EACH_POSSIBLE(&table, x, hashval)
  {
    struct entry *e = CONTAINER_OF(x, struct entry, e);
    if (fast_mac_equals(e->mac, mac))
    {
      port = e->port;
      break;
    }
  }
  hash_table_unlock_bucket(&table, hashval);
  return port;
}

#define TIMEOUT (300*1000*1000)

static void time_out(uint64_t time64)
{
  struct linked_list_node *n, *tmp;
  if (num_thrs > 1)
  {
    pthread_mutex_lock(&gbl_mtx);
  }
  LINKED_LIST_FOR_EACH_SAFE(n, tmp, &oldest_to_newest)
  {
    struct entry *e = CONTAINER_OF(n, struct entry, n);
    if (e->time64 + TIMEOUT < time64)
    {
      linked_list_delete(&e->n);
      printf("deleting entry with MAC %d:%d:%d:%d:%d:%d port %d from hash table due to timeout\n",
             (unsigned char)e->mac[0],
             (unsigned char)e->mac[1],
             (unsigned char)e->mac[2],
             (unsigned char)e->mac[3],
             (unsigned char)e->mac[4],
             (unsigned char)e->mac[5],
             e->port);
      hash_table_delete(&table, &e->e, mac_hash_fn(&e->e, NULL));
      free(e);
    }
    else
    {
      break;
    }
  }
  if (num_thrs > 1)
  {
    pthread_mutex_unlock(&gbl_mtx);
  }
}

static void port_put(const char mac[6], int port, uint64_t time64)
{
  uint32_t hashval = mac_hash(mac);
  struct hash_list_node *x;
  struct entry *e2 = NULL;

  hash_table_lock_bucket(&table, hashval);
  HASH_TABLE_FOR_EACH_POSSIBLE(&table, x, hashval)
  {
    struct entry *e = CONTAINER_OF(x, struct entry, e);
    if (fast_mac_equals(e->mac, mac))
    {
      e2 = e;
      e2->port = port;
      e2->time64 = time64;
      if (num_thrs > 1)
      {
        pthread_mutex_lock(&gbl_mtx);
      }
      linked_list_delete(&e2->n);
      linked_list_add_tail(&e2->n, &oldest_to_newest);
      if (num_thrs > 1)
      {
        pthread_mutex_unlock(&gbl_mtx);
      }
      break;
    }
  }
  if (e2 == NULL)
  {
    if (num_thrs > 1)
    {
      pthread_mutex_lock(&gbl_mtx);
    }
    if (table.itemcnt >= table.bucketcnt)
    {
      struct entry *e = CONTAINER_OF(oldest_to_newest.node.next, struct entry, n);
      linked_list_delete(&e->n);
      printf("deleting entry with MAC %d:%d:%d:%d:%d:%d port %d from hash table due to memory shortage\n",
             (unsigned char)e->mac[0],
             (unsigned char)e->mac[1],
             (unsigned char)e->mac[2],
             (unsigned char)e->mac[3],
             (unsigned char)e->mac[4],
             (unsigned char)e->mac[5],
             e->port);
      if (e->bucket >> table.mutex_shift == (hashval & (table.bucketcnt - 1)) >> table.mutex_shift)
      {
        hash_table_delete_already_bucket_locked(&table, &e->e);
      }
      else
      {
        hash_table_delete(&table, &e->e, hashval);
      }
      free(e);
    }
    e2 = malloc(sizeof(*e2));
    if (e2 == NULL)
    {
      goto out;
    }
    memcpy(e2->mac, mac, 6);
    e2->bucket = (uint32_t)(hashval & (table.bucketcnt - 1));
    e2->port = port;
    e2->time64 = time64;
    linked_list_add_tail(&e2->n, &oldest_to_newest);
    hash_table_add_nogrow_already_bucket_locked(&table, &e2->e, hashval);
    if (num_thrs > 1)
    {
      pthread_mutex_unlock(&gbl_mtx);
    }
    printf("adding entry with MAC %d:%d:%d:%d:%d:%d port %d to hash table due to learning\n",
           (unsigned char)e2->mac[0],
           (unsigned char)e2->mac[1],
           (unsigned char)e2->mac[2],
           (unsigned char)e2->mac[3],
           (unsigned char)e2->mac[4],
           (unsigned char)e2->mac[5],
           e2->port);
  }

out:
  hash_table_unlock_bucket(&table, hashval);
}

static void *thrfn(void *arg)
{
  struct thrctx *thrctx = arg;
  int id = thrctx->id;
  struct pollfd *pfds_template;
  struct pollfd *pfds;
  int do_poll = 1;
  size_t i, j, k;
  int num;
  struct ldp_packet pkt_tbl[256];
  struct ldp_packet pktout_tbl[num_intfs][256];
  int numout[num_intfs];

  pfds_template = malloc(sizeof(*pfds_template)*num_intfs);
  if (pfds_template == NULL)
  {
    printf("out of memory\n");
    exit(1);
  }
  pfds = malloc(sizeof(*pfds)*num_intfs);
  if (pfds == NULL)
  {
    printf("out of memory\n");
    exit(1);
  }
  for (k = 0; k < num_intfs; k++)
  {
    numout[k] = 0;
  }

  for (i = 0; i < num_intfs; i++)
  {
    pfds_template[i].fd = intfs[i]->inq[id]->fd;
    pfds_template[i].events = POLLIN;
    if (pfds_template[i].fd < 0)
    {
      do_poll = 0;
      break;
    }
  }

  for (;;)
  {
    for (k = 0; k < num_intfs; k++)
    {
      ldp_out_txsync(intfs[k]->outq[id]);
    }
    if (do_poll)
    {
      memcpy(pfds, pfds_template, sizeof(*pfds)*num_intfs);
      poll(pfds, num_intfs, 5);
    }
    if (id == 0)
    {
      time_out(gettime64());
    }
    for (i = 0; i < num_intfs; i++)
    {
      uint64_t time64;
      char last_mac[6] = {1,0,0,0,0,0};
      time64 = gettime64();
      num = ldp_in_nextpkts(intfs[i]->inq[id], pkt_tbl, sizeof(pkt_tbl)/sizeof(*pkt_tbl));
      if (num < 0)
      {
        num = 0;
      }
      for (j = 0; j < (size_t)num; j++)
      {
        int port;
        if (pkt_tbl[j].sz >= 12)
        {
          char *src = ether_src(pkt_tbl[j].data);
          if (!(src[0] & 1))
          {
            if (!fast_mac_equals(src, last_mac))
            {
              port_put(src, (int)i, time64);
              memcpy(last_mac, src, 6);
            }
          }
          port = port_get(ether_dst(pkt_tbl[j].data));
        }
        else
        {
          port = -1;
        }
        if (port == -1)
        {
          for (k = 0; k < num_intfs; k++)
          {
            if (k != i)
            {
              pktout_tbl[k][numout[k]++] = pkt_tbl[j];
            }
          }
        }
        else
        {
          pktout_tbl[port][numout[port]++] = pkt_tbl[j];
        }
      }
      for (k = 0; k < num_intfs; k++)
      {
        if (numout[k])
        {
          ldp_out_inject(intfs[k]->outq[id], pktout_tbl[k], numout[k]);
          numout[k] = 0;
        }
      }
      ldp_in_deallocate_some(intfs[i]->inq[id], pkt_tbl, num);
    }
  }
}

int main(int argc, char **argv)
{
  size_t i;
  int ret;

  hash_seed_init();
  linked_list_head_init(&oldest_to_newest);

  setlinebuf(stdout);

  if (argc < 4)
  {
    printf("usage: %s 3 vale0:1 vale1:1 ...\n", argv[0]);
    exit(1);
  }

  num_intfs = (size_t)(argc - 2);
  intfs = malloc(num_intfs*sizeof(*intfs));
  if (intfs == NULL)
  {
    printf("out of memory\n");
    exit(1);
  }
  int num_thrs_tmp = atoi(argv[1]);
  if (num_thrs_tmp < 1 || num_thrs_tmp > 1024)
  {
    printf("invalid thread count %s\n", argv[1]);
    exit(1);
  }
  num_thrs = (size_t)num_thrs_tmp;
  if (num_thrs > 1)
  {
    ret = hash_table_init_locked(&table, 8192, mac_hash_fn, NULL, 1);
  }
  else
  {
    ret = hash_table_init(&table, 8192, mac_hash_fn, NULL);
  }
  if (ret != 0)
  {
    printf("out of memory\n");
    exit(1);
  }
  thrs = malloc(num_thrs*sizeof(*thrs));
  if (thrs == NULL)
  {
    printf("out of memory\n");
    exit(1);
  }
  thrctxs = malloc(num_thrs*sizeof(*thrctxs));
  if (thrctxs == NULL)
  {
    printf("out of memory\n");
    exit(1);
  }

  for (i = 0; i < num_intfs; i++)
  {
    intfs[i] = ldp_interface_open(argv[2+i], (int)num_thrs, (int)num_thrs);
  }

  for (i = 0; i < num_thrs; i++)
  {
    thrctxs[i].id = (int)i;
    pthread_create(&thrs[i], NULL, thrfn, &thrctxs[i]);
  }
  for (i = 0; i < num_thrs; i++)
  {
    pthread_join(thrs[i], NULL);
  }

  return 0;
}
