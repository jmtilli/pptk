#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include "ldp.h"
#include "ldppcap.h"
#include "mypcapjoker.h"
#include "mypcapng.h"
#include "mypcap.h"
#include "containerof.h"
#include "linkedlist.h"


struct ldp_in_queue_pcap {
  struct ldp_in_queue q;
  char *ifname;
  void **bufs;
  size_t *bufcapacities;
  size_t num_bufs;
  size_t buf_start;
  size_t buf_end;
  struct ldp_capture_shared_in_pcap *regular;
};

static uint32_t ldp_in_queue_ring_size_pcap(struct ldp_in_queue *inq)
{
  struct ldp_in_queue_pcap *inpcap;
  inpcap = CONTAINER_OF(inq, struct ldp_in_queue_pcap, q);
  return inpcap->num_bufs;
}

struct ldp_out_queue_pcap {
  struct ldp_out_queue q;
  char *ifname;
  struct ldp_capture_shared_out_pcap *regular;
  struct ldp_capture_shared_out_pcapng *ng;
};

struct ldp_capture_ctx {
  struct linked_list_head shared_in_pcaps;
  struct linked_list_head shared_out_pcaps;
  struct linked_list_head shared_out_pcapngs;
};

struct ldp_capture_ctx ctx = {
  .shared_in_pcaps = {{.prev = &ctx.shared_in_pcaps.node,
                       .next = &ctx.shared_in_pcaps.node}},
  .shared_out_pcaps = {{.prev = &ctx.shared_out_pcaps.node,
                        .next = &ctx.shared_out_pcaps.node}},
  .shared_out_pcapngs = {{.prev = &ctx.shared_out_pcapngs.node,
                          .next = &ctx.shared_out_pcapngs.node}}
};

struct ldp_capture_shared_in_pcap {
  pthread_mutex_t mtx;
  char *fname;
  int buf_valid;
  void *buf;
  size_t bufcapacity;
  size_t len;
  size_t snap;
  const char *bufifname;
  uint64_t time64;
  int eof;
  int refc;
  struct linked_list_node node;
  struct pcap_joker_ctx ctx;
};

static struct ldp_capture_shared_in_pcap *create_in(const char *fname,
                                                    const char *jokerifname)
{
  char *fname2;
  struct linked_list_node *it;
  struct ldp_capture_shared_in_pcap *pcap;
  fname2 = strdup(fname);
  LINKED_LIST_FOR_EACH(it, &ctx.shared_in_pcaps)
  {
    pcap = CONTAINER_OF(it, struct ldp_capture_shared_in_pcap, node);
    if (strcmp(pcap->fname, fname2) == 0)
    {
      pcap->refc++;
      free(fname2);
      return pcap;
    }
  }
  pcap = malloc(sizeof(*pcap));
  pcap->fname = fname2;
  pcap->buf_valid = 0;
  pcap->buf = NULL;
  pcap->bufcapacity = 0;
  pcap->len = 0;
  pcap->snap = 0;
  pcap->time64 = 0;
  pcap->bufifname = NULL;
  pcap->eof = 0;
  if (pcap_joker_ctx_init(&pcap->ctx, fname2, 1, jokerifname) != 0)
  {
    free(pcap);
    free(fname2);
    return NULL;
  }
  pthread_mutex_init(&pcap->mtx, NULL);
  linked_list_add_tail(&pcap->node, &ctx.shared_in_pcaps);
  pcap->refc = 1;
  return pcap;
}

struct ldp_capture_shared_out_pcap {
  pthread_mutex_t mtx;
  const char *fname;
  struct linked_list_node node;
  struct pcap_out_ctx ctx;
  int refc;
};

static struct ldp_capture_shared_out_pcap *create_out(const char *fname)
{
  char *fname2;
  struct linked_list_node *it;
  struct ldp_capture_shared_out_pcap *pcap;
  fname2 = strdup(fname);
  LINKED_LIST_FOR_EACH(it, &ctx.shared_out_pcaps)
  {
    pcap = CONTAINER_OF(it, struct ldp_capture_shared_out_pcap, node);
    if (strcmp(pcap->fname, fname2) == 0)
    {
      pcap->refc++;
      return pcap;
    }
  }
  pcap = malloc(sizeof(*pcap));
  pcap->fname = fname2;
  if (pcap_out_ctx_init(&pcap->ctx, fname2) != 0)
  {
    free(pcap);
    return NULL;
  }
  pthread_mutex_init(&pcap->mtx, NULL);
  linked_list_add_tail(&pcap->node, &ctx.shared_out_pcaps);
  pcap->refc = 1;
  return pcap;
}

struct ldp_capture_shared_out_pcapng {
  pthread_mutex_t mtx;
  const char *fname;
  struct linked_list_node node;
  struct pcapng_out_ctx ctx;
  int refc;
};

static struct ldp_capture_shared_out_pcapng *create_out_ng(const char *fname)
{
  char *fname2;
  struct linked_list_node *it;
  struct ldp_capture_shared_out_pcapng *pcap;
  fname2 = strdup(fname);
  LINKED_LIST_FOR_EACH(it, &ctx.shared_out_pcapngs)
  {
    pcap = CONTAINER_OF(it, struct ldp_capture_shared_out_pcapng, node);
    if (strcmp(pcap->fname, fname2) == 0)
    {
      pcap->refc++;
      return pcap;
    }
  }
  pcap = malloc(sizeof(*pcap));
  pcap->fname = fname2;
  if (pcapng_out_ctx_init(&pcap->ctx, fname2) != 0)
  {
    free(pcap);
    return NULL;
  }
  pthread_mutex_init(&pcap->mtx, NULL);
  linked_list_add_tail(&pcap->node, &ctx.shared_out_pcapngs);
  pcap->refc = 1;
  return pcap;
}

static void ldp_in_queue_close_pcap(struct ldp_in_queue *inq)
{
  struct ldp_in_queue_pcap *inpcapq;
  size_t j;
  inpcapq = CONTAINER_OF(inq, struct ldp_in_queue_pcap, q);
  for (j = 0; j < inpcapq->num_bufs; j++)
  {
    free(inpcapq->bufs[j]);
  }
  free(inpcapq->bufs);
  free(inpcapq->ifname);
  free(inpcapq->bufcapacities);
  if (inpcapq->regular != NULL)
  {
    inpcapq->regular->refc--;
    if (inpcapq->regular->refc == 0)
    {
      struct linked_list_node *it;
      LINKED_LIST_FOR_EACH(it, &ctx.shared_in_pcaps)
      {
        struct ldp_capture_shared_in_pcap *pcap =
          CONTAINER_OF(it, struct ldp_capture_shared_in_pcap, node);
        if (pcap == inpcapq->regular)
        {
          linked_list_delete(it);
          pcap_joker_ctx_free(&pcap->ctx);
          free(pcap->buf);
          free(pcap->fname);
          free(pcap);
          break;
        }
      }
    }
  }
  free(inpcapq);
}

static void ldp_out_queue_close_pcap(struct ldp_out_queue *outq)
{
  struct ldp_out_queue_pcap *outpcapq;
  outpcapq = CONTAINER_OF(outq, struct ldp_out_queue_pcap, q);
  free(outpcapq->ifname);
  free(outpcapq);
}

static void
ldp_in_queue_deallocate_some_pcap(struct ldp_in_queue *inq,
                                    struct ldp_packet *pkts, int num)
{
  int i;
  size_t new_end;
  struct ldp_in_queue_pcap *inpcap;
  inpcap = CONTAINER_OF(inq, struct ldp_in_queue_pcap, q);
  if (num <= 0)
  {
    return;
  }
  new_end = inpcap->buf_end;
  for (i = 0; i < num; i++)
  {
    inpcap->bufs[new_end] = pkts[i].data;
    inpcap->bufcapacities[new_end] = pkts[i].u.ancillarysz;
    new_end++;
    if (new_end >= inpcap->num_bufs)
    {
      new_end = 0;
    }
  }
  inpcap->buf_end = new_end;
}


static void ldp_in_queue_intern(struct ldp_in_queue_pcap *inq,
                                struct ldp_packet *pkt,
                                void *buf, size_t len, size_t snap)
{
  size_t min = len;
  if (min > snap)
  {
    min = snap;
  }
  int amnt_free = inq->buf_end - inq->buf_start - 1;
  if (amnt_free < 0)
  {
    if (inq->num_bufs > INT_MAX)
    {
      abort();
    }
    amnt_free += (int)inq->num_bufs;
  }
  if (amnt_free == 0)
  {
    abort();
  }
  if (inq->bufcapacities[inq->buf_start] < min)
  {
    void *buf2;
    size_t newcapacity = inq->bufcapacities[inq->buf_start]*2;
    if (newcapacity < min)
    {
      newcapacity = min;
    }
    buf2 = realloc(inq->bufs[inq->buf_start], newcapacity);
    if (buf2 == NULL)
    {
      abort(); // FIXME better error handling
    }
    inq->bufs[inq->buf_start] = buf2;
    inq->bufcapacities[inq->buf_start] = newcapacity;
  }
  memcpy(inq->bufs[inq->buf_start], buf, min);
  pkt->data = inq->bufs[inq->buf_start];
  pkt->sz = min;
  pkt->u.ancillarysz = inq->bufcapacities[inq->buf_start];
  inq->buf_start++;
  if (inq->buf_start >= inq->num_bufs)
  {
    inq->buf_start = 0;
  }
}

static int ldp_in_queue_eof_pcap(struct ldp_in_queue *inq)
{
  struct ldp_in_queue_pcap *inpcapq;
  inpcapq = CONTAINER_OF(inq, struct ldp_in_queue_pcap, q);
  if (inpcapq->regular == NULL)
  {
    return 1;
  }
  pthread_mutex_lock(&inpcapq->regular->mtx);
  if (inpcapq->regular->eof)
  {
    pthread_mutex_unlock(&inpcapq->regular->mtx);
    return 1;
  }
  pthread_mutex_unlock(&inpcapq->regular->mtx);
  return 0;
}

static int ldp_in_queue_nextpkts_ts_pcap(struct ldp_in_queue *inq,
                                         struct ldp_packet *pkts, int num,
                                         uint64_t *ts)
{
  struct ldp_in_queue_pcap *inpcapq;
  int ret;
  int amnt_free;

  inpcapq = CONTAINER_OF(inq, struct ldp_in_queue_pcap, q);

  if (inpcapq->regular == NULL)
  {
    return 0;
  }

  amnt_free = inpcapq->buf_end - inpcapq->buf_start - 1;
  if (amnt_free < 0)
  {
    if (inpcapq->num_bufs > INT_MAX)
    {
      abort();
    }
    amnt_free += (int)inpcapq->num_bufs;
  }
  if (amnt_free == 0)
  {
    if (ts)
    {
      *ts = inpcapq->regular->time64;
    }
    errno = ENOMEM;
    return -1;
  }

  if (num == 0)
  {
    if (ts)
    {
      *ts = inpcapq->regular->time64;
    }
    return 0;
  }

  pthread_mutex_lock(&inpcapq->regular->mtx);

  if (inpcapq->regular->buf_valid)
  {
    if (   inpcapq->ifname == NULL
        || strcmp(inpcapq->ifname, inpcapq->regular->bufifname) == 0)
    {
      ldp_in_queue_intern(inpcapq, pkts, inpcapq->regular->buf,
                          inpcapq->regular->len,
                          inpcapq->regular->snap);
      if (ts)
      {
        *ts = inpcapq->regular->time64;
      }
      inpcapq->regular->buf_valid = 0;
      pthread_mutex_unlock(&inpcapq->regular->mtx);
      return 1;
    }
  }
  ret = pcap_joker_ctx_read(&inpcapq->regular->ctx, 
                            &inpcapq->regular->buf,
                            &inpcapq->regular->bufcapacity,
                            &inpcapq->regular->len, &inpcapq->regular->snap,
                            &inpcapq->regular->time64,
                            &inpcapq->regular->bufifname);
  if (ret < 0)
  {
    inpcapq->regular->eof = 1;
    if (ts)
    {
      *ts = inpcapq->regular->time64;
    }
    pthread_mutex_unlock(&inpcapq->regular->mtx);
    errno = EIO;
    return -1;
  }
  if (ret == 0)
  {
    inpcapq->regular->eof = 1;
    if (ts)
    {
      *ts = inpcapq->regular->time64;
    }
    pthread_mutex_unlock(&inpcapq->regular->mtx);
    return 0;
  }
  if (   inpcapq->ifname == NULL
      || strcmp(inpcapq->ifname, inpcapq->regular->bufifname) == 0)
  {
    ldp_in_queue_intern(inpcapq, pkts, inpcapq->regular->buf,
                        inpcapq->regular->len,
                        inpcapq->regular->snap);
    if (ts)
    {
      *ts = inpcapq->regular->time64;
    }
    inpcapq->regular->buf_valid = 0;
    pthread_mutex_unlock(&inpcapq->regular->mtx);
    return 1;
  }
  inpcapq->regular->buf_valid = 1;
  if (ts)
  {
    *ts = inpcapq->regular->time64;
  }
  pthread_mutex_unlock(&inpcapq->regular->mtx);
  return 0;
}

static int ldp_in_queue_nextpkts_pcap(struct ldp_in_queue *inq,
                                      struct ldp_packet *pkts, int num)
{
  return ldp_in_queue_nextpkts_ts_pcap(inq, pkts, num, NULL);
}

static int ldp_out_queue_inject_pcap(struct ldp_out_queue *outq,
                                     struct ldp_packet *packets, int num)
{
  struct ldp_out_queue_pcap *outpcapq;
  int ret;
  int err = 0;
  int i;

  outpcapq = CONTAINER_OF(outq, struct ldp_out_queue_pcap, q);

  if (num == 0 || (outpcapq->regular == NULL && outpcapq->ng == NULL))
  {
    return 0;
  }
  for (i = 0; i < num; i++)
  {
    if (outpcapq->regular != NULL)
    {
      pthread_mutex_lock(&outpcapq->regular->mtx);
      ret = pcap_out_ctx_write(&outpcapq->regular->ctx,
                               packets[i].data, 
                               packets[i].sz, 0);
      if (ret != 1)
      {
        errno = EIO;
        err = -1;
      }
      pthread_mutex_unlock(&outpcapq->regular->mtx);
    }
    if (outpcapq->ng != NULL)
    {
      pthread_mutex_lock(&outpcapq->ng->mtx);
      ret = pcapng_out_ctx_write(&outpcapq->ng->ctx,
                                 packets[i].data, 
                                 packets[i].sz, 0, outpcapq->ifname);
      if (ret != 1)
      {
        errno = EIO;
        err = -1;
      }
      pthread_mutex_unlock(&outpcapq->ng->mtx);
    }
    if (err)
    {
      return (i == 0) ? err : i;
    }
  }
  return num;
}

static int ldp_out_queue_inject_chunk_pcap(struct ldp_out_queue *outq,
                                           struct ldp_chunkpacket *packets,
                                           int num)
{
  struct ldp_out_queue_pcap *outpcapq;
  int ret;
  int err = 0;
  int i;
  size_t j;
  size_t maxlen = 0;

  for (i = 0; i < num; i++)
  {
    struct ldp_chunkpacket *pkt = &packets[i];
    size_t curlen = 0;
    for (j = 0; j < pkt->iovlen; j++)
    {
      struct iovec *iov = &pkt->iov[j];
      curlen += iov->iov_len;
    }
    if (curlen > maxlen)
    {
      maxlen = curlen;
    }
  }

  char buf[maxlen];

  outpcapq = CONTAINER_OF(outq, struct ldp_out_queue_pcap, q);

  if (num == 0 || (outpcapq->regular == NULL && outpcapq->ng == NULL))
  {
    return 0;
  }
  for (i = 0; i < num; i++)
  {
    struct ldp_chunkpacket *pkt = &packets[i];
    size_t cur = 0;
    for (j = 0; j < pkt->iovlen; j++)
    {
      struct iovec *iov = &pkt->iov[j];
      memcpy(buf + cur, iov->iov_base, iov->iov_len);
      cur += iov->iov_len;
    }
    if (outpcapq->regular != NULL)
    {
      pthread_mutex_lock(&outpcapq->regular->mtx);
      ret = pcap_out_ctx_write(&outpcapq->regular->ctx, buf, cur, 0);
      if (ret != 1)
      {
        errno = EIO;
        err = -1;
      }
      pthread_mutex_unlock(&outpcapq->regular->mtx);
    }
    if (outpcapq->ng != NULL)
    {
      pthread_mutex_lock(&outpcapq->ng->mtx);
      ret = pcapng_out_ctx_write(&outpcapq->ng->ctx, buf, cur, 0,
                                 outpcapq->ifname);
      if (ret != 1)
      {
        errno = EIO;
        err = -1;
      }
      pthread_mutex_unlock(&outpcapq->ng->mtx);
    }
    if (err)
    {
      return (i == 0) ? err : i;
    }
  }
  return num;
}

static int ldp_out_queue_txsync_pcap(struct ldp_out_queue *outq)
{
  return 0;
}

struct ldp_interface *
ldp_interface_open_pcap(const char *name, int numinq, int numoutq,
                        const struct ldp_interface_settings *settings)
{
  struct ldp_interface *intf = NULL;
  struct ldp_in_queue **inqs = NULL;
  struct ldp_out_queue **outqs = NULL;
  size_t j;
  char *name2 = NULL;
  char *tok, *end, *tok2, *end2;
  char *inname = NULL;
  char *inifname = NULL;
  char *outname = NULL;
  char *outifname = strdup("pcap");
  char *outngname = NULL;
  const char *jokerifname = "pcap";
  int i;
  int errnosave;

  if (numinq < 0 || numoutq < 0 || numinq > 1024*1024 || numoutq > 1024*1024)
  {
    abort();
  }
  if (numinq <= 0 || numoutq <= 0 || numinq > 1 || numoutq > 1)
  {
    errno = ECHRNG;
    return NULL;
  }
  if (strncmp(name, "pcap:", 5) != 0)
  {
    errno = EINVAL;
    return NULL;
  }
  name2 = strdup(name + 5);
  if (name2 == NULL)
  {
    errno = ENOMEM;
    return NULL;
  }
  tok = name2;
  end = name2;
  while (tok != NULL)
  {
    strsep(&end, ":");
    //printf("tok: %s\n", tok);
    tok2 = tok;
    end2 = tok;
    strsep(&end2, "=");
    if (strcmp(tok2, "in") == 0)
    {
      inname = end2;
    }
    else if (strcmp(tok2, "out") == 0)
    {
      outname = end2;
    }
    else if (strcmp(tok2, "outng") == 0)
    {
      outngname = end2;
    }
    else if (strcmp(tok2, "inifname") == 0)
    {
      free(inifname);
      inifname = strdup(end2);
    }
    else if (strcmp(tok2, "outifname") == 0)
    {
      free(outifname);
      outifname = strdup(end2);
    }
#if 0
    else if (strcmp(tok2, "jokerifname") == 0)
    {
      jokerifname = end2;
    }
#endif
    //printf("split: %s %s\n", tok2, end2);
    tok = end;
  }
  intf = malloc(sizeof(*intf));
  if (intf == NULL)
  {
    errno = ENOMEM;
    goto err;
  }
  intf->promisc_mode_set = NULL;
  intf->promisc_mode_get = NULL;
  intf->allmulti_set = NULL;
  intf->allmulti_get = NULL;
  intf->mtu_set = NULL;
  intf->mtu_get = NULL;
  intf->link_wait = NULL;
  intf->link_status = NULL;
  intf->mac_addr = NULL;
  intf->mac_addr_set = NULL;
  inqs = malloc(((unsigned)numinq)*sizeof(*inqs));
  if (inqs == NULL)
  {
    errno = ENOMEM;
    goto err;
  }
  inqs[0] = NULL;
  outqs = malloc(((unsigned)numoutq)*sizeof(*outqs));
  if (outqs == NULL)
  {
    errno = ENOMEM;
    goto err;
  }
  outqs[0] = NULL;

  struct ldp_in_queue_pcap *inpcapq;
  for (i = 0; i < numinq; i++)
  {
    inpcapq = malloc(sizeof(*inpcapq));
    if (inpcapq == NULL)
    {
      errno = ENOMEM;
      goto err;
    }
    inqs[i] = &inpcapq->q;
    inpcapq->ifname = NULL;
    int num_bufs_tmp = ldp_config_get_global()->pcap_num_bufs;
    if (num_bufs_tmp < 0)
    {
      abort();
    }
    inpcapq->num_bufs = (unsigned)num_bufs_tmp;
    inpcapq->bufs = malloc(inpcapq->num_bufs*sizeof(*inpcapq->bufs));
    inpcapq->bufcapacities = malloc(inpcapq->num_bufs*sizeof(*inpcapq->bufcapacities));
    for (j = 0; j < inpcapq->num_bufs; j++)
    {
      inpcapq->bufs[j] = NULL;
      inpcapq->bufcapacities[j] = 0;
    }
    inpcapq->buf_start = 0;
    inpcapq->buf_end = 0;
    inpcapq->regular = NULL;
    if (inname)
    {
      inpcapq->regular = create_in(inname, jokerifname);
      if (inpcapq->regular == NULL)
      {
        errno = ENOENT;
        goto err;
      }
    }
    inpcapq->ifname = inifname;
    inpcapq->q.fd = -1;
    inpcapq->q.nextpkts = ldp_in_queue_nextpkts_pcap;
    inpcapq->q.nextpkts_ts = ldp_in_queue_nextpkts_ts_pcap;
    inpcapq->q.poll = ldp_in_queue_poll;
    inpcapq->q.eof = ldp_in_queue_eof_pcap;
    inpcapq->q.close = ldp_in_queue_close_pcap;
    inpcapq->q.deallocate_some = ldp_in_queue_deallocate_some_pcap;
    inpcapq->q.deallocate_all = NULL;
    inpcapq->q.ring_size = ldp_in_queue_ring_size_pcap;
  }
  for (i = 0; i < numoutq; i++)
  {
    struct ldp_out_queue_pcap *outpcapq;
    outpcapq = malloc(sizeof(*outpcapq));
    if (outpcapq == NULL)
    {
      errno = ENOMEM;
      goto err;
    }
    outqs[i] = &outpcapq->q;
    outpcapq->regular = NULL;
    if (outname)
    {
      outpcapq->regular = create_out(outname);
      if (outpcapq->regular == NULL)
      {
        errno = EPERM;
        goto err;
      }
    }
    outpcapq->ng = NULL;
    if (outngname)
    {
      outpcapq->ng = create_out_ng(outngname);
      if (outpcapq->ng == NULL)
      {
        errno = EPERM;
        goto err;
      }
    }
    outpcapq->ifname = outifname;
    outpcapq->q.fd = -1;
    outpcapq->q.inject = ldp_out_queue_inject_pcap;
    outpcapq->q.inject_dealloc = NULL;
    outpcapq->q.inject_chunk = ldp_out_queue_inject_chunk_pcap;
    outpcapq->q.txsync = ldp_out_queue_txsync_pcap;
    outpcapq->q.close = ldp_out_queue_close_pcap;
  }
  intf->num_inq = numinq;
  intf->num_outq = numoutq;
  intf->inq = inqs;
  intf->outq = outqs;
  snprintf(intf->name, sizeof(intf->name), "%s", name);
  free(name2);
  return intf;

err:
  errnosave = errno;
  if (inqs != NULL && inqs[0] != NULL)
  {
    free(CONTAINER_OF(inqs[0], struct ldp_in_queue_pcap, q));
  }
  if (outqs != NULL && outqs[0] != NULL)
  {
    free(CONTAINER_OF(outqs[0], struct ldp_out_queue_pcap, q));
  }
  free(intf);
  free(inqs);
  free(outqs);
  free(name2);
  errno = errnosave;
  return NULL;
}
