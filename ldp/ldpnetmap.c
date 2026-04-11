#define NETMAP_WITH_LIBS
#define _GNU_SOURCE

#include <sys/poll.h>
#include <sys/socket.h>
#include <linux/ethtool.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "net/netmap_user.h"
#include "ldp.h"
#include "ldpnetmap.h"
#include "linkcommon.h"
#include "containerof.h"


struct ldp_in_queue_netmap {
  struct ldp_in_queue q;
  struct nm_desc *nmd;
};

struct ldp_out_queue_netmap {
  struct ldp_out_queue q;
  struct nm_desc *nmd;
};

static uint32_t ldp_in_queue_ring_size_netmap(struct ldp_in_queue *inq)
{
  struct ldp_in_queue_netmap *innmq;
  innmq = CONTAINER_OF(inq, struct ldp_in_queue_netmap, q);
  struct netmap_ring *rxring;
  rxring = NETMAP_RXRING(innmq->nmd->nifp, innmq->nmd->first_rx_ring);
  return rxring->num_slots;
}

static void ldp_in_queue_close_netmap(struct ldp_in_queue *inq)
{
  struct ldp_in_queue_netmap *innmq;
  innmq = CONTAINER_OF(inq, struct ldp_in_queue_netmap, q);
  nm_close(innmq->nmd);
  free(innmq);
}

static void ldp_out_queue_close_netmap(struct ldp_out_queue *outq)
{
  struct ldp_out_queue_netmap *outnmq;
  outnmq = CONTAINER_OF(outq, struct ldp_out_queue_netmap, q);
  nm_close(outnmq->nmd);
  free(outnmq);
}

static inline int nm_ldp_inject1(struct nm_desc *d, const void *buf, size_t sz)
{
  uint32_t ri = d->cur_tx_ring;
  struct netmap_ring *ring;
  uint32_t slotidx, bufidx;

  ring = NETMAP_TXRING(d->nifp, ri);
  if (nm_ring_empty(ring))
  {
    return 0;
  }
  slotidx = ring->cur;
  bufidx = ring->slot[slotidx].buf_idx;
  ring->slot[slotidx].len = sz;
  memcpy(NETMAP_BUF(ring, bufidx), buf, sz);
  slotidx = nm_ring_next(ring, slotidx);
  ring->head = slotidx;
  ring->cur = slotidx;
  return sz;
}

static inline int nm_ldp_inject_chunk1(struct nm_desc *d,
                                       struct ldp_chunkpacket *pkt)
{
  uint32_t ri = d->cur_tx_ring;
  struct netmap_ring *ring;
  uint32_t slotidx, bufidx;
  char *bufbase;
  size_t sz = 0;
  size_t i;

  ring = NETMAP_TXRING(d->nifp, ri);
  if (nm_ring_empty(ring))
  {
    return 0;
  }
  slotidx = ring->cur;
  bufidx = ring->slot[slotidx].buf_idx;
  bufbase = NETMAP_BUF(ring, bufidx);
  for (i = 0; i < pkt->iovlen; i++)
  {
    struct iovec *iov = &pkt->iov[i];
    memcpy(bufbase + sz, iov->iov_base, iov->iov_len);
    sz += iov->iov_len;
  }
  ring->slot[slotidx].len = sz;
  slotidx = nm_ring_next(ring, slotidx);
  ring->head = slotidx;
  ring->cur = slotidx;
  return sz;
}



static inline void nm_ldp_inject(struct nm_desc *nmd, void *data, size_t sz)
{
  if (likely(nm_ldp_inject1(nmd, data, sz) != 0))
  {
    return;
  }
  struct pollfd pollfd;
  pollfd.fd = nmd->fd;
  pollfd.events = POLLOUT;
  poll(&pollfd, 1, -1);
  nm_ldp_inject1(nmd, data, sz);
}

static inline void nm_ldp_inject_chunk(struct nm_desc *nmd,
                                       struct ldp_chunkpacket *pkt)
{
  if (likely(nm_ldp_inject_chunk1(nmd, pkt) != 0))
  {
    return;
  }
  struct pollfd pollfd;
  pollfd.fd = nmd->fd;
  pollfd.events = POLLOUT;
  poll(&pollfd, 1, -1);
  nm_ldp_inject_chunk1(nmd, pkt);
}

static void ldp_in_queue_deallocate_some_netmap(struct ldp_in_queue *inq,
                                                struct ldp_packet *pkts,
                                                int num)
{
  struct ldp_in_queue_netmap *innmq;
  int i;
  uint32_t next_head;
  innmq = CONTAINER_OF(inq, struct ldp_in_queue_netmap, q);
  struct netmap_ring *rxring;
  rxring = NETMAP_RXRING(innmq->nmd->nifp, innmq->nmd->first_rx_ring);
  if (num <= 0)
  {
    return;
  }
  next_head = rxring->head;
  for (i = 0; i < num; i++)
  {
    struct netmap_slot *slot = rxring->slot + next_head;
    if (slot->buf_idx != pkts[i].u.ancillary)
    {
      slot->buf_idx = pkts[i].u.ancillary;
      slot->flags |= NS_BUF_CHANGED;
    }
    next_head = nm_ring_next(rxring, next_head);
  }
  rxring->head = next_head;
}

static int ldp_in_queue_nextpkts_netmap(struct ldp_in_queue *inq,
                                        struct ldp_packet *pkts, int num)
{
  int i;
  struct ldp_in_queue_netmap *innmq;
  innmq = CONTAINER_OF(inq, struct ldp_in_queue_netmap, q);
  struct netmap_ring *rxring;
  uint32_t cur, tail;
  rxring = NETMAP_RXRING(innmq->nmd->nifp, innmq->nmd->first_rx_ring);
  cur = rxring->cur;
  tail = rxring->tail;
  for (i = 0; cur != tail && i < num; cur = nm_ring_next(rxring, cur))
  {
    struct netmap_slot *slot = rxring->slot + cur;
    char *buf = NETMAP_BUF(rxring, slot->buf_idx);
    pkts[i].data = buf;
    pkts[i].sz = slot->len;
    pkts[i].u.ancillary = slot->buf_idx;
    i++;
  }
  rxring->cur = cur;
  return i;
}

static int ldp_out_queue_inject_netmap(struct ldp_out_queue *outq,
                                       struct ldp_packet *packets, int num)
{
  int i;
  struct ldp_out_queue_netmap *outnmq;
  outnmq = CONTAINER_OF(outq, struct ldp_out_queue_netmap, q);
  for (i = 0; i < num; i++)
  {
    nm_ldp_inject(outnmq->nmd, packets[i].data, packets[i].sz);
  }
  return num;
}

static int ldp_out_queue_inject_chunk_netmap(struct ldp_out_queue *outq,
                                             struct ldp_chunkpacket *packets,
                                             int num)
{
  int i;
  struct ldp_out_queue_netmap *outnmq;
  outnmq = CONTAINER_OF(outq, struct ldp_out_queue_netmap, q);
  for (i = 0; i < num; i++)
  {
    nm_ldp_inject_chunk(outnmq->nmd, &packets[i]);
  }
  return num;
}

static int ldp_out_queue_txsync_netmap(struct ldp_out_queue *outq)
{
  struct ldp_out_queue_netmap *outnmq;
  outnmq = CONTAINER_OF(outq, struct ldp_out_queue_netmap, q);
  if (ioctl(outnmq->nmd->fd, NIOCTXSYNC, NULL) == -1)
  {
    return -1;
  }
  return 0;
}

static int check_channels(const char *name, int numinq, int numoutq)
{
  size_t rx, tx;
  struct ethtool_channels echannels = {};
  struct ifreq ifr = {};
  int fd;

  if (numinq < 0 || numoutq < 0)
  {
    abort();
  }

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0)
  {
    return 0;
  }
  echannels.cmd = ETHTOOL_GCHANNELS;
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
  ifr.ifr_data = (void*)&echannels; // cmd
  if (ioctl(fd, SIOCETHTOOL, &ifr) != 0)
  {
    int errnosave;
    if (errno == ENOTSUP && numinq == 1 && numoutq == 1)
    {
      close(fd);
      return 1;
    }
    errnosave = errno;
    close(fd);
    errno = errnosave;
    return 0;
  }
  close(fd);

  rx = echannels.rx_count;
  if (rx <= 0)
  {
    rx = echannels.combined_count;
  }
  if (rx != ((size_t)numinq))
  {
    errno = ECHRNG;
    return 0;
  }
  tx = echannels.tx_count;
  if (tx <= 0)
  {
    tx = echannels.combined_count;
  }
  if (tx < ((size_t)numoutq))
  {
    errno = ECHRNG;
    return 0;
  }
  return 1;
}

static int set_channels(const char *name, int numinq, int numoutq)
{
  size_t rx, tx;
  struct ethtool_channels echannels = {};
  struct ifreq ifr = {};
  int fd;
  int use_combined = 0;

  if (numinq < 0 || numoutq < 0)
  {
    abort();
  }

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0)
  {
    return 0;
  }
  echannels.cmd = ETHTOOL_GCHANNELS;
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
  ifr.ifr_data = (void*)&echannels; // cmd
  if (ioctl(fd, SIOCETHTOOL, &ifr) != 0)
  {
    int errnosave;
    if (errno == ENOTSUP && numinq == 1 && numoutq == 1)
    {
      close(fd);
      return 1;
    }
    errnosave = errno;
    close(fd);
    errno = errnosave;
    return 0;
  }

  rx = echannels.rx_count;
  if (rx <= 0)
  {
    rx = echannels.combined_count;
    use_combined = 1;
  }
  if (rx <= 0)
  {
    errno = ECHRNG;
    return 0;
  }
  tx = echannels.tx_count;
  if (tx <= 0)
  {
    tx = echannels.combined_count;
  }
  if (tx <= 0)
  {
    errno = ECHRNG;
    return 0;
  }
  if (use_combined && numoutq > numinq)
  {
    errno = ECHRNG;
    return 0;
  }
  if (use_combined)
  {
    echannels.combined_count = (uint32_t)numinq;
  }
  else
  {
    echannels.rx_count = (uint32_t)numinq;
    echannels.tx_count = (uint32_t)numoutq;
  }
  echannels.cmd = ETHTOOL_SCHANNELS;
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
  ifr.ifr_data = (void*)&echannels; // cmd
  if (ioctl(fd, SIOCETHTOOL, &ifr) != 0)
  {
    int errnosave;
    if (errno == ENOTSUP && (size_t)numinq == rx && (size_t)numoutq <= tx)
    {
      close(fd);
      return 1;
    }
    errnosave = errno;
    close(fd);
    errno = errnosave;
    return 0;
  }
  close(fd);
  return 1;
}

static int set_rss(const char *name, const struct rss_opts *rss)
{
  struct ethtool_rxnfc nfc = {};
  struct ifreq ifr = {};
  int fd;

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0)
  {
    return 0;
  }
  if (rss->udp4_set)
  {
    nfc.cmd = ETHTOOL_SRXFH;
    nfc.flow_type = UDP_V4_FLOW;
    nfc.data = 0;
    if (rss->udp4 & RSS_OPT_SRC_IP) nfc.data |= RXH_IP_SRC;
    if (rss->udp4 & RSS_OPT_DST_IP) nfc.data |= RXH_IP_DST;
    if (rss->udp4 & RSS_OPT_SRC_PORT) nfc.data |= RXH_L4_B_0_1;
    if (rss->udp4 & RSS_OPT_DST_PORT) nfc.data |= RXH_L4_B_2_3;
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
    ifr.ifr_data = (void*)&nfc; // cmd
    if (ioctl(fd, SIOCETHTOOL, &ifr) != 0)
    {
      int errnosave;
      errnosave = errno;
      close(fd);
      errno = errnosave;
      return 0;
    }
  }
  if (rss->udp6_set)
  {
    nfc.cmd = ETHTOOL_SRXFH;
    nfc.flow_type = UDP_V6_FLOW;
    nfc.data = 0;
    if (rss->udp6 & RSS_OPT_SRC_IP) nfc.data |= RXH_IP_SRC;
    if (rss->udp6 & RSS_OPT_DST_IP) nfc.data |= RXH_IP_DST;
    if (rss->udp6 & RSS_OPT_SRC_PORT) nfc.data |= RXH_L4_B_0_1;
    if (rss->udp6 & RSS_OPT_DST_PORT) nfc.data |= RXH_L4_B_2_3;
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
    ifr.ifr_data = (void*)&nfc; // cmd
    if (ioctl(fd, SIOCETHTOOL, &ifr) != 0)
    {
      int errnosave;
      errnosave = errno;
      close(fd);
      errno = errnosave;
      return 0;
    }
  }

  if (rss->tcp4_set)
  {
    nfc.cmd = ETHTOOL_SRXFH;
    nfc.flow_type = TCP_V4_FLOW;
    nfc.data = 0;
    if (rss->tcp4 & RSS_OPT_SRC_IP) nfc.data |= RXH_IP_SRC;
    if (rss->tcp4 & RSS_OPT_DST_IP) nfc.data |= RXH_IP_DST;
    if (rss->tcp4 & RSS_OPT_SRC_PORT) nfc.data |= RXH_L4_B_0_1;
    if (rss->tcp4 & RSS_OPT_DST_PORT) nfc.data |= RXH_L4_B_2_3;
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
    ifr.ifr_data = (void*)&nfc; // cmd
    if (ioctl(fd, SIOCETHTOOL, &ifr) != 0)
    {
      int errnosave;
      errnosave = errno;
      close(fd);
      errno = errnosave;
      return 0;
    }
  }
  if (rss->tcp6_set)
  {
    nfc.cmd = ETHTOOL_SRXFH;
    nfc.flow_type = TCP_V6_FLOW;
    nfc.data = 0;
    if (rss->tcp6 & RSS_OPT_SRC_IP) nfc.data |= RXH_IP_SRC;
    if (rss->tcp6 & RSS_OPT_DST_IP) nfc.data |= RXH_IP_DST;
    if (rss->tcp6 & RSS_OPT_SRC_PORT) nfc.data |= RXH_L4_B_0_1;
    if (rss->tcp6 & RSS_OPT_DST_PORT) nfc.data |= RXH_L4_B_2_3;
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
    ifr.ifr_data = (void*)&nfc; // cmd
    if (ioctl(fd, SIOCETHTOOL, &ifr) != 0)
    {
      int errnosave;
      errnosave = errno;
      close(fd);
      errno = errnosave;
      return 0;
    }
  }

  if (rss->ipv4_set)
  {
    nfc.cmd = ETHTOOL_SRXFH;
    nfc.flow_type = IPV4_FLOW;
    nfc.data = 0;
    if (rss->ipv4 & RSS_OPT_SRC_IP) nfc.data |= RXH_IP_SRC;
    if (rss->ipv4 & RSS_OPT_DST_IP) nfc.data |= RXH_IP_DST;
    if (rss->ipv4 & RSS_OPT_SRC_PORT) nfc.data |= RXH_L4_B_0_1;
    if (rss->ipv4 & RSS_OPT_DST_PORT) nfc.data |= RXH_L4_B_2_3;
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
    ifr.ifr_data = (void*)&nfc; // cmd
    if (ioctl(fd, SIOCETHTOOL, &ifr) != 0)
    {
      int errnosave;
      errnosave = errno;
      close(fd);
      errno = errnosave;
      return 0;
    }
  }
  if (rss->ipv6_set)
  {
    nfc.cmd = ETHTOOL_SRXFH;
    nfc.flow_type = IPV6_FLOW;
    nfc.data = 0;
    if (rss->ipv6 & RSS_OPT_SRC_IP) nfc.data |= RXH_IP_SRC;
    if (rss->ipv6 & RSS_OPT_DST_IP) nfc.data |= RXH_IP_DST;
    if (rss->ipv6 & RSS_OPT_SRC_PORT) nfc.data |= RXH_L4_B_0_1;
    if (rss->ipv6 & RSS_OPT_DST_PORT) nfc.data |= RXH_L4_B_2_3;
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
    ifr.ifr_data = (void*)&nfc; // cmd
    if (ioctl(fd, SIOCETHTOOL, &ifr) != 0)
    {
      int errnosave;
      errnosave = errno;
      close(fd);
      errno = errnosave;
      return 0;
    }
  }

  close(fd);
  return 1;
}

struct ldp_interface *
ldp_interface_open_netmap(const char *name, int numinq, int numoutq,
                          const struct ldp_interface_settings *settings)
{
  char nmifnamebuf[1024] = {0};
  struct ldp_interface *intf = NULL;
  struct ldp_in_queue **inqs = NULL;
  struct ldp_out_queue **outqs = NULL;
  struct nmreq nmr;
  int i;
  int max;
  int errnosave;
  const char *devname = NULL;
  if (numinq < 0 || numoutq < 0 || numinq > 1024*1024 || numoutq > 1024*1024)
  {
    abort();
  }
  if (strncmp(name, "netmap:", 7) == 0)
  {
    devname = name + 7;
    if (!set_channels(devname, numinq, numoutq))
    {
      // errno already set
      return NULL;
    }
    if (!check_channels(devname, numinq, numoutq))
    {
      // errno already set
      return NULL;
    }
    if (settings && settings->rss_set)
    {
        if (!set_rss(devname, &settings->rss))
        {
          // errno already set
          return NULL;
        }
    }
  }
  else if (strncmp(name, "vale", 4) == 0)
  {
    // nop
  }
  else
  {
    errno = EINVAL;
    return NULL;
  }
  max = numinq;
  if (max < numoutq)
  {
    max = numoutq;
  }
  intf = malloc(sizeof(*intf));
  if (intf == NULL)
  {
    errno = ENOMEM;
    return NULL;
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
  for (i = 0; i < numinq; i++)
  {
    inqs[i] = NULL;
  }
  outqs = malloc(((unsigned)numoutq)*sizeof(*outqs));
  if (outqs == NULL)
  {
    errno = ENOMEM;
    goto err;
  }
  for (i = 0; i < numoutq; i++)
  {
    outqs[i] = NULL;
  }
  for (i = 0; i < numinq; i++)
  {
    struct ldp_in_queue_netmap *innmq;
    innmq = malloc(sizeof(*innmq));
    if (innmq == NULL)
    {
      errno = ENOMEM;
      goto err;
    }
    inqs[i] = &innmq->q;
  }
  if (settings && settings->mtu_set && devname)
  {
    // Do this early in case we can't do it for a running interface
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
      // errno set already
      goto err;
    }
    if (ldp_set_mtu(sockfd, devname, settings->mtu) != 0)
    {
      // errno set already
      errnosave = errno;
      close(sockfd);
      errno = errnosave;
      goto err;
    }
    close(sockfd);
  }
  for (i = 0; i < numoutq; i++)
  {
    struct ldp_out_queue_netmap *outnmq;
    outnmq = malloc(sizeof(*outnmq));
    if (outnmq == NULL)
    {
      errno = ENOMEM;
      goto err;
    }
    outqs[i] = &outnmq->q;
  }
  for (i = 0; i < numinq; i++)
  {
    struct ldp_in_queue_netmap *innmq;
    memset(&nmr, 0, sizeof(nmr));
    nmr.nr_tx_rings = max;
    nmr.nr_rx_rings = max;
    nmr.nr_flags = NR_REG_ONE_NIC;
    nmr.nr_ringid = i | NETMAP_NO_TX_POLL;
    int nr_rx_slots_tmp = ldp_config_get_global()->netmap_nr_rx_slots;
    int nr_tx_slots_tmp = ldp_config_get_global()->netmap_nr_tx_slots;
    if (nr_rx_slots_tmp < 0 || nr_tx_slots_tmp < 0)
    {
      abort();
    }
    nmr.nr_rx_slots = (unsigned)nr_rx_slots_tmp;
    nmr.nr_tx_slots = (unsigned)nr_tx_slots_tmp;
    snprintf(nmifnamebuf, sizeof(nmifnamebuf), "%s-%d", name, i);
    innmq = CONTAINER_OF(inqs[i], struct ldp_in_queue_netmap, q);
    innmq->nmd = nm_open(nmifnamebuf, &nmr, 0, NULL);
    innmq->q.nextpkts = ldp_in_queue_nextpkts_netmap;
    innmq->q.nextpkts_ts = NULL;
    innmq->q.poll = ldp_in_queue_poll;
    innmq->q.eof = NULL;
    innmq->q.close = ldp_in_queue_close_netmap;
    innmq->q.deallocate_all = NULL;
    innmq->q.deallocate_some = ldp_in_queue_deallocate_some_netmap;
    innmq->q.ring_size = ldp_in_queue_ring_size_netmap;
    if (innmq->nmd == NULL)
    {
      while (--i >= 0)
      {
        innmq = CONTAINER_OF(inqs[i], struct ldp_in_queue_netmap, q);
        nm_close(innmq->nmd);
      }
      goto err;
    }
    if (innmq->nmd->first_rx_ring != innmq->nmd->last_rx_ring)
    {
      abort();
    }
    innmq->q.fd = innmq->nmd->fd;
  }
  for (i = 0; i < numoutq; i++)
  {
    struct ldp_out_queue_netmap *outnmq;
    memset(&nmr, 0, sizeof(nmr));
    nmr.nr_tx_rings = max;
    nmr.nr_rx_rings = max;
    nmr.nr_flags = NR_REG_ONE_NIC;
    nmr.nr_ringid = i | NETMAP_NO_TX_POLL;
    int nr_rx_slots_tmp = ldp_config_get_global()->netmap_nr_rx_slots;
    int nr_tx_slots_tmp = ldp_config_get_global()->netmap_nr_tx_slots;
    if (nr_rx_slots_tmp < 0 || nr_tx_slots_tmp < 0)
    {
      abort();
    }
    nmr.nr_rx_slots = (unsigned)nr_rx_slots_tmp;
    nmr.nr_tx_slots = (unsigned)nr_tx_slots_tmp;
    snprintf(nmifnamebuf, sizeof(nmifnamebuf), "%s-%d", name, i);
    outnmq = CONTAINER_OF(outqs[i], struct ldp_out_queue_netmap, q);
    outnmq->nmd = nm_open(nmifnamebuf, &nmr, 0, NULL);
    outnmq->q.inject = ldp_out_queue_inject_netmap;
    outnmq->q.inject_dealloc = NULL;
    outnmq->q.inject_chunk = ldp_out_queue_inject_chunk_netmap;
    outnmq->q.txsync = ldp_out_queue_txsync_netmap;
    outnmq->q.close = ldp_out_queue_close_netmap;
    if (outnmq->nmd == NULL)
    {
      while (--i >= 0)
      {
        outnmq = CONTAINER_OF(outqs[i], struct ldp_out_queue_netmap, q);
        nm_close(outnmq->nmd);
      }
      for (i = 0; i < numinq; i++)
      {
        struct ldp_in_queue_netmap *innmq;
        innmq = CONTAINER_OF(inqs[i], struct ldp_in_queue_netmap, q);
        nm_close(innmq->nmd);
      }
      goto err;
    }
    if (outnmq->nmd->first_tx_ring != outnmq->nmd->last_tx_ring)
    {
      abort();
    }
    if (outnmq->nmd->first_tx_ring != outnmq->nmd->cur_tx_ring)
    {
      abort();
    }
    outnmq->q.fd = outnmq->nmd->fd;
  }
  intf->num_inq = numinq;
  intf->num_outq = numoutq;
  intf->inq = inqs;
  intf->outq = outqs;
  snprintf(intf->name, sizeof(intf->name), "%s", name);
  if (settings && settings->promisc_set)
  {
    ldp_interface_set_promisc_mode(intf, settings->promisc_on);
  }
  if (settings && settings->allmulti_set)
  {
    ldp_interface_set_allmulti(intf, settings->allmulti_on);
  }
  if (settings && settings->mac_addr_set)
  {
    ldp_interface_set_mac_addr(intf, settings->mac);
  }
  return intf;

err:
  errnosave = errno;
  if (inqs)
  {
    for (i = 0; i < numinq; i++)
    {
      if (inqs[i] != NULL)
      {
        struct ldp_in_queue_netmap *innmq;
        innmq = CONTAINER_OF(inqs[i], struct ldp_in_queue_netmap, q);
        free(innmq);
      }
    }
  }
  if (outqs)
  {
    for (i = 0; i < numoutq; i++)
    {
      if (outqs[i] != NULL)
      {
        struct ldp_out_queue_netmap *outnmq;
        outnmq = CONTAINER_OF(outqs[i], struct ldp_out_queue_netmap, q);
        free(outnmq);
      }
    }
  }
  free(inqs);
  free(outqs);
  free(intf);
  errno = errnosave;
  return NULL;
}
