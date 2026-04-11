#define _GNU_SOURCE

#include <sys/poll.h>
#include <sys/socket.h>
#include <linux/ethtool.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <rte_mempool.h>
#include <rte_ethdev.h>
#include <rte_string_fns.h>
#include "ldp.h"
#include "ldpdpdk.h"
#include "linkcommon.h"
#include "containerof.h"

static int ldp_dpdk_interface_count = 0;

struct ldp_port_dpdk {
  int portid;
  int refc;
};

struct ldp_in_queue_dpdk {
  struct ldp_in_queue q;
  struct ldp_port_dpdk *port;
  int qid;
  int num_cache;
  struct rte_mbuf *cache[4];
};

static uint32_t ldp_in_queue_ring_size_dpdk(struct ldp_in_queue *inq)
{
  return ldp_config_get_global()->dpdk_pool_num / (2*ldp_dpdk_interface_count);
}

struct ldp_out_queue_dpdk {
  struct ldp_out_queue q;
  int qid;
  struct ldp_port_dpdk *port;
};

struct dpdk_ctx {
  int inited;
  struct rte_mempool *rte_mp;
};

struct dpdk_ctx dpdk_ctx;

static int init_dpdk_ctx(void)
{
  int ret;
  const char *cmdline1 = getenv("LDP_DPDK_ARGV");
  char *cmdline;
#if 0
  char *argv[] = {"foo",
                  /*
                  "-c",
                  "0xf",
                  "-n",
                  "4", */
                  "--vdev=eth_pcap0,iface=veth1",
                  "--vdev=eth_pcap1,iface=veth2",
                  NULL};
#endif
  int argc = 0;
  int len;
  int i;

  if (dpdk_ctx.inited)
  {
    return 0;
  }
  if (cmdline1 == NULL)
  {
    cmdline1 = "";
  }

  cmdline = strdup(cmdline1);
  len = strlen(cmdline);

  argc = 1;
  for (i = 0; i < len; i++)
  {
    if (isspace(cmdline[i]))
    {
      argc++;
    }
  }

  char *argv[argc];
  argc = rte_strsplit(cmdline, len, argv, argc, ' ');

  ret = rte_eal_init(argc, argv);
  if (ret < 0)
  {
    return -1;
  }
  dpdk_ctx.rte_mp = rte_pktmbuf_pool_create("mbuf_pool", ldp_config_get_global()->dpdk_pool_num, ldp_config_get_global()->dpdk_pool_cache_num, 0, ldp_config_get_global()->dpdk_pool_data_room, 0 /* socket id */);
  if (dpdk_ctx.rte_mp == NULL)
  {
    return -1;
  }
  dpdk_ctx.inited = 1;
  return 0;
}

static void ldp_in_queue_close_dpdk(struct ldp_in_queue *inq)
{
  struct ldp_in_queue_dpdk *innmq;
  int amnt_cache, i;

  innmq = CONTAINER_OF(inq, struct ldp_in_queue_dpdk, q);

  amnt_cache = innmq->num_cache;

  if (amnt_cache > 0)
  {
    for (i = 0; i < amnt_cache; i++)
    {
      struct rte_mbuf *mbuf = innmq->cache[i];
      rte_pktmbuf_free(mbuf);
    }
  }

  if (--innmq->port->refc == 0)
  {
    rte_eth_dev_stop(innmq->port->portid);
    ldp_dpdk_interface_count--;
    free(innmq->port);
  }

  free(innmq);
}

static void ldp_out_queue_close_dpdk(struct ldp_out_queue *outq)
{
  struct ldp_out_queue_dpdk *outnmq;
  outnmq = CONTAINER_OF(outq, struct ldp_out_queue_dpdk, q);
  if (--outnmq->port->refc == 0)
  {
    rte_eth_dev_stop(outnmq->port->portid);
    ldp_dpdk_interface_count--;
    free(outnmq->port);
  }
  free(outnmq);
}

static void
ldp_in_queue_deallocate_some_dpdk(struct ldp_in_queue *inq,
                                  struct ldp_packet *pkts, int num)
{
  int i;
  for (i = 0; i < num; i++)
  {
    rte_pktmbuf_free(pkts[i].u.ancillaryptr);
  }
}

static int ldp_in_queue_nextpkts_dpdk(struct ldp_in_queue *inq,
                                      struct ldp_packet *pkts, int num)
{
  int nb_rx;
  int max_num;
  int i;
  int amnt_cache;
  struct ldp_in_queue_dpdk *indpdkq;

  indpdkq = CONTAINER_OF(inq, struct ldp_in_queue_dpdk, q);
  amnt_cache = indpdkq->num_cache;

  if (amnt_cache > 0)
  {
    max_num = num;
    if (max_num > amnt_cache)
    {
      max_num = amnt_cache;
    }
    for (i = 0; i < max_num; i++)
    {
      struct rte_mbuf *mbuf = indpdkq->cache[i];
      pkts[i].data = rte_pktmbuf_mtod(mbuf, char *);
      pkts[i].sz = rte_pktmbuf_pkt_len(mbuf);
      pkts[i].u.ancillaryptr = mbuf;
    }
    for (i = max_num; i < amnt_cache; i++)
    {
      indpdkq->cache[i-max_num] = indpdkq->cache[i];
    }
    indpdkq->num_cache -= max_num;
    return max_num;
  }

  max_num = num;
  if (max_num < 4)
  {
    max_num = 4; // some drivers require a minimum burst size
  }
  struct rte_mbuf *local_pkts[max_num];
  nb_rx = rte_eth_rx_burst(indpdkq->port->portid, indpdkq->qid,
                           local_pkts, max_num);
  int nb_rx2 = nb_rx;
  if (nb_rx2 > num)
  {
    nb_rx2 = num;
  }
  for (i = 0; i < nb_rx2; i++)
  {
    struct rte_mbuf *mbuf = local_pkts[i];
    pkts[i].data = rte_pktmbuf_mtod(mbuf, char *);
    pkts[i].sz = rte_pktmbuf_pkt_len(mbuf);
    pkts[i].u.ancillaryptr = mbuf;
    //printf("packet received by DPDK, len %zu\n", pkts[i].sz);
  }
  for (i = nb_rx2; i < nb_rx; i++)
  {
    indpdkq->cache[i-nb_rx2] = local_pkts[i];
  }
  indpdkq->num_cache = nb_rx - nb_rx2;
  if (nb_rx2 < 0)
  {
    errno = -nb_rx2;
  }
  return nb_rx2;
}

static int ldp_out_queue_inject_dpdk(struct ldp_out_queue *outq,
                                     struct ldp_packet *packets, int num)
{
  struct rte_mbuf *tx_mbufs[num];
  int ret;
  int num2;
  int i;
  struct ldp_out_queue_dpdk *outdpdkq;
  int errnosave;

  outdpdkq = CONTAINER_OF(outq, struct ldp_out_queue_dpdk, q);

  if (rte_pktmbuf_alloc_bulk(dpdk_ctx.rte_mp, tx_mbufs, num))
  {
    errno = ENOMEM;
    return -1;
  }
  for (i = 0; i < num; i++)
  {
    char *data = rte_pktmbuf_append(tx_mbufs[i], packets[i].sz);
    if (data == NULL)
    {
      errno = EMSGSIZE;
      ret = -1;
      num2 = 0;
      goto out;
    }
    memcpy(data, packets[i].data, packets[i].sz);
  }

  ret = rte_eth_tx_burst(outdpdkq->port->portid, outdpdkq->qid,
                         tx_mbufs, num);
  num2 = ret;
  if (num2 < 0)
  {
    errno = -ret;
    num2 = 0;
  }

out:
  errnosave = errno;
  for (i = num2; i < num; i++)
  {
    rte_pktmbuf_free(tx_mbufs[i]);
  }
  errno = errnosave;
  return ret;
}

static int ldp_out_queue_inject_chunk_dpdk(struct ldp_out_queue *outq,
                                           struct ldp_chunkpacket *packets,
                                           int num)
{
  struct rte_mbuf *tx_mbufs[num];
  int ret = -1;
  int num2 = 0;
  int i;
  struct ldp_out_queue_dpdk *outdpdkq;
  int errnosave;

  outdpdkq = CONTAINER_OF(outq, struct ldp_out_queue_dpdk, q);

  if (rte_pktmbuf_alloc_bulk(dpdk_ctx.rte_mp, tx_mbufs, num))
  {
    errno = ENOMEM;
    return -1;
  }
  for (i = 0; i < num; i++)
  {
    struct ldp_chunkpacket *pkt = &packets[i];
    size_t sz = 0, cur = 0, j;
    for (j = 0; j < pkt->iovlen; j++)
    {
      struct iovec *iov = &pkt->iov[j];
      sz += iov->iov_len;
    }
    char *data = rte_pktmbuf_append(tx_mbufs[i], sz);
    if (data == NULL)
    {
      errno = EMSGSIZE;
      ret = -1;
      num2 = 0;
      goto out;
    }
    for (j = 0; j < pkt->iovlen; j++)
    {
      struct iovec *iov = &pkt->iov[j];
      memcpy(data + cur, iov->iov_base, iov->iov_len);
      cur += iov->iov_len;
    }
  }

  ret = rte_eth_tx_burst(outdpdkq->port->portid, outdpdkq->qid,
                         tx_mbufs, num);
  num2 = ret;
  if (num2 < 0)
  {
    errno = -ret;
    num2 = 0;
  }

out:
  errnosave = errno;
  for (i = num2; i < num; i++)
  {
    rte_pktmbuf_free(tx_mbufs[i]);
  }
  errno = errnosave;
  return ret;
}

static int ldp_out_queue_inject_dealloc_dpdk(struct ldp_in_queue *inq,
                                             struct ldp_out_queue *outq,
                                             struct ldp_packet *packets,
                                             int num)
{
  int i;
  int ret;
  struct ldp_out_queue_dpdk *outdpdkq;

  outdpdkq = CONTAINER_OF(outq, struct ldp_out_queue_dpdk, q);

  if (num <= 0)
  {
    return 0;
  }
  struct rte_mbuf *tx_mbufs[num];
  for (i = 0; i < num; i++)
  {
    tx_mbufs[i] = packets[i].u.ancillaryptr;
  }

  ret = rte_eth_tx_burst(outdpdkq->port->portid, outdpdkq->qid,
                         tx_mbufs, num);
  if (ret < 0)
  {
    errno = -ret;
  }
  return ret;
}

static int ldp_out_queue_txsync_dpdk(struct ldp_out_queue *outq)
{
  return 0;
}

struct ldp_interface *
ldp_interface_open_dpdk(const char *name, int numinq, int numoutq,
                        const struct ldp_interface_settings *settings)
{
  struct ldp_interface *intf = NULL;
  struct ldp_in_queue **inqs = NULL;
  struct ldp_out_queue **outqs = NULL;
  int i;
  int ret;
  struct ldp_port_dpdk *port = NULL;
  long int portid;
  char *endptr;
  struct rte_eth_conf port_conf = {};
  uint16_t nb_rxd = ldp_config_get_global()->dpdk_nb_rxd;
  uint16_t nb_txd = ldp_config_get_global()->dpdk_nb_txd;
  int started = 0;
  int errnosave;


  port_conf.rxmode.hw_strip_crc = 1;
  port_conf.txmode.mq_mode = ETH_MQ_TX_NONE;
  port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
  port_conf.rx_adv_conf.rss_conf.rss_hf =
    ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP | ETH_RSS_SCTP;

  if (numinq < 0 || numoutq < 0 || numinq > 1024*1024 || numoutq > 1024*1024)
  {
    abort();
  }
  portid = strtol(name, &endptr, 10);
  if (*name == '\0' || *endptr != '\0' || portid < 0 || portid > INT_MAX)
  {
    errno = EINVAL;
    return NULL;
  }

  if (init_dpdk_ctx() != 0)
  {
    errno = ENOMEM;
    return NULL;
  }
  
  if (!rte_eth_dev_is_valid_port(portid))
  {
    errno = ENODEV;
    return NULL;
  }
  ret = rte_eth_dev_configure(portid, numinq, numoutq, &port_conf);
  if (ret < 0)
  {
    errno = ECHRNG;
    return NULL;
  }
  ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
  if (ret < 0)
  {
    errno = -ret;
    return NULL;
  }
  for (i = 0; i < numinq; i++)
  {
    ret = rte_eth_rx_queue_setup(portid, i, nb_rxd,
                                 rte_eth_dev_socket_id(portid),
                                 NULL, dpdk_ctx.rte_mp);
    if (ret < 0)
    {
      errno = -ret;
      return NULL;
    }
  }
  for (i = 0; i < numinq; i++)
  {
    ret = rte_eth_tx_queue_setup(portid, i, nb_txd,
                                 rte_eth_dev_socket_id(portid), NULL);
    if (ret < 0)
    {
      errno = -ret;
      return NULL;
    }
  }
  if (settings && settings->mtu_set)
  {
    if (rte_eth_dev_set_mtu(portid, settings->mtu) != 0)
    {
      errno = -ret;
      return NULL;
    }
  }
  ret = rte_eth_dev_start(portid);
  if (ret < 0)
  {
    errno = EIO;
    return NULL;
  }
  started = 1;


  port = malloc(sizeof(*port));
  if (port == NULL)
  {
    errno = ENOMEM;
    goto err;
  }
  port->refc = numinq + numoutq;
  port->portid = portid;
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
  inqs = malloc(numinq*sizeof(*inqs));
  if (inqs == NULL)
  {
    errno = ENOMEM;
    goto err;
  }
  for (i = 0; i < numinq; i++)
  {
    inqs[i] = NULL;
  }
  outqs = malloc(numoutq*sizeof(*outqs));
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
    struct ldp_in_queue_dpdk *innmq;
    innmq = malloc(sizeof(*innmq));
    if (innmq == NULL)
    {
      errno = ENOMEM;
      goto err;
    }
    inqs[i] = &innmq->q;
  }
  for (i = 0; i < numoutq; i++)
  {
    struct ldp_out_queue_dpdk *outnmq;
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
    struct ldp_in_queue_dpdk *innmq;
    innmq = CONTAINER_OF(inqs[i], struct ldp_in_queue_dpdk, q);
    innmq->port = port;
    innmq->num_cache = 0;
    innmq->qid = i;
    innmq->q.nextpkts = ldp_in_queue_nextpkts_dpdk;
    innmq->q.nextpkts_ts = NULL;
    innmq->q.poll = ldp_in_queue_poll;
    innmq->q.eof = NULL;
    innmq->q.close = ldp_in_queue_close_dpdk;
    innmq->q.deallocate_all = NULL;
    innmq->q.deallocate_some = ldp_in_queue_deallocate_some_dpdk;
    innmq->q.ring_size = ldp_in_queue_ring_size_dpdk;
    innmq->q.fd = -1;
  }
  for (i = 0; i < numoutq; i++)
  {
    struct ldp_out_queue_dpdk *outnmq;
    outnmq = CONTAINER_OF(outqs[i], struct ldp_out_queue_dpdk, q);
    outnmq->port = port;
    outnmq->qid = i;
    outnmq->q.inject = ldp_out_queue_inject_dpdk;
    outnmq->q.inject_dealloc = ldp_out_queue_inject_dealloc_dpdk;
    outnmq->q.inject_chunk = ldp_out_queue_inject_chunk_dpdk;
    outnmq->q.txsync = ldp_out_queue_txsync_dpdk;
    outnmq->q.close = ldp_out_queue_close_dpdk;
    outnmq->q.fd = -1;
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
  ldp_dpdk_interface_count++;
  return intf;

err:
  errnosave = errno;
  if (started)
  {
    rte_eth_dev_stop(portid);
  }
  if (inqs)
  {
    for (i = 0; i < numinq; i++)
    {
      if (inqs[i])
      {
        struct ldp_in_queue_dpdk *innmq;
        innmq = CONTAINER_OF(inqs[i], struct ldp_in_queue_dpdk, q);
        free(innmq);
      }
    }
  }
  if (outqs)
  {
    for (i = 0; i < numoutq; i++)
    {
      if (outqs[i])
      {
        struct ldp_out_queue_dpdk *outnmq;
        outnmq = CONTAINER_OF(outqs[i], struct ldp_out_queue_dpdk, q);
        free(outnmq);
      }
    }
  }
  free(port);
  free(intf);
  free(inqs);
  free(outqs);
  errno = errnosave;
  return NULL;
}

int ldp_dpdk_mac_addr(int portid, void *mac)
{
  rte_eth_macaddr_get(portid, (struct ether_addr *)mac);
  return 0;
}

int ldp_dpdk_set_mac_addr(int portid, const void *mac)
{
  char mac2[6];
  memcpy(mac2, mac, 6);
  return rte_eth_dev_default_mac_addr_set(portid, (struct ether_addr *)mac2);
}

int ldp_dpdk_promisc_mode_set(int portid, int on)
{
  if (on)
  {
    rte_eth_promiscuous_enable(portid);
  }
  else
  {
    rte_eth_promiscuous_disable(portid);
  }
  return 0;
}

int ldp_dpdk_promisc_mode_get(int portid)
{
  return rte_eth_promiscuous_get(portid);
}

int ldp_dpdk_allmulti_set(int portid, int on)
{
  if (on)
  {
    rte_eth_allmulticast_enable(portid);
  }
  else
  {
    rte_eth_allmulticast_disable(portid);
  }
  return 0;
}

int ldp_dpdk_allmulti_get(int portid)
{
  return rte_eth_allmulticast_get(portid);
}

int ldp_dpdk_mtu_get(int portid)
{
  uint16_t mtu = 0;
  int ret;
  ret = rte_eth_dev_get_mtu(portid, &mtu);
  if (ret != 0)
  {
    return -1;
  }
  return mtu;
}
