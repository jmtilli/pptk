#define _GNU_SOURCE

#include <sys/poll.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/ethtool.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "ldp.h"
#include "ldpnull.h"
#include "linkcommon.h"
#include "ldppcap.h"
#include "containerof.h"
#if WITH_NETMAP
#include "ldpnetmap.h"
#endif
#if WITH_DPDK
#include "ldpdpdk.h"
#endif
#if WITH_ODP
#include "ldpodp.h"
#endif

struct feature_state {
  struct ethtool_gfeatures features;
};

struct feature_state_set {
  struct ethtool_sfeatures features;
};

static int turn_off_offloads(const char *name)
{
  size_t i;
  struct ethtool_gstrings *names;
  struct {
    struct ethtool_sset_info hdr;
    uint32_t buf[1];
  } sset_info;
  struct feature_state *state;
  struct feature_state_set *setstate;
  struct ifreq ifr = {.ifr_name = ""};
  int fd;
  uint32_t len;

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0)
  {
    return 0;
  }

  sset_info.hdr.cmd = ETHTOOL_GSSET_INFO;
  sset_info.hdr.reserved = 0;
  sset_info.hdr.sset_mask = 1ULL << ETH_SS_FEATURES;
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
  ifr.ifr_data = (void*)&sset_info.hdr; // cmd
  if (ioctl(fd, SIOCETHTOOL, &ifr) != 0)
  {
    int errnosave;
    errnosave = errno;
    close(fd);
    errno = errnosave;
    return 0;
  }
  len = sset_info.hdr.sset_mask ? sset_info.hdr.data[0] : 0;
  names = calloc(1, sizeof(*names) + len * ETH_GSTRING_LEN);
  if (names == NULL)
  {
    close(fd);
    errno = ENOMEM;
    return 0;
  }

  names->cmd = ETHTOOL_GSTRINGS;
  names->string_set = ETH_SS_FEATURES;
  names->len = len;
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
  ifr.ifr_data = (void*)names; // cmd
  if (ioctl(fd, SIOCETHTOOL, &ifr) != 0)
  {
    int errnosave;
    errnosave = errno;
    close(fd);
    free(names);
    errno = errnosave;
    return 0;
  }

  for (i = 0; i < len; i++)
  {
    names->data[(i+1)*ETH_GSTRING_LEN - 1] = '\0';
  }

  state = malloc(sizeof(*state) + ((len+31)/32) * sizeof(state->features.features[0]));
  if (state == NULL)
  {
    free(names);
    close(fd);
    errno = ENOMEM;
    return 0;
  }

  state->features.cmd = ETHTOOL_GFEATURES;
  state->features.size = (len+31) / 32;
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
  ifr.ifr_data = (void*)&state->features; // cmd
  if (ioctl(fd, SIOCETHTOOL, &ifr) != 0)
  {
    int errnosave;
    errnosave = errno;
    close(fd);
    free(names);
    free(state);
    errno = errnosave;
    return 0;
  }

  setstate = calloc(1,sizeof(*setstate) + ((len+31)/32) * sizeof(setstate->features.features[0]));

  for (i = 0; i < len; i++)
  {
    char *offload = (char*)&names->data[i*ETH_GSTRING_LEN];
    int fixed;
    fixed =
        !(state->features.features[i/32].available & (1U<<(i%32U))) ||
        (state->features.features[i/32].never_changed & (1U<<(i%32U)));
    if (fixed)
    {
      continue;
    }
    if (strcmp(offload, "rx-checksum") == 0)
    {
      setstate->features.features[i/32].valid |= (1U<<(i%32U));
      setstate->features.features[i/32].requested &= ~(1U<<(i%32U));
    }
    else if (strcmp(offload, "rx-gro") == 0)
    {
      setstate->features.features[i/32].valid |= (1U<<(i%32U));
      setstate->features.features[i/32].requested &= ~(1U<<(i%32U));
    }
    else if (strcmp(offload, "rx-lro") == 0)
    {
      setstate->features.features[i/32].valid |= (1U<<(i%32U));
      setstate->features.features[i/32].requested &= ~(1U<<(i%32U));
    }
  }

  setstate->features.cmd = ETHTOOL_SFEATURES;
  setstate->features.size = (len+31) / 32;
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
  ifr.ifr_data = (void*)&setstate->features; // cmd
  if (ioctl(fd, SIOCETHTOOL, &ifr) != 0)
  {
    int errnosave;
    errnosave = errno;
    close(fd);
    free(names);
    free(state);
    free(setstate);
    errno = errnosave;
    return 0;
  }
  close(fd);

  free(names);
  free(state);
  free(setstate);
  return 1;
}

static int check_offloads(const char *name)
{
  size_t i;
  struct ethtool_gstrings *names;
  struct {
    struct ethtool_sset_info hdr;
    uint32_t buf[1];
  } sset_info;
  struct feature_state *state;
  struct ifreq ifr = {.ifr_name = ""};
  int fd;
  uint32_t len;

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0)
  {
    return 0;
  }

  sset_info.hdr.cmd = ETHTOOL_GSSET_INFO;
  sset_info.hdr.reserved = 0;
  sset_info.hdr.sset_mask = 1ULL << ETH_SS_FEATURES;
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
  ifr.ifr_data = (void*)&sset_info.hdr; // cmd
  if (ioctl(fd, SIOCETHTOOL, &ifr) != 0)
  {
    int errnosave;
    errnosave = errno;
    close(fd);
    errno = errnosave;
    return 0;
  }
  len = sset_info.hdr.sset_mask ? sset_info.hdr.data[0] : 0;
  names = calloc(1, sizeof(*names) + len * ETH_GSTRING_LEN);
  if (names == NULL)
  {
    close(fd);
    errno = ENOMEM;
    return 0;
  }

  names->cmd = ETHTOOL_GSTRINGS;
  names->string_set = ETH_SS_FEATURES;
  names->len = len;
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
  ifr.ifr_data = (void*)names; // cmd
  if (ioctl(fd, SIOCETHTOOL, &ifr) != 0)
  {
    int errnosave;
    errnosave = errno;
    close(fd);
    free(names);
    errno = errnosave;
    return 0;
  }

  for (i = 0; i < len; i++)
  {
    names->data[(i+1)*ETH_GSTRING_LEN - 1] = '\0';
  }

  state = malloc(sizeof(*state) + ((len+31)/32) * sizeof(state->features.features[0]));
  if (state == NULL)
  {
    free(names);
    close(fd);
    errno = ENOMEM;
    return 0;
  }

  state->features.cmd = ETHTOOL_GFEATURES;
  state->features.size = (len+31) / 32;
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
  ifr.ifr_data = (void*)&state->features; // cmd
  if (ioctl(fd, SIOCETHTOOL, &ifr) != 0)
  {
    int errnosave;
    errnosave = errno;
    close(fd);
    free(names);
    free(state);
    errno = errnosave;
    return 0;
  }
  close(fd);

  for (i = 0; i < len; i++)
  {
    char *offload = (char*)&names->data[i*ETH_GSTRING_LEN];
    int x;
    int fixed;
    fixed =
        !(state->features.features[i/32].available & (1U<<(i%32U))) ||
        (state->features.features[i/32].never_changed & (1U<<(i%32U)));
    x = !!(state->features.features[i/32].active & (1U<<(i%32U))) && !fixed;
    if (strcmp(offload, "rx-checksum") == 0 && x)
    {
      errno = EMEDIUMTYPE;
      free(names);
      free(state);
      return 0;
    }
    else if (strcmp(offload, "rx-gro") == 0 && x)
    {
      errno = EMEDIUMTYPE;
      free(names);
      free(state);
      return 0;
    }
    else if (strcmp(offload, "rx-lro") == 0 && x)
    {
      errno = EMEDIUMTYPE;
      free(names);
      free(state);
      return 0;
    }
  }

  free(names);
  free(state);
  return 1;
}



static int ldp_config_global_isset = 0;
static struct ldp_config ldp_config_global = LDP_CONFIG_EMPTY;

void ldp_config_init(struct ldp_config *config)
{
  memset(config, 0, sizeof(*config));
  if (getenv("LDP_NETMAP_NR_RX_SLOTS"))
  {
    config->netmap_nr_rx_slots = atoi(getenv("LDP_NETMAP_NR_RX_SLOTS"));
  }
  else
  {
    config->netmap_nr_rx_slots = 256;
  }
  if (getenv("LDP_NETMAP_NR_TX_SLOTS"))
  {
    config->netmap_nr_tx_slots = atoi(getenv("LDP_NETMAP_NR_TX_SLOTS"));
  }
  else
  {
    config->netmap_nr_tx_slots = 64;
  }
  if (getenv("LDP_DPDK_POOL_NUM"))
  {
    config->dpdk_pool_num = atoi(getenv("LDP_DPDK_POOL_NUM"));
  }
  else
  {
    config->dpdk_pool_num = 8192;
  }
  if (getenv("LDP_DPDK_POOL_CACHE_NUM"))
  {
    config->dpdk_pool_cache_num = atoi(getenv("LDP_DPDK_POOL_CACHE_NUM"));
  }
  else
  {
    config->dpdk_pool_cache_num = 256;
  }
  if (getenv("LDP_DPDK_POOL_DATA_ROOM"))
  {
    config->dpdk_pool_data_room = atoi(getenv("LDP_DPDK_POOL_DATA_ROOM"));
  }
  else
  {
    config->dpdk_pool_data_room = 2176;
  }
  if (getenv("LDP_DPDK_NB_RXD"))
  {
    config->dpdk_nb_rxd = atoi(getenv("LDP_DPDK_NB_RXD"));
  }
  else
  {
    config->dpdk_nb_rxd = 128;
  }
  if (getenv("LDP_DPDK_NB_TXD"))
  {
    config->dpdk_nb_txd = atoi(getenv("LDP_DPDK_NB_TXD"));
  }
  else
  {
    config->dpdk_nb_txd = 512;
  }
  if (getenv("LDP_SOCKET_NUM_BUFS"))
  {
    config->socket_num_bufs = atoi(getenv("LDP_SOCKET_NUM_BUFS"));
  }
  else
  {
    config->socket_num_bufs = 1024;
  }
  if (getenv("LDP_SOCKET_RCVBUF"))
  {
    config->socket_rcvbuf = atoi(getenv("LDP_SOCKET_RCVBUF"));
  }
  else
  {
    config->socket_rcvbuf = 0;
  }
  if (getenv("LDP_SOCKET_SNDBUF"))
  {
    config->socket_sndbuf = atoi(getenv("LDP_SOCKET_SNDBUF"));
  }
  else
  {
    config->socket_sndbuf = 0;
  }
  if (getenv("LDP_ODP_NUM_PKT"))
  {
    config->odp_num_pkt = atoi(getenv("LDP_ODP_NUM_PKT"));
  }
  else
  {
    config->odp_num_pkt = 8192;
  }
  if (getenv("LDP_ODP_PKT_LEN"))
  {
    config->odp_pkt_len = atoi(getenv("LDP_ODP_PKT_LEN"));
  }
  else
  {
    config->odp_pkt_len = 1856;
  }
  if (getenv("LDP_PCAP_NUM_BUFS"))
  {
    config->pcap_num_bufs = atoi(getenv("LDP_PCAP_NUM_BUFS"));
  }
  else
  {
    config->pcap_num_bufs = 1024;
  }
}

struct ldp_config *ldp_config_get_global(void)
{
  if (!ldp_config_global_isset)
  {
    struct ldp_config ldp_config_local = LDP_CONFIG_EMPTY;
    ldp_config_init(&ldp_config_local);
    ldp_config_set(&ldp_config_local);
  }
  if (!ldp_config_global_isset)
  {
    abort();
  }
  return &ldp_config_global;
}

// Must be called before calling any other LDP function, if default is not ok
void ldp_config_set(struct ldp_config *config)
{
  ldp_config_global = *config; // struct assignment
  ldp_config_global_isset = 1;
}

struct ldp_in_queue_socket {
  struct ldp_in_queue q;
  size_t max_sz;
  size_t num_bufs;
  size_t buf_start;
  size_t buf_end;
  char **bufs; // always at least 1 slot free
};

static uint32_t ldp_in_queue_ring_size_socket(struct ldp_in_queue *inq)
{
  struct ldp_in_queue_socket *insock;
  insock = CONTAINER_OF(inq, struct ldp_in_queue_socket, q);
  return insock->num_bufs;
}

struct ldp_out_queue_socket {
  struct ldp_out_queue q;
};

static void ldp_in_queue_close_socket(struct ldp_in_queue *inq)
{
  size_t i;
  struct ldp_in_queue_socket *insock;
  insock = CONTAINER_OF(inq, struct ldp_in_queue_socket, q);
  close(insock->q.fd);
  for (i = 0; i < insock->num_bufs; i++)
  {
    free(insock->bufs[i]);
  }
  free(insock->bufs);
  free(insock);
}

static void ldp_out_queue_close_socket(struct ldp_out_queue *outq)
{
  struct ldp_out_queue_socket *outsock;
  outsock = CONTAINER_OF(outq, struct ldp_out_queue_socket, q);
  close(outsock->q.fd);
  free(outsock);
}

static int ldp_out_queue_txsync_socket(struct ldp_out_queue *outq)
{
  return 0;
}



int ldp_in_queue_poll(struct ldp_in_queue *inq, uint64_t timeout_usec)
{
  int nfds;
  struct timeval timeout;
  fd_set set;
  if (inq->fd < 0)
  {
    errno = -ENOTSOCK;
    return -1;
  }
  nfds = inq->fd + 1;
  FD_ZERO(&set);
  FD_SET(inq->fd, &set);
  timeout.tv_sec = (int64_t)(timeout_usec / (1000U*1000U));
  timeout.tv_usec = (int)(timeout_usec % (1000U*1000U));
  return select(nfds, &set, NULL, NULL, &timeout);
}

static void
ldp_in_queue_deallocate_some_socket(struct ldp_in_queue *inq,
                                    struct ldp_packet *pkts, int num)
{
  int i;
  size_t new_end;
  struct ldp_in_queue_socket *insock;
  insock = CONTAINER_OF(inq, struct ldp_in_queue_socket, q);
  if (num <= 0)
  {
    return;
  }
  new_end = insock->buf_end;
  for (i = 0; i < num; i++)
  {
    insock->bufs[new_end] = pkts[i].data;
    new_end++;
    if (new_end >= insock->num_bufs)
    {
      new_end = 0;
    }
  }
  insock->buf_end = new_end;
}

static int ldp_in_queue_nextpkts_socket(struct ldp_in_queue *inq,
                                        struct ldp_packet *pkts, int num)
{
  size_t i, j, k, l;
  int fd = inq->fd;
  int ret;
  int amnt_free;
  struct ldp_in_queue_socket *insock;
  insock = CONTAINER_OF(inq, struct ldp_in_queue_socket, q);

  // sz = 4
  //       X
  // 0 1 2 3
  // ^     ^

  if (num < 0)
  {
    abort();
  }


  // FIXME this calculation needs to be checked
  amnt_free = insock->buf_end - insock->buf_start - 1;
  if (amnt_free < 0)
  {
    if (insock->num_bufs > INT_MAX)
    {
      abort();
    }
    amnt_free += (int)insock->num_bufs;
  }
  if (amnt_free == 0)
  {
    return 0;
  }

  if (num > amnt_free)
  {
    num = amnt_free;
  }

  struct sockaddr_ll names[num];
  struct mmsghdr msgs[num];
  struct iovec iovecs[num][1];
  struct ldp_packet missed[num];

  memset(msgs, 0, sizeof(msgs));
  memset(iovecs, 0, sizeof(iovecs));

  j = insock->buf_start;
  for (i = 0; i < (unsigned)num; i++)
  {
    msgs[i].msg_hdr.msg_iovlen = 1;
    msgs[i].msg_hdr.msg_iov = iovecs[i];
    msgs[i].msg_hdr.msg_namelen = sizeof(names[i]);
    msgs[i].msg_hdr.msg_name = &names[i];
    if (j >= insock->num_bufs)
    {
      j = 0;
    }
    iovecs[i][0].iov_base = insock->bufs[j++];
    iovecs[i][0].iov_len = insock->max_sz;
  }
  ret = recvmmsg(fd, msgs, (unsigned)num, MSG_DONTWAIT, NULL);
  if (ret < 0)
  {
    return ret;
  }
  j = 0;
  k = insock->buf_start;
  l = 0;
  // FIXME what if all packets are outgoing?
  for (i = 0; i < (size_t)ret; i++)
  {
    if (names[i].sll_pkttype == PACKET_OUTGOING)
    {
      missed[l].data = iovecs[i][0].iov_base;
      missed[l].sz = msgs[i].msg_len;
      k++;
      if (k >= insock->num_bufs)
      {
        k = 0;
      }
      l++;
      continue;
    }
    pkts[j].data = iovecs[i][0].iov_base;
    pkts[j].sz = msgs[i].msg_len;
    k++;
    if (k >= insock->num_bufs)
    {
      k = 0;
    }
    j++;
  }
  insock->buf_start = k;
  ldp_in_queue_deallocate_some_socket(inq, missed, l);
  return j;
}

static int ldp_out_queue_inject_socket(struct ldp_out_queue *outq,
                                       struct ldp_packet *pkts, int num)
{
  int i;
  int fd = outq->fd;
  int ret;

  if (num <= 0)
  {
    return 0;
  }

  struct mmsghdr msgs[num];
  struct iovec iovecs[num][1];

  memset(msgs, 0, sizeof(msgs));
  memset(iovecs, 0, sizeof(iovecs));

  for (i = 0; i < num; i++)
  {
    msgs[i].msg_hdr.msg_iovlen = 1;
    msgs[i].msg_hdr.msg_iov = iovecs[i];
    iovecs[i][0].iov_base = pkts[i].data;
    iovecs[i][0].iov_len = pkts[i].sz;
  }
  ret = sendmmsg(fd, msgs, (unsigned)num, 0);
  return ret;
}

static int ldp_out_queue_inject_chunk_socket(struct ldp_out_queue *outq,
                                             struct ldp_chunkpacket *pkts,
                                             int num)
{
  int i;
  int fd = outq->fd;
  int ret;

  if (num <= 0)
  {
    return 0;
  }

  struct mmsghdr msgs[num];

  memset(msgs, 0, sizeof(msgs));

  for (i = 0; i < num; i++)
  {
    msgs[i].msg_hdr.msg_iovlen = pkts[i].iovlen;
    msgs[i].msg_hdr.msg_iov = pkts[i].iov;
  }
  ret = sendmmsg(fd, msgs, (unsigned)num, 0);
  return ret;
}

static struct ldp_interface *
ldp_interface_open_socket(const char *name, int numinq, int numoutq,
                          const struct ldp_interface_settings *settings)
{
  struct ldp_interface *intf = NULL;
  struct ldp_in_queue **inqs = NULL;
  struct ldp_out_queue **outqs = NULL;
  struct ldp_in_queue_socket *insock = NULL;
  struct ldp_out_queue_socket *outsock = NULL;
  struct sockaddr_ll sockaddr_ll;
  size_t i;
  struct ifreq ifr;
  int ifindex;
  int mtu;
  int errnosave;
  int buf;

  if (numinq < 0 || numoutq < 0)
  {
    abort();
  }

  if (numinq != 1 || numoutq != 1)
  {
    errno = ECHRNG;
    goto err;
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
  outqs = malloc(((unsigned)numoutq)*sizeof(*outqs));
  if (outqs == NULL)
  {
    errno = ENOMEM;
    goto err;
  }


  insock = malloc(sizeof(*insock));
  if (insock == NULL)
  {
    errno = ENOMEM;
    goto err;
  }
  insock->bufs = NULL;
  insock->q.fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (insock->q.fd < 0)
  {
    // errno already set
    goto err;
  }
  buf = ldp_config_get_global()->socket_rcvbuf;
  if (buf > 0 && setsockopt(insock->q.fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf)) != 0)
  {
    goto err;
  }
  buf = ldp_config_get_global()->socket_sndbuf;
  if (buf > 0 && setsockopt(insock->q.fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf)) != 0)
  {
    goto err;
  }

  memset(&ifr, 0, sizeof(ifr));
  if (settings && settings->mtu_set)
  {
    ifr.ifr_mtu = settings->mtu;
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
    if (ioctl(insock->q.fd, SIOCSIFMTU, &ifr) != 0)
    {
      // errno already set
      goto err;
    }
  }

  memset(&ifr, 0, sizeof(ifr));
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
  if (ioctl(insock->q.fd, SIOCGIFMTU, &ifr) != 0)
  {
    // errno already set
    goto err;
  }
  mtu = ifr.ifr_mtu;
  memset(&ifr, 0, sizeof(ifr));
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
  if (ioctl(insock->q.fd, SIOCGIFINDEX, &ifr) != 0)
  {
    // errno already set
    goto err;
  }
  ifindex = ifr.ifr_ifindex;
  memset(&sockaddr_ll, 0, sizeof(sockaddr_ll));
  sockaddr_ll.sll_family = AF_PACKET;
  sockaddr_ll.sll_ifindex = ifindex;
  sockaddr_ll.sll_protocol = htons(ETH_P_ALL);
  if (bind(insock->q.fd,
           (struct sockaddr*)&sockaddr_ll, sizeof(sockaddr_ll)) < 0)
  {
    // errno already set
    goto err;
  }

  outsock = malloc(sizeof(*outsock));
  if (outsock == NULL)
  {
    errno = ENOMEM;
    goto err;
  }
  outsock->q.fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (outsock->q.fd < 0)
  {
    // errno already set
    goto err;
  }
  buf = ldp_config_get_global()->socket_rcvbuf;
  if (buf > 0 && setsockopt(outsock->q.fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf)) != 0)
  {
    goto err;
  }
  buf = ldp_config_get_global()->socket_sndbuf;
  if (buf > 0 && setsockopt(outsock->q.fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf)) != 0)
  {
    goto err;
  }

#ifdef PACKET_QDISC_BYPASS
  int one = 1;
  one = 1;
  setsockopt(outsock->q.fd, SOL_PACKET, PACKET_QDISC_BYPASS, &one, sizeof(one));
#endif

  memset(&sockaddr_ll, 0, sizeof(sockaddr_ll));
  sockaddr_ll.sll_family = AF_PACKET;
  sockaddr_ll.sll_ifindex = ifindex;
  sockaddr_ll.sll_protocol = htons(ETH_P_ALL);
  if (bind(outsock->q.fd,
           (struct sockaddr*)&sockaddr_ll, sizeof(sockaddr_ll)) < 0)
  {
    // errno already set
    goto err;
  }

  insock->q.nextpkts = ldp_in_queue_nextpkts_socket;
  insock->q.nextpkts_ts = NULL;
  insock->q.poll = ldp_in_queue_poll;
  insock->q.eof = NULL;
  insock->q.close = ldp_in_queue_close_socket;
  insock->q.deallocate_all = NULL;
  insock->q.deallocate_some = ldp_in_queue_deallocate_some_socket;
  insock->q.ring_size = ldp_in_queue_ring_size_socket;

  outsock->q.inject = ldp_out_queue_inject_socket;
  outsock->q.inject_dealloc = NULL;
  outsock->q.inject_chunk = ldp_out_queue_inject_chunk_socket;
  outsock->q.txsync = ldp_out_queue_txsync_socket;
  outsock->q.close = ldp_out_queue_close_socket;

  inqs[0] = &insock->q;
  outqs[0] = &outsock->q;
  
  intf->num_inq = numinq;
  intf->num_outq = numoutq;
  intf->inq = inqs;
  intf->outq = outqs;
  snprintf(intf->name, sizeof(intf->name), "%s", name);

  if (mtu < 0)
  {
    abort();
  }
  insock->max_sz = ((unsigned)mtu) + 14U;
  int num_bufs_tmp;
  num_bufs_tmp = ldp_config_get_global()->socket_num_bufs;
  if (num_bufs_tmp < 0)
  {
    abort();
  }
  insock->num_bufs = (unsigned)num_bufs_tmp;
  insock->buf_start = 0;
  insock->buf_end = 0;
  insock->bufs = malloc(insock->num_bufs*sizeof(*insock->bufs));
  if (insock->bufs == NULL)
  {
    errno = ENOMEM;
    goto err;
  }
  for (i = 0; i < insock->num_bufs; i++)
  {
    insock->bufs[i] = NULL;
  }
  for (i = 0; i < insock->num_bufs; i++)
  {
    insock->bufs[i] = malloc(insock->max_sz);
    if (insock->bufs[i] == NULL)
    {
      errno = ENOMEM;
      goto err;
    }
  }

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
  if (insock)
  {
    if (insock->bufs)
    {
      for (i = 0; i < insock->num_bufs; i++)
      {
        free(insock->bufs[i]);
      }
    }
    free(insock->bufs);
  }
  if (outsock && outsock->q.fd >= 0)
  {
    close(outsock->q.fd);
  }
  free(outsock);
  if (insock && insock->q.fd >= 0)
  {
    close(insock->q.fd);
  }
  free(insock);
  free(inqs);
  free(outqs);
  free(intf);
  errno = errnosave;
  return NULL;
}

void ldp_interface_close(struct ldp_interface *intf)
{
  int numinq = intf->num_inq;
  int numoutq = intf->num_outq;
  struct ldp_in_queue **inqs = intf->inq;
  struct ldp_out_queue **outqs = intf->outq;
  int i;

  for (i = 0; i < numinq; i++)
  {
    inqs[i]->close(inqs[i]);
  }
  for (i = 0; i < numoutq; i++)
  {
    outqs[i]->close(outqs[i]);
  }
  free(inqs);
  free(outqs);
  free(intf);
}

struct ldp_interface *
ldp_interface_open_2(const char *name, int numinq, int numoutq,
                     const struct ldp_interface_settings *settings)
{
  long portid;
  char *endptr;
  if (numinq < 0 || numoutq < 0 || numinq > 1024*1024 || numoutq > 1024*1024)
  {
    abort();
  }
  portid = strtol(name, &endptr, 10);
  if (*name != '\0' && *endptr == '\0' && portid >= 0 && portid <= INT_MAX)
  {
#if WITH_DPDK
    return ldp_interface_open_dpdk(name, numinq, numoutq, settings);
#else
    return NULL;
#endif
  }
  if (strncmp(name, "pcap:", 5) == 0)
  {
    return ldp_interface_open_pcap(name, numinq, numoutq, settings);
  }
  else if (strncmp(name, "null:", 5) == 0)
  {
    return ldp_interface_open_null(name, numinq, numoutq, settings);
  }
  else if (strncmp(name, "odp:", 4) == 0)
  {
#if WITH_ODP
    return ldp_interface_open_odp(name+4, numinq, numoutq, settings);
#else
    return NULL;
#endif
  }
  else if (strncmp(name, "netmap:", 7) == 0)
  {
    if (!turn_off_offloads(name+7))
    {
      return NULL;
    }
    if (!check_offloads(name+7))
    {
      return NULL;
    }
#if WITH_NETMAP
    return ldp_interface_open_netmap(name, numinq, numoutq, settings);
#else
    return NULL;
#endif
  }
  else if (strncmp(name, "vale", 4) == 0)
  {
#if WITH_NETMAP
    return ldp_interface_open_netmap(name, numinq, numoutq, settings);
#else
    return NULL;
#endif
  }
  if (!turn_off_offloads(name))
  {
    return NULL;
  }
  if (!check_offloads(name))
  {
    return NULL;
  }
  return ldp_interface_open_socket(name, numinq, numoutq, settings);
}
