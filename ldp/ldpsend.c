#include <sys/poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include "ldp.h"
#include "iphdr.h"
#include "ipcksum.h"
#include "time64.h"

struct ldp_interface *intf;

struct opts {
  size_t num_pkt;
  int interval_usec;
  uint16_t src_port;
  uint16_t dst_port;
  size_t payload_size;
  int burst_size;

  uint32_t src_ip;
  int src_ip_set;
  uint32_t dst_ip;
  int dst_ip_set;
  char src_mac[6];
  int src_mac_set;
  char dst_mac[6];
  int dst_mac_set;
};

struct opts global_opts = {
  .num_pkt = 0,
  .interval_usec = 0,
  .src_port = 12345,
  .dst_port = 54321,
  .payload_size = 1472,
  .burst_size = 128,
};

static int mac_parse(const char *str, char mac[6])
{
  char *nxt, *end;
  char *nxtx;
  unsigned long int uli;
  int i;

  nxtx = strchr(str, 'x');
  if (nxtx != NULL)
  {
    return -EINVAL;
  }

  for (i = 0; i < 6; i++)
  {
    nxt = strchr(str, ':');
    if ((nxt == NULL) != (i == 5))
    {
      return -EINVAL;
    }
    uli = strtoul(str, &end, 16);
    if (end != str + 1 && end != str + 2)
    {
      return -EINVAL;
    }
    if (i == 5)
    {
      if (*end != '\0')
      {
        return -EINVAL;
      }
    }
    else
    {
      if (end != nxt)
      {
        return -EINVAL;
      }
    }
    if (uli > 255)
    {
      return -EINVAL;
    }
    mac[i] = (char)(unsigned char)uli;
    str = nxt+1;
  }
  return 0;
}

static int ip_parse(const char *str, uint32_t *ip)
{
  char *nxt, *end;
  char *nxtx;
  unsigned long int uli;
  int i;

  nxtx = strchr(str, 'x');
  if (nxtx != NULL)
  {
    return -EINVAL;
  }

  for (i = 0; i < 4; i++)
  {
    nxt = strchr(str, '.');
    if ((nxt == NULL) != (i == 3))
    {
      return -EINVAL;
    }
    uli = strtoul(str, &end, 10);
    if (end != str + 1 && end != str + 2 && end != str + 3)
    {
      return -EINVAL;
    }
    if (i == 3)
    {
      if (*end != '\0')
      {
        return -EINVAL;
      }
    }
    else
    {
      if (end != nxt)
      {
        return -EINVAL;
      }
    }
    if (uli > 255)
    {
      return -EINVAL;
    }
    *ip |= (((uint32_t)(unsigned char)uli) << 8*(3-i));
    str = nxt+1;
  }
  return 0;
}

static void construct_packet(char *data, size_t sz)
{
  char *ip, *udp;
  if (sz != (size_t)(global_opts.payload_size + 8 + 20 + 14))
  {
    abort();
  }
  memset(data, 0, sz);
  memcpy(ether_dst(data), global_opts.dst_mac, 6);
  memcpy(ether_src(data), global_opts.src_mac, 6);
  ether_set_type(data, 0x0800);
  ip = ether_payload(data);
  ip_set_version(ip, 4);
  ip46_set_min_hdr_len(ip);
  ip46_set_payload_len(ip, global_opts.payload_size + 8);
  ip46_set_dont_frag(ip, 1);
  ip46_set_id(ip, 0);
  ip46_set_ttl(ip, 64);
  ip46_set_proto(ip, 17);
  ip_set_src(ip, global_opts.src_ip);
  ip_set_dst(ip, global_opts.dst_ip);
  ip46_set_hdr_cksum_calc(ip);
  udp = ip46_payload(ip);
  udp_set_src_port(udp, global_opts.src_port);
  udp_set_dst_port(udp, global_opts.dst_port);
  udp_set_total_len(udp, global_opts.payload_size + 8);
  udp_set_cksum_calc(ip, 20, udp, global_opts.payload_size + 8);
}

static void usage(const char *argv0)
{
  printf("usage: %s opts vale1:0\n", argv0);
  printf("mandatory opts:\n");
  printf("  --src_mac | -S 01:02:03:04:05:06\n");
  printf("  --dst_mac | -D 06:05:04:03:02:01\n");
  printf("  --src_ip | -s 1.2.3.4\n");
  printf("  --dst_ip | -d 4.3.2.1\n");
  printf("optional opts:\n");
  printf("  --src_port | -f 12345\n");
  printf("  --dst_port | -n 54321\n");
  printf("  --payload | -p 1472\n");
  printf("  --count | -c 0\n");
  printf("  --interval | -i 0\n");
  printf("  --burst | -b 128\n");
  printf("  --help | -h\n");
  exit(1);
}

int main(int argc, char **argv)
{
  uint64_t time64;
  uint64_t last_time64 = gettime64();
  uint64_t pkts = 0, bytes = 0;
  uint64_t last_pkts = 0, last_bytes = 0;
  struct ldp_packet pkt_tbl[8192] = {LDP_PACKET_EMPTY};
  int i;
  char pkt[65536] = {0};
  struct option long_options[] = {
      {"src_mac",  required_argument, 0,  'S' },
      {"dst_mac",  required_argument, 0,  'D' },
      {"src_ip",   required_argument, 0,  's' },
      {"dst_ip",   required_argument, 0,  'd' },
      {"src_port", required_argument, 0,  'f' },
      {"dst_port", required_argument, 0,  'n' },
      {"payload",  required_argument, 0,  'p' },
      {"count",    required_argument, 0,  'c' },
      {"interval", required_argument, 0,  'i' },
      {"help",     no_argument,       0,  'h' },
      {"burst",    required_argument, 0,  'b' },
      {0,          0,                 0,  0 }
  };

  setlinebuf(stdout);

  for (;;)
  {
    int option_index;
    unsigned long int uli;
    int c;
    char *endptr;
    c = getopt_long(argc, argv, "S:D:s:d:f:n:p:c:i:hb:", long_options, &option_index);
    if (c == -1)
    {
      break;
    }
    switch (c)
    {
      case 'S':
        if (mac_parse(optarg, global_opts.src_mac) != 0)
        {
          usage(argv[0]);
        }
        global_opts.src_mac_set = 1;
        break;
      case 'D':
        if (mac_parse(optarg, global_opts.dst_mac) != 0)
        {
          usage(argv[0]);
        }
        global_opts.dst_mac_set = 1;
        break;
      case 's':
        if (ip_parse(optarg, &global_opts.src_ip) != 0)
        {
          usage(argv[0]);
        }
        global_opts.src_ip_set = 1;
        break;
      case 'd':
        if (ip_parse(optarg, &global_opts.dst_ip) != 0)
        {
          usage(argv[0]);
        }
        global_opts.dst_ip_set = 1;
        break;
      case 'f':
        uli = strtoul(optarg, &endptr, 10);
        if (uli > 65535)
        {
          usage(argv[0]);
        }
        global_opts.src_port = uli;
        break;
      case 'n':
        uli = strtoul(optarg, &endptr, 10);
        if (uli > 65535)
        {
          usage(argv[0]);
        }
        global_opts.dst_port = uli;
        break;
      case 'i':
        uli = strtoul(optarg, &endptr, 10);
        if (uli > INT_MAX)
        {
          usage(argv[0]);
        }
        global_opts.interval_usec = uli;
        break;
      case 'c':
        uli = strtoul(optarg, &endptr, 10);
        if (uli > INT_MAX)
        {
          usage(argv[0]);
        }
        global_opts.num_pkt = uli;
        break;
      case 'p':
        uli = strtoul(optarg, &endptr, 10);
        if (uli > 65535 - 8 - 20)
        {
          usage(argv[0]);
        }
        global_opts.payload_size = uli;
        break;
      case 'b':
        uli = strtoul(optarg, &endptr, 10);
        if (uli > 8192)
        {
          usage(argv[0]);
        }
        global_opts.burst_size = uli;
        break;
      case 'h':
        usage(argv[0]);
        break;
      default:
        abort();
    }
  }
  if (!global_opts.src_mac_set ||
      !global_opts.dst_mac_set ||
      !global_opts.src_ip_set ||
      !global_opts.dst_ip_set)
  {
    usage(argv[0]);
  }

  if (argc != optind + 1)
  {
    usage(argv[0]);
  }

  intf = ldp_interface_open(argv[optind], 1, 1);
  if (intf == NULL)
  {
    printf("cannot open %s\n", argv[optind]);
    exit(1);
  }

  construct_packet(pkt, global_opts.payload_size + 8 + 20 + 14);
  for (i = 0; i < global_opts.burst_size; i++)
  {
    pkt_tbl[i].data = pkt;
    pkt_tbl[i].sz = global_opts.payload_size + 8 + 20 + 14;
  }

  while (global_opts.num_pkt <= 0 || pkts <= (size_t)global_opts.num_pkt)
  {
    int num;
    int left = global_opts.burst_size;
    if (global_opts.num_pkt && left > (int)(global_opts.num_pkt - pkts))
    {
      left = global_opts.num_pkt - pkts;
    }
    if (left == 0)
    {
      break;
    }
    
    num = ldp_out_inject(intf->outq[0], pkt_tbl, left);
    ldp_out_txsync(intf->outq[0]);
    if (num > 0)
    {
      pkts += (size_t)num;
      bytes += ((size_t)num)*pkt_tbl[0].sz;
    }

    time64 = gettime64();
    if (time64 - last_time64 > 1000*1000)
    {
      uint64_t pdiff = pkts - last_pkts;
      uint64_t bdiff = bytes - last_bytes;
      double tdiff = time64 - last_time64;
      printf("%g MPPS %g Gbps\n",
             pdiff/tdiff, bdiff*8/1000/tdiff);
      last_time64 = time64;
      last_pkts = pkts;
      last_bytes = bytes;
    }

    if (global_opts.interval_usec > 0)
    {
      usleep(((unsigned)global_opts.interval_usec));
    }
  }

  ldp_interface_close(intf);

  return 0;
}
