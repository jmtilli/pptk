#include "ports.h"
#include "ldpports.h"
#include "ldp.h"
#include "time64.h"
#include "mypcapng.h"
#include "log.h"
#include <sys/poll.h>

void ldpfunc(struct packet *pkt, void *userdata)
{
  struct ldpfunc_userdata *ud = userdata;
  struct ldp_packet pkts[1];
  pkts[0].data = pkt->data;
  pkts[0].sz = (uint32_t)pkt->sz;
  ldp_out_inject(ud->outq, pkts, 1);
  allocif_free(ud->intf, pkt);
}

void ldpfunc2(struct packet *pkt, void *userdata)
{
  struct ldpfunc2_userdata *ud = userdata;
  struct ldp_packet pkts[1];
  pkts[0].data = pkt->data;
  pkts[0].sz = (uint32_t)pkt->sz;
  if (pkt->direction == PACKET_DIRECTION_UPLINK)
  {
    ldp_out_inject(ud->uloutq, pkts, 1);
    if (ud->wan)
    {
      if (pcapng_out_ctx_write(ud->wanctx, pkt->data, pkt->sz,
          gettime64(), "out"))
      {
        log_log(LOG_LEVEL_CRIT, "PORTS", "can't record packet");
        exit(1);
      }
    }
    if (ud->out)
    {
      if (pcapng_out_ctx_write(ud->outctx, pkt->data, pkt->sz,
          gettime64(), "out"))
      {
        log_log(LOG_LEVEL_CRIT, "PORTS", "can't record packet");
        exit(1);
      }
    }
  }
  else
  {
    ldp_out_inject(ud->dloutq, pkts, 1);
    if (ud->lan)
    {
      if (pcapng_out_ctx_write(ud->lanctx, pkt->data, pkt->sz,
          gettime64(), "out"))
      {
        log_log(LOG_LEVEL_CRIT, "PORTS", "can't record packet");
        exit(1);
      }
    }
    if (ud->out)
    {
      if (pcapng_out_ctx_write(ud->outctx, pkt->data, pkt->sz,
          gettime64(), "in"))
      {
        log_log(LOG_LEVEL_CRIT, "PORTS", "can't record packet");
        exit(1);
      }
    }
  }
  allocif_free(ud->intf, pkt);
}

void ldpfunc3flushdl(struct ldpfunc3_userdata *ud)
{
  struct ldp_packet ldppkts[ud->dloutcnt];
  size_t i;
  for (i = 0; i < ud->dloutcnt; i++)
  {
    ldppkts[i].data = ud->dloutbuf[i]->data;
    ldppkts[i].sz = (uint32_t)ud->dloutbuf[i]->sz;
  }
  ldp_out_inject(ud->dloutq, ldppkts, (int)ud->dloutcnt);
  for (i = 0; i < ud->dloutcnt; i++)
  {
    allocif_free(ud->intf, ud->dloutbuf[i]);
  }
  ud->dloutcnt = 0;
}

void ldpfunc3flushul(struct ldpfunc3_userdata *ud)
{
  struct ldp_packet ldppkts[ud->uloutcnt];
  size_t i;
  for (i = 0; i < ud->uloutcnt; i++)
  {
    ldppkts[i].data = ud->uloutbuf[i]->data;
    ldppkts[i].sz = (uint32_t)ud->uloutbuf[i]->sz;
  }
  ldp_out_inject(ud->uloutq, ldppkts, (int)ud->uloutcnt);
  for (i = 0; i < ud->uloutcnt; i++)
  {
    allocif_free(ud->intf, ud->uloutbuf[i]);
  }
  ud->uloutcnt = 0;
}

void ldpfunc3(struct packet *pkt, void *userdata)
{
  struct ldpfunc3_userdata *ud = userdata;
  if (pkt->direction == PACKET_DIRECTION_UPLINK)
  {
    if (ud->uloutcnt >= sizeof(ud->uloutbuf)/sizeof(*ud->uloutbuf))
    {
      ldpfunc3flushul(ud);
    }
    if (ud->uloutcnt >= sizeof(ud->uloutbuf)/sizeof(*ud->uloutbuf))
    {
      abort();
    }
    ud->uloutbuf[ud->uloutcnt++] = pkt;
    if (ud->wan)
    {
      if (pcapng_out_ctx_write(ud->wanctx, pkt->data, pkt->sz,
          gettime64(), "out"))
      {
        log_log(LOG_LEVEL_CRIT, "PORTS", "can't record packet");
        exit(1);
      }
    }
    if (ud->out)
    {
      if (pcapng_out_ctx_write(ud->outctx, pkt->data, pkt->sz,
          gettime64(), "out"))
      {
        log_log(LOG_LEVEL_CRIT, "PORTS", "can't record packet");
        exit(1);
      }
    }
  } 
  else
  { 
    if (ud->dloutcnt >= sizeof(ud->dloutbuf)/sizeof(*ud->dloutbuf))
    {
      ldpfunc3flushdl(ud);
    }
    if (ud->dloutcnt >= sizeof(ud->dloutbuf)/sizeof(*ud->dloutbuf))
    {
      abort();
    }
    ud->dloutbuf[ud->dloutcnt++] = pkt;
    if (ud->lan)
    {
      if (pcapng_out_ctx_write(ud->lanctx, pkt->data, pkt->sz,
          gettime64(), "out"))
      {
        log_log(LOG_LEVEL_CRIT, "PORTS", "can't record packet");
        exit(1);
      }
    }
    if (ud->out)
    {
      if (pcapng_out_ctx_write(ud->outctx, pkt->data, pkt->sz,
          gettime64(), "in"))
      {
        log_log(LOG_LEVEL_CRIT, "PORTS", "can't record packet");
        exit(1);
      }
    }
  }
}
