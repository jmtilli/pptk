#ifndef _NETMAPPORTS_H_
#define _NETMAPPORTS_H_

#include "packet.h"
#include "asalloc.h"
#include "ports.h"

void netmapfunc(struct packet *pkt, void *userdata);

void netmapfunc2(struct packet *pkt, void *userdata);

struct netmapfunc_userdata {
  struct as_alloc_local *loc;
  struct nm_desc *nmd;
};

struct netmapfunc2_userdata {
  struct as_alloc_local *loc;
  struct nm_desc *ulnmd;
  struct nm_desc *dlnmd;
};

#endif
