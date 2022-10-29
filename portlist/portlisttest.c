#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include "portlist.h"

int main(int argc, char **argv)
{
  struct port_list list;
  int i;
  port_list_init(&list);
  for (i = 1024; i < 65536; i++)
  {
    port_list_add(&list, (uint16_t)i);
  }
  for (i = 0; i < 10*1000*1000; i++)
  {
    uint16_t port;
    port = port_list_get(&list);
    port_list_add(&list, port);
  }
  port_list_free(&list);
  return 0;
}
