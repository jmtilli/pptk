#include "ldp.h"
#include <stdio.h>

int main(int argc, char **argv)
{
  struct ldp_interface *intf;
  if (argc != 2)
  {
    printf("Usage: testldp netmap:eth0\n");
    return 1;
  }
  intf = ldp_interface_open(argv[1], 1, 1);
  if (intf == NULL)
  {
    printf("Can't open interface\n");
    return 1;
  }
  ldp_interface_close(intf);
  return 0;
}