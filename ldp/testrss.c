#include "ldp.h"
#include "linkcommon.h"
#include <stdio.h>

int main(int argc, char **argv)
{
  struct ldp_interface *intf;
  struct ldp_interface_settings settings = LDP_INTERFACE_SETTINGS_EMPTY;
  if (argc != 2)
  {
    printf("Usage: testldp netmap:eth0\n");
    return 1;
  }
  settings.rss_set = 1;
  settings.rss.udp4 = RSS_OPT_DST_PORT | RSS_OPT_DST_IP;
  settings.rss.udp4_set = 1;
  intf = ldp_interface_open_2(argv[1], 1, 1, &settings);
  if (intf == NULL)
  {
    perror("Can't open interface");
    return 1;
  }
  if (ldp_interface_link_wait(intf) != 0)
  {
    printf("Can't wait for link\n");
    ldp_interface_close(intf);
    return 1;
  }
  ldp_interface_close(intf);
  return 0;
}
