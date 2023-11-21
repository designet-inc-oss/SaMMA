#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*******************************
 *  struct IPv4
*******************************/
struct netlist_v4 {
     struct netlist_v4 *nl_next;
     struct in_addr  nl_addr;
     struct in_addr  nl_mask;
};

/*******************************
 *  struct IPv6
*******************************/
struct netlist_v6 {
     struct netlist_v6 *nl_next;
     struct in6_addr nl_addr;
     struct in6_addr nl_mask;
};


/*******************************
 *  struct whitelist
 ******************************/
struct whitelist {
     struct netlist_v4 *listv4;
     struct netlist_v6 *listv6;
};

int check_whitelist_file(int , char *);
int whitelist_read(struct whitelist **, char *);
void display_netlist6(struct netlist_v6 *);
void whilelist_free(struct whitelist *);
