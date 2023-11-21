#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmime/gmime.h>
#include "samma_policy.h"
#include <sys/types.h>
#include <sys/stat.h>

#include "mailzip_config.h"

#include "netlist.h"
#include "log.h"
#include "global.h"

#define MAX_NETLIST_LINE    1024

/*
 * get_v6mask()
 *
 * convert mask bits to netmask IPv6
 *
 * Args:
 *   int mask                     mask bits
 *   struct in6_addr *addr        netmask IPv6                     
 *
 * Return value:
 *   SUCCESS       0     success
 *   ERROR         -1    error
 *
 */
int
get_v6mask(int mask, struct in6_addr *addr)
{
    int c, ret;
    int maskset[] = {0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff};

    if(mask < 1 || mask > 128) {
        return ERROR;
    }

    for (c = 0; c < 16; c++) {
        if ((c * 8) >= mask) {
            addr->s6_addr[c] = maskset[0];
        } else if (((c + 1) * 8) <= mask) {
            addr->s6_addr[c] = maskset[8];
        } else {
            ret = mask % 8;
            addr->s6_addr[c] = maskset[ret];
        }
    }
    return SUCCESS;
}

/*
 * get_v4mask()
 *
 * convert mask bits to netmask IPv4
 *
 * Args:
 *   int nummask                 Mask bits
 *   struct in_addr *addr        Netmask IPv4
 *
 * Return value:
 *   SUCCESS       0     success
 *   ERROR         -1    error
 *
 */
int
get_v4mask(int nummask, struct in_addr *addr) {
    /* mask number less than 0 or biger 32 then error */
    if (nummask < 1 || nummask > 32) {
        return ERROR;
    } 

    /* convert number mask to IP mask */
    addr->s_addr = htonl(~((1 << (32 - nummask)) - 1));

    return SUCCESS; 
}

/*
 * make_netlist_v4
 *
 * make list whitelist.
 *
 * Args:
 *   struct netlist_v4 *list      
 *   struct in_addr addr
 *   struct in_addr mask
 *
 * Return value:
 *   SUCCESS       0     success
 *   ERROR         -1    error
 *
 */
struct netlist_v4 *
make_netlist_v4(struct netlist_v4 *list, struct in_addr addr,
                struct in_addr mask)
{
    /* define struct */
    struct netlist_v4 *st, *p;

    /* allocate memory  */
    st = (struct netlist_v4*)malloc(sizeof(struct netlist_v4));
    if (st == NULL) {
        return NULL;
    }
    /* setting value of struct  */
    st->nl_addr = addr;
    st->nl_mask = mask;
    st->nl_next = NULL;

    /* if List is NULL */
    if (list == NULL) {
        return st;
    }else {
        p = list;
        /* find the lastest element of list */
        while (p->nl_next != NULL) {
            p = p->nl_next;
        }    
        p->nl_next = st;
    }
    
    return list; 
}

/*
 * make_netlist_v6
 *
 * make list whitelist.
 *
 * Args:
 *   struct netlist_v6 *list      
 *   struct in_addr addr
 *   struct in_addr mask
 *
 * Return value:
 *   SUCCESS       0     success
 *   ERROR         -1    error
 *
 */
struct netlist_v6 *
make_netlist_v6(struct netlist_v6 *list, struct in6_addr addr,
                struct in6_addr mask)
{
    /* define  struct */
    struct netlist_v6 *st, *p;

    /* allocate memory */
    st = (struct netlist_v6*)malloc(sizeof(struct netlist_v6));
    if (st == NULL) {
        return NULL;
    }

    /* setting value  */
    st->nl_addr = addr;
    st->nl_mask =  mask;
    st->nl_next = NULL;

    /* if list is empty */
    if (list == NULL) {
        list = st;
        return list;
    }else {
        p = list;
        /* find the lasest element of lsit */
        while (p->nl_next != NULL) {
            p = p->nl_next;
        }    
        p->nl_next = st;
    }
    
    return list; 
}


/*
 * netlist4_free
 *
 * free list ipv4
 *
 * Args:
 *   struct netlist_v4 *top      
 *
 * Return value:
 *
 */
void
netlist4_free(struct netlist_v4 *top)
{
    struct netlist_v4 *p;
    struct netlist_v4 *next;
    for(p = top; p != NULL; p = next) {
        next = p->nl_next;
        free(p);
    }

    return;
}

/*
 * netlist6_free
 *
 * free list ipv6
 *
 * Args:
 *   struct netlist_v6 *top      
 *
 * Return value:
 *
 */
void
netlist6_free(struct netlist_v6 *top)
{
    struct netlist_v6 *p;
    struct netlist_v6 *next;

    for(p = top; p != NULL; p = next) {
        next = p->nl_next;
        free(p);
    }

    return;
}

/*
 * whilelist_free
 *
 * free whitelist
 *
 * Args:
 *   struct netlist_v6 *top      
 *
 * Return value:
 *
 */
void
whilelist_free(struct whitelist *wlist)
{
    if (wlist != NULL) {
        /* free list ip v4 */
        if (wlist->listv4 != NULL) {
            netlist4_free(wlist->listv4);
        }
        /* free list ip v6 */
        if (wlist->listv6 != NULL) {
            netlist6_free(wlist->listv6);
        }

        /* free top */
        free(wlist);
    }

    return;
}

/*
 * check_in_network_v4()
 *
 * check ip belong to network
 *
 * Args:
 *   struct in_addr network    
 *   struct in_addr mask
 *   struct in_addr addr
 *
 * Return value:
 *
 */
int check_in_network_v4(struct in_addr network, 
                        struct in_addr mask, 
                        struct in_addr addr)
{
    if ((addr.s_addr & mask.s_addr) 
              == (network.s_addr & mask.s_addr)) {
        return NOT_ENC;
    }
    return ENC;
}

/*
 * check_ip_in_list()
 *
 * check ip belong to list ipv6
 *
 * Args:
 *   struct netlist_v4 *list
 *   struct in_addr ipcheck
 *
 * Return value:
 *
 */
int check_ip_in_list(struct netlist_v4 *list, struct in_addr ipcheck) 
{
    int ret;
    struct netlist_v4 *p;
    for (p = list; p != NULL; p = p->nl_next) {
        ret = check_in_network_v4(p->nl_addr, p->nl_mask, ipcheck);
        /* if not encrypt file */
        if (ret == NOT_ENC) {
           return NOT_ENC;
        }
    }

    return ENC;
}

/*
 * check_range_ipv6()
 *
 * check ip belong to list ipv6
 *
 * Args:
 *   struct in6_addr addr
 *   struct in6_addr mask
 *   struct in6_addr ipv6
 *
 * Return value:
 *
 */
int 
check_range_ipv6(struct in6_addr addr, struct in6_addr mask,
                         struct in6_addr ipv6) 
{
    int i;

    /* full bit */
    struct in6_addr tmp_ipv6;
    struct in6_addr tmp_addr;

    for (i = 0; i < 16; i++) {
        tmp_addr.s6_addr[i] = addr.s6_addr[i] & mask.s6_addr[i];
    }

    for (i = 0; i < 16; i++) {
        tmp_ipv6.s6_addr[i] = ipv6.s6_addr[i] & mask.s6_addr[i];
    }

    for (i = 0; i < 16; i++) {
        if (tmp_addr.s6_addr[i] != tmp_ipv6.s6_addr[i]) {
            return ENC;    
        }
    }

    return NOT_ENC;
}

/*
 * check_ip_in_list()
 *
 * check ip belong to list ipv6
 *
 * Args:
 *   struct netlist_v4 *list
 *   struct in_addr ipcheck
 *
 * Return value:
 *
 */
int check_ip_in_list6(struct netlist_v6 *listipv6, struct in6_addr ipcheck) 
{
    int ret = 0;
    struct netlist_v6 *p;
    for (p = listipv6; p != NULL; p = p->nl_next) {
       ret = check_range_ipv6(p->nl_addr, p->nl_mask, ipcheck);
       if (ret == NOT_ENC) {
           return NOT_ENC;
       } 
    }
    return ENC;
}

/*
 * check_whitelist_file()
 *
 * check whitelist file
 *
 * Args:
 *   int typecheck
 *   char *stripcheck
 *
 * Return value:
 *    ENC              encrypt attachment file
 *    NOT_ENC          do not encrypt attachment file
 */
int
check_whitelist_file(int typecheck, char *stripcheck)
{
    int ret;
    struct in_addr ipv4;
    struct in6_addr ipv6;
    struct whitelist *wlist = NULL;

    /* init whilist */
    wlist = whitelist_init();

    if (wlist == NULL) {
        whitelist_release(wlist);
        return ENC;
    }

    /* if type check is IPv4*/
    if (typecheck == AF_INET) {
        /* store  ip address */
        if (!inet_aton(stripcheck, &ipv4)) {
            /* release whitelist */
            whitelist_release(wlist);
            log(ERR_WHITELIST_INVALID_IP, "check_whitelist_file", stripcheck);
            return ENC;
        }

        /* check whether list contain ipv4 */
        ret = check_ip_in_list(wlist->listv4, ipv4);

        if (ret == NOT_ENC) {
            /* release whitelist */
            whitelist_release(wlist);
            return NOT_ENC;
        }

        /* release whitelist */
        whitelist_release(wlist);

    } else {
        if (inet_pton(AF_INET6, stripcheck, &ipv6) != 1) {
            /* release whitelist */
            whitelist_release(wlist);
            log(ERR_WHITELIST_INVALID_IP, "check_whitelist_file", stripcheck);
            return ENC;
        }
       
        /* check whether list contain ipv6 */
        ret = check_ip_in_list6(wlist->listv6, ipv6);
        if (ret == NOT_ENC) {
            /* release whitelist */
            whitelist_release(wlist);
            return NOT_ENC;
        }

        /* release whitelist */
        whitelist_release(wlist);
    }

    return ENC;
}

/*
 * whitelist_read()
 *
 * Read the whitelist file.
 *
 * Args:
 *   struct whitelist **whitelist_data      pointer
 *   char *whitelist_file                   whitelist file path
 *
 * Return value:
 *   SUCCESS       0     success
 *   ERROR         -1    error
 *
 */
int
whitelist_read(struct whitelist **whitelist_data, char *whitelist_file) 
{
    struct netlist_v4 *list = NULL;
    struct netlist_v6 *list6 = NULL;
    
    struct whitelist *wlist = NULL;

    /* ipv4 */
    struct in_addr addr, netmask;

    /* ipv6 */
    struct in6_addr addr6, netmask6;

    int maskbits;
    int ret;
    char * end;
    char *strmask = NULL;
    char *straddr = NULL;
    
    FILE *fp;
    char *p = NULL;
    char *tmp_p = NULL;

    /* if value offlg_type_ipv6 is NULL then address is IP V4 */
    char *flg_type_ipv6; 
    char line[MAX_NETLIST_LINE + 1];

    /* current line when read file */
    int linenum;
    
    /* open file whilelist */
    fp = fopen(whitelist_file, "r");
    if (fp == NULL) {
        systemlog(ERR_FILE_OPEN, "whilelist_read", whitelist_file);
        *whitelist_data = NULL;
        return SUCCESS;
    }

    linenum = 0;
    /* read line by line in file */
    while (fgets(line, MAX_NETLIST_LINE + 1, fp) != NULL) {
        linenum++;

        /* the end char do not exist*/
        if(strchr(line, '\n') == NULL) {
            /* free memory */
            if (list != NULL) {
                netlist4_free(list);
            }
            if (list6 != NULL) {
                netlist6_free(list6);  
            }
            return ERROR;
        }

        /* ignore comment, break line */
        if((line[0] == '#') || (line[0] == '\n')) {
            continue;
        }

        /* remove break line */
        tmp_p = strpbrk(line, "\n");
        if (tmp_p != NULL) {
            /* remove break line */
            *tmp_p = '\0';
        }

        flg_type_ipv6 = NULL;
        flg_type_ipv6 = strchr(line, ':');
       
        /* found slash */
        p = strchr(line, '/');

        if (p != NULL) {
            *p = '\0';
            p++;
            strmask = strdup(p);
            straddr = strdup(line);

            /* convert char to int */
            maskbits = strtol(strmask, &end, 10);

            /* mask is not number */
            if (*end != '\0') {

                /* free memory */
                if (list != NULL) {
                    netlist4_free(list);
                }
                if (list6 != NULL) {
                    netlist6_free(list6);
                }

                systemlog(ERR_WHITELIST_MASK_NOT_NUM, "whitelist_read", strmask, linenum);
                return ERROR;
            }

        } else {
            straddr = strdup(line);
            if (flg_type_ipv6 == NULL) {
                 maskbits = 32;
            } else {
                 maskbits = 128;
            }
        }

        /* IP is IPV4 */
        if (flg_type_ipv6 == NULL) {
            /* convert number to ipv4 address */
            ret = get_v4mask(maskbits, &netmask);
            if (ret == ERROR) {
                /* free memory */
                if (list != NULL) {
                    netlist4_free(list);
                }
                if (list6 != NULL) {
                    netlist6_free(list6);
                }

                systemlog(ERR_WHITELIST_MASK_RANGEV4, "whitelist_read", maskbits, linenum);
                return ERROR;
            }

            /* store  ip address */
            if (!inet_aton(straddr, &addr)) {
                /* free memory */
                if (list != NULL) {
                    netlist4_free(list);
                }
                if (list6 != NULL) {
                    netlist6_free(list6);
                }

                systemlog(ERR_WHITELIST_IP_INVALID, "whitelist_read", straddr, linenum );
                return ERROR;
            }

            /* save to netlist v4 */
            list = make_netlist_v4(list, addr, netmask);
            if (list == NULL) {
                systemlog(ERR_MEMORY_ALLOCATE, "whitelist_read", "list", strerror(errno));
                return ERROR;
            }
         } else {

            /* convert number to ipv6 address */
            ret = get_v6mask(maskbits, &netmask6);
            if (ret == ERROR) {

                /* free memory */
                if (list != NULL) {
                    netlist4_free(list);
                }
                if (list6 != NULL) {
                    netlist6_free(list6);
                }

                systemlog(ERR_WHITELIST_MASK_RANGEV6, "whitelist_read", maskbits, linenum);
                return ERROR;
             }
            
             if (inet_pton(AF_INET6, straddr, &addr6) != 1) {
                /* free memory */
                if (list != NULL) {
                    netlist4_free(list);
                }
                if (list6 != NULL) {
                    netlist6_free(list6);
                }

                systemlog(ERR_WHITELIST_IP_INVALID, "whitelist_read", straddr, linenum);
                return ERROR;
             }

            /* save to netlist v6*/
            list6 = make_netlist_v6(list6, addr6, netmask6);
            if (list6 == NULL) {
                systemlog(ERR_MEMORY_ALLOCATE, "whitelist_read", "list6", strerror(errno));
                return ERROR;
            }
        }
            

        free(strmask);
        free(straddr);
        strmask = NULL;
        straddr = NULL;
    
    }

    /* close file whilelist */
    fclose(fp);

    /* allocate memory */
    wlist = (struct whitelist*)malloc(sizeof(struct whitelist));
    if (wlist == NULL) {
        /* free memory */
        if (list != NULL) {
           netlist4_free(list);
        }
        if (list6 != NULL) {
           netlist6_free(list6);
        }

        systemlog(ERR_MEMORY_ALLOCATE, "whitelist_read", "wlist", strerror(errno));
        return ERROR;
    } else {
        wlist->listv4 = list;
        wlist->listv6 = list6;
    }

    *whitelist_data = wlist;

    return SUCCESS;    
}





