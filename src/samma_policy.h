/*
 * samma
 *
 * Copyright (C) 2006,2007,2008 DesigNET, INC.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/*
 * $RCSfile$
 * $Revision$
 * $Date$
 */

#ifndef _SAMMA_POLICY_H_
#define _SAMMA_POLICY_H_

#include <ldap.h>
#include "zipconv.h"

#define OTHERKEYWORD    "other"
#define ATMARK 		'@'
#define DOT    		'.'
#define NOT_ENC   0    //NOT DELETE in delete mode.
#define ENC       1    //DELETE in delete mode.
#define UNDEF_ENC 2    //Undefined encryption mode.

#define ADDENCLIST_ERR	-1
#define RECORD_FOUND	1
#define RECORD_NOTFOUND	2
#define ADD_LIST_SUCCESS	0

/* LDAP */
#define ENC_ADDR "mailEncryptionAddr"
#define ENC_PASS "mailEncryptionPassword"
#define LDAP_EXC_MARK_ESC "\\21"
#define PART_FILTER_FORM "(%s=%s%s)(%s=%s)" 
#define PART_FILTER_LEN (sizeof(ENC_ADDR) - 1) * 2 + (sizeof(LDAP_EXC_MARK_ESC) - 1) + 6
#define FILTER_FORM "(|%s)" 
#define URI "ldap://%s:%d/"
#define URILEN 10
#define LDAP_ERROR	-1
#define FILTER_CREATE	1
#define FILTER_ERR	-1
#define CLOSE_LEN 2
#define LDAP_CONNECT 1
#define VALUENULL 2
#define LDAP_TIMEOUT_SEC 5
#define PORT_MAX_LEN 5
#define IP_MAX_LEN 15
#define CONVERSION_STR_LEN 2
#define EXTENSION_CHAR  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`~!@#$%^&*()_+-={}|[]:\\\";'<>?.,"

struct search_res {
    char	*onetime_pass;
    DB		*rcpt_dbp;
    DB		*ext_dbp;
    DB		*comm_dbp;
    LDAP 	*ld;
    char	*userdn;
};

struct person {
    char        *addr;
    char        *pass;
    int         addr_len;
};

int search_rcptaddr(struct config *, char *, struct rcptaddr *, struct rcptinfo **, struct rcptinfo **);
int search_rcptaddr_delmode(struct config *, struct rcptaddr *, struct rcptinfo **, struct rcptinfo **);
int add_enclist(struct config *cfg, struct rcptinfo ***, char *, char *, char *, DB *, char *, DB *, char *);
int search_fromaddr_bdb(struct config *, char *);
int search_subdomain_bdb(DB *, const char *, char *, char **, char **);
int mk_passwd(char **, int);
int search_str_bdb(DB *, const char *, char *, char *, char **);
int make_filter (char *, char **);
LDAP * myldap_connect(char *, char *, char *);
int ldap_search_policy(LDAP *, char *, char *, char*, struct person *);
int ldap_get_userdn(LDAP *, char *, char *, char *, char *, char **);
int search_rcptaddr_bdb(struct search_res *, struct config *, char *, struct rcptinfo **, struct rcptinfo **);
int make_part_filter(char **, char *, char *, int *);
int check_default_policy(int, struct search_res *, struct config *, char *, struct rcptinfo **, struct rcptinfo **);
int search_rcptaddr_ldap(struct search_res *, struct config *, char *, struct rcptinfo **, struct rcptinfo **);
int set_priority_addr (struct person *, struct berval **, struct berval **);
char *str_tolower (char *);
int check_validation_of_ext(struct config *, char *);
int search_ext_bdb(DB *, const char *, char *, char **);

#endif /*_SAMMA_POLICY_H_*/
