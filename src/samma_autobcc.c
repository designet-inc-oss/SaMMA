/*
 * samma
 *
 * Copyright (C) 2011 DesigNET, INC.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <gmime/gmime.h>
#include <dirent.h>
#include <libdgstr.h>
#include <lber.h>
#include <regex.h>

#include "mailzip_config.h"
#include "mailsave.h"
#include "log.h"
#include "maildrop.h"
#include "sendmail.h"
#include "global.h"
#include "samma_autobcc.h"

/*
 * free_add_bccaddr()
 *
 */
void
free_add_bccaddr(struct search_res *res)
{
    if (res->ld != NULL) {
	ldap_unbind_ext_s(res->ld, NULL, NULL);
    }

    if (res->userdn != NULL) {
	free(res->userdn);
	res->userdn = NULL;
    }
}

/*
 * add_bccaddr()
 *
 * args
 *	config *cfg			pointer
 *	char *sender			string
 *	struct rcptaddr *rcptlist	pointer
 *
 * return value
 *       SUCCESS
 *       ERROR
 */
int
add_bccaddr(struct config *cfg, char *sender,
    struct rcptaddr **rcptlist, struct rcptaddr **savebcc)
{
    struct search_res res;
    char *condition = NULL;
    char *address = NULL;
    int i, rc;

    /* Initialization */
    res.ld = NULL;
    res.userdn = NULL;

    /* user policy set */
    if ((cfg->cf_userpolicy[0] == 'N') || (cfg->cf_userpolicy[0] == 'n')) {
	return SUCCESS;
    }

    /* ldapserver connect */
    res.ld = myldap_connect(cfg->cf_ldapuri, cfg->cf_ldapbinddn, cfg->cf_ldapbindpassword);
    if (res.ld == NULL) {
	free_add_bccaddr(&res);
	return ERROR;
    }

    /* get userdn */
    rc = ldap_get_userdn(res.ld, cfg->cf_ldapbasedn,
	sender, NULL, cfg->cf_ldapfilter, &res.userdn);
    if ((rc == LDAP_ERROR) || (rc == MALLOC_ERROR)) {
	free_add_bccaddr(&res);
	return ERROR;
    }

    /* get autobcc attr */
    rc = ldap_search_autobcc_attr(res.ld,
	cfg->cf_ldapbasedn, res.userdn, &condition, &address);
    if ((rc == LDAP_ERROR) || (rc == ERROR)) {
	free_add_bccaddr(&res);
	if (condition != NULL) {
	    free(condition);
	}
	if (address != NULL) {
	    free(address);
	}
	return ERROR;
    }
    else if (rc == BCC_NO_ENTRY) {
	condition = strdup(cfg->cf_defaultautobccconditionstring);
	if (condition == NULL) {
	    log(ERR_MEMORY_ALLOCATE, "add_bccaddr", "condition", strerror(errno));
	    free_add_bccaddr(&res);
	    return ERROR;
	}
	address = strdup(cfg->cf_defaultautobccmailaddr);
	if (address == NULL) {
	    log(ERR_MEMORY_ALLOCATE, "add_bccaddr", "address", strerror(errno));
	    free_add_bccaddr(&res);
	    free(condition);
	    return ERROR;
	}
    }

    // check rcpt addrlist
    rc = check_rcptlist(*rcptlist, condition);
    if (rc == ERROR) {
	free_add_bccaddr(&res);
	free(condition);
	free(address);
	return ERROR;
    }
    else if (rc == BCC_NO_MATCH) {
	/* split and push add bcc list */
	rc = split_rcptlist(savebcc, address);
	if (rc == ERROR) {
	    free_add_bccaddr(&res);
	    free(condition);
	    free(address);
	    return ERROR;
	}
	for (i = 0; (*savebcc + i)->rcpt_addr != NULL; i++) {
	    /* push rcpt addr */
	    rc = push_rcptlist(rcptlist, (*savebcc + i)->rcpt_addr);
	    if (rc != 0) {
		free_add_bccaddr(&res);
		free(condition);
		free(address);
		return ERROR;
	    }
	}
    }
    free_add_bccaddr(&res);
    free(condition);
    free(address);
    return SUCCESS;
}

/*
 * check_rcptlist()
 * 
 * args
 *       struct rcptaddr *rcptlist	pointer
 *       char *condition		string
 *
 * return value
 *       SUCCESS	success
 *	 ERROR		error
 *       BCC_NO_MATCH	no match 
 */
int
check_rcptlist(struct rcptaddr *rcptlist, char *condition)
{
    regex_t preg;
    char errbuf[REGEXERR_BUFLEN];
    char *rcptaddr = NULL;
    int i;
    int rc;

    for (i = 0; (rcptlist + i)->rcpt_addr != NULL; i++) {
	rcptaddr = (rcptlist + i)->rcpt_addr;
	DEBUGLOG("Check Rcpt Addr.(%s)", rcptaddr);

	rc = regcomp(&preg, condition, REG_EXTENDED|REG_NOSUB);
	if (rc != 0) {
	    regerror(rc, &preg, errbuf, sizeof(errbuf));
	    log(ERR_REGEX, "check_rcptlist", errbuf);
	    return ERROR;
	}

	rc = regexec(&preg, rcptaddr, 0, 0, 0);
	if (rc == 0)
	{
	    regfree(&preg);
	    return SUCCESS;
	}
    }
    regfree(&preg);
    return BCC_NO_MATCH; 
}

/*
 * split_rcptlist()
 * 
 * args
 *       struct rcptaddr *rcptlist	pointer
 *       char *address			string
 *
 * return value
 *       SUCCESS	success
 *	 ERROR		error
 */
int
split_rcptlist(struct rcptaddr **rcptlist, char *address)
{
    char *token, *saveptr;
 
    for (token = strtok_r(address, ADDRESS_DELIM, &saveptr); token != NULL;
	 token = strtok_r(NULL, ADDRESS_DELIM, &saveptr)) {
	/* push rcpt addr */
	if (push_rcptlist(rcptlist, token) != 0) {
	    return ERROR;
	}
    }
    return SUCCESS;
}

/*
 * ldap_search_autobcc_attr()
 *
 * args
 *       LDAP *ld               pointer
 *       char *ldapbasedn       string
 *       char *userdn           string
 *       char *condition        string
 *       char *address          string
 *
 * return value
 *       SUCCESS	success
 *       ERROR		error
 *       LDAP_ERROR	ldap error
 *       BCC_NO_ENTRY	no entry
 */
int
ldap_search_autobcc_attr(LDAP *ld, char *ldapbasedn,
    char *userdn, char **condition, char **address)
{
    LDAPMessage *res = NULL;
    LDAPMessage *p = NULL;
    int count;
    char *attr[3];
    struct timeval tv;
    struct berval **valp_condition;
    struct berval **valp_address;
    int lderrno;

    //timeout parameter
    tv.tv_sec  = LDAP_TIMEOUT_SEC;
    tv.tv_usec = 0;

    //attribute list
    attr[0] = BCC_STRING;
    attr[1] = BCC_ADDRES;
    attr[2] = NULL;

    //search for auto bcc attributes
    ldap_search_ext_s(ld, userdn, LDAP_SCOPE_SUBTREE, BCC_FILTER, attr, 0, NULL, NULL, &tv, 0, &res);

    //count the number of data
    count = ldap_count_entries(ld, res);
    if (count < 0) {
        ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &lderrno);
        log(ERR_LDAP_COUNT , "ldap_search_autobcc_attr", ldap_err2string(lderrno));
        ldap_msgfree(res);
        return LDAP_ERROR;
    }
    else if (count == 0) {
        ldap_msgfree(res);
        return BCC_NO_ENTRY;
    }

    //find condition string and bcc address
    for (p = ldap_first_entry(ld, res); p != NULL ; p = ldap_next_entry(ld, p)) {

	//get condition string
	valp_condition = ldap_get_values_len(ld, p, BCC_STRING);
	if (valp_condition == NULL) {
	    log(ERR_LDAP_VALUE, "ldap_search_autobcc_attr", ldap_err2string(lderrno));
	    break;
	}

	// set condition string
	*condition = strdup(valp_condition[0]->bv_val);
	if (condition == NULL) {
	    log(ERR_MEMORY_ALLOCATE, "ldap_search_autobcc_attr", "condition", strerror(errno));
	    ldap_value_free_len(valp_condition);
	    break;
	}
	ldap_value_free_len(valp_condition);

	//get address
	valp_address = ldap_get_values_len(ld, p, BCC_ADDRES);
	if (valp_address == NULL) {
	    log(ERR_LDAP_VALUE, "ldap_search_autobcc_attr", ldap_err2string(lderrno));
	    break;
	}  

	if (strlen(valp_address[0]->bv_val) == 0) {
	    log(ERR_LDAP_VALUE, "ldap_search_autobcc_attr",
				"autoBccMailAddress is NULL");
	    ldap_value_free_len(valp_address);
	    break;
	}

	// set address
	*address = strdup(valp_address[0]->bv_val);
	if (address == NULL) {
	    log(ERR_MEMORY_ALLOCATE, "ldap_search_autobcc_attr", "address", strerror(errno));
	    ldap_value_free_len(valp_address);
	    break;
	}
	ldap_value_free_len(valp_address);
    }
    ldap_msgfree(res);

    if (*condition == NULL || *address == NULL) {
	return ERROR;
    } 
    return SUCCESS;
}
