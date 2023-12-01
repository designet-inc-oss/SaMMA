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
#include <pthread.h>
#include <libdgstr.h>
#include <lber.h>

#include "mailzip_config.h"
#include "mailsave.h"
#include "log.h"
#include "mailzip_db.h"
#include "maildrop.h"
#include "sendmail.h"
#include "global.h"
#include "samma_policy.h"

#define DEFALT_ENCSTR_YES	"yes"

pthread_mutex_t pw_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * search_rcptstr_bdb()
 *
 * Rcpt addr of RCTPDB is retrieved.(mail address or FQDN) 
 *
 * struct search_res *res
 * config *cfg
 * char *rcptaddr			Recipient address
 * char *searchstr			Search string
 * struct rcptinfo **passlist		List encrypted by fixed password
 * struct rcptinfo ** rdmpasslist	List encrypted by random password
 *
 * return value
 *       ENC            encryption
 *       NOT_ENC        no encryption
 *       DB_ERROR       db error
 *       MALLOC_ERROR   alloc error
 */
int
search_rcptstr_bdb(struct search_res *res, struct config *cfg,
                   char *rcptaddr, char *searchstr,
                   struct rcptinfo **passlist, struct rcptinfo **rdmpasslist)
{
    int ret;
    char *noenc_searchstr = NULL;
    char *passwd = NULL;
    struct tm *ti;
    time_t now;
    char tmppass[BUFSIZE];

    /* make noenc_searchstr (addr + [!] + \0) */
    noenc_searchstr = malloc(strlen(searchstr) + 2);
    if (noenc_searchstr == NULL) {
        log(ERR_MEMORY_ALLOCATE, "search_rcptstr_bdb", "noenc_searchstr", strerror(errno));
        return MALLOC_ERROR;
    }

    /* search noenc_searchstr */
    sprintf(noenc_searchstr , "!%s", searchstr);

    ret = search_str_bdb(res->rcpt_dbp, cfg->cf_rcptdbpath,
                             searchstr, noenc_searchstr, &passwd);
    if (ret == DB_ERROR) {
        if (passwd != NULL) {
            free(passwd);
            passwd = NULL;
        }
	free(noenc_searchstr);
        return DB_ERROR;
    }
    if (ret == NOT_ENC) {
        DEBUGLOG("Not Encryption: [!]Rcpt address found.(%s)", noenc_searchstr);
        if (passwd != NULL) {
            free(passwd);
            passwd = NULL;
        }
	free(noenc_searchstr);
	return NOT_ENC;
    }
    if (ret == ENC) {
        if (passwd != NULL) {
            /* Add address list */
            /* get now time */
            time(&now);
            ti = localtime(&now);

            strftime(tmppass, BUFSIZE - 1, passwd, ti);
            free(passwd);
            passwd = NULL;

            if (add_enclist(cfg, &passlist, searchstr, rcptaddr, tmppass,
                            res->ext_dbp, cfg->cf_extensiondbpath, res->comm_dbp, cfg->cf_commanddbpath) != 0) {
                free(noenc_searchstr);
                return MALLOC_ERROR;
            }
            DEBUGLOG("Add keyword to passlist structure.(%s)", searchstr);
            free(passwd);
            passwd = NULL;
        } else {
            /* Add rdmpasslist list */
            if (add_enclist(cfg, &rdmpasslist, searchstr, rcptaddr,
                            res->onetime_pass, res->ext_dbp,
                            cfg->cf_extensiondbpath, res->comm_dbp, cfg->cf_commanddbpath) != 0) {
                free(noenc_searchstr);
                return MALLOC_ERROR;
            }
            DEBUGLOG("Add keyword to rdmpasslist structure.(%s)", searchstr);
        }
	free(noenc_searchstr);
	return ENC;
    }

    free(noenc_searchstr);
    return RECORD_NOTFOUND;
}

/*
 * free_search_rcptaddr()
 *
 */
void
free_search_rcptaddr(struct search_res *res)
{
    if (res->onetime_pass != NULL) {
	free(res->onetime_pass);
	res->onetime_pass = NULL;
    }

    if (res->rcpt_dbp != NULL) {
	db_close(res->rcpt_dbp);
    }

    if (res->ext_dbp != NULL) {
	db_close(res->ext_dbp);
    }

    if (res->comm_dbp != NULL) {
	db_close(res->comm_dbp);
    }

    if (res->ld != NULL) {
	ldap_unbind_ext_s(res->ld, NULL, NULL);
    }

    if (res->userdn != NULL) {
	free(res->userdn);
	res->userdn = NULL;
    }
}

/*
 * search_rcptaddr()
 *
 * Rcpt addr of RCTPDB is retrieved.
 *
 * config *cfg      			cfg pointer
 * struct rcptaddr *rcptlist		rcpt addr list
 * struct rcptinfo **passlist		List encrypted by fixed password
 * struct rcptinfo ** rdmpasslist	List encrypted by random password
 *
 * return value
 *       ENC        	encryption
 *       NOT_ENC    	no encryption
 *       ERROR   	bdb or ldap error
 *       MALLOC_ERROR   alloc error
 */
int
search_rcptaddr(struct config *cfg, char *sender, struct rcptaddr *rcptlist, struct rcptinfo **passlist, struct rcptinfo ** rdmpasslist)
{
    int i, ret, enc_status = NOT_ENC;
    int default_policy = NOT_ENC;
    int user_policy = NOT_ENC;
    char *rcptaddr = NULL;
    //int rcptaddrlen = 0;
    int pass_len = cfg->cf_passwordlength;
    int defalt_pass_len = 0;
    struct search_res res;

    /* Initialization */
    memset(&res, 0, sizeof(res));

    /* make onetime password */
    ret = mk_passwd(&res.onetime_pass, pass_len);
    if (ret != PASSWD_SUCCESS) {
        return MALLOC_ERROR;
    }
    DEBUGLOG("Make password ok");

    /* default policy set */
    if ((cfg->cf_defaultencryption[0] == 'Y') || (cfg->cf_defaultencryption[0] == 'y')) {
        default_policy = ENC;
        defalt_pass_len = strlen(cfg->cf_defaultpassword);
    }

    /* user policy set */
    if ((cfg->cf_userpolicy[0] == 'Y') || (cfg->cf_userpolicy[0] == 'y')) {
        user_policy = ENC;

        /* ldapserver connect */
        res.ld = myldap_connect(cfg->cf_ldapuri, cfg->cf_ldapbinddn, 
                cfg->cf_ldapbindpassword);
        if (res.ld == NULL) {
            free_search_rcptaddr(&res);
            return ERROR;
        }

        /* get userdn */
        ret = ldap_get_userdn(res.ld, cfg->cf_ldapbasedn, sender, rcptaddr, 
                cfg->cf_ldapfilter, &res.userdn);
        if ((ret == LDAP_ERROR) || (ret == MALLOC_ERROR)) {
            free_search_rcptaddr(&res);
            return ERROR;
        } else if (ret == NOT_ENC) {
            user_policy =NOT_ENC;
        }
    }

    /* rcptdb open */
    ret = db_open(&res.rcpt_dbp, cfg->cf_rcptdbpath, cfg->cf_rcptdbtype);
    if (ret == DB_ERROR) {
        free_search_rcptaddr(&res);
        return ERROR;
    }

    if (cfg->cf_extensiondb && cfg->cf_extensiondb[0] != '\0') {
        /* extension db open */
        ret = db_open(&res.ext_dbp, cfg->cf_extensiondbpath,  cfg->cf_extensiondbtype);
        if (ret == DB_ERROR) {
            free_search_rcptaddr(&res);
            return ERROR;
        }
    }

    if (cfg->cf_commanddb && cfg->cf_commanddb[0] != '\0') {
        /* command db open */
        ret = db_open(&res.comm_dbp, cfg->cf_commanddbpath,  cfg->cf_commanddbtype);
        if (ret == DB_ERROR) {
            free_search_rcptaddr(&res);
            return ERROR;
        }
    }

    for (i = 0; (rcptlist + i)->rcpt_addr != NULL; i++) {
        rcptaddr = (rcptlist + i)->rcpt_addr;
        //rcptaddrlen = (rcptlist + i)->rcpt_addr_len;
        DEBUGLOG("Check Rcpt Addr.(%s)", rcptaddr);

        /* Berkeleydb check */
        ret = search_rcptaddr_bdb(&res, cfg, rcptaddr, passlist, rdmpasslist);
        if (ret < 0) {
            free_search_rcptaddr(&res);
            return ERROR;
        } else if (ret != RECORD_NOTFOUND) {
            enc_status = ENC;
            continue;
        }

        /* default policy check */
        if (default_policy == ENC) {
            enc_status = ENC;
            ret = check_default_policy(defalt_pass_len, &res, cfg, rcptaddr, 
                    passlist, rdmpasslist);
            if (ret != ADD_LIST_SUCCESS) {
                free_search_rcptaddr(&res);
                return ERROR;
            }
            continue;
        }

        /* user policy check */
        if (user_policy == ENC) {
            ret = search_rcptaddr_ldap(&res, cfg, rcptaddr,
                                       passlist, rdmpasslist);
            if (ret == ERROR) {
                free_search_rcptaddr(&res);
                return ERROR;
            } else if (ret == NOT_ENC) {
                continue;
            }
            if (ret != UNDEF_ENC) {
                enc_status = ENC;
                // case ret == ENC: already added to encryption rcpt list
                //       so continue anyway
                continue;
            }
        }

        /* default user policy check */
        if ((cfg->cf_userpolicy[0] == 'Y' || cfg->cf_userpolicy[0] == 'y')
             && (cfg->cf_userdefaultencryption[0] == 'Y'
                 || cfg->cf_userdefaultencryption[0] == 'y')) {
            // case UserPolicy is yes, UserDefaultPolicy is yes,
            //      and recipient is not in userdata of the sender on LDAP
            enc_status = ENC;
            ret = check_default_policy(defalt_pass_len, &res, cfg, rcptaddr, 
                    passlist, rdmpasslist);
            if (ret != ADD_LIST_SUCCESS) {
                free_search_rcptaddr(&res);
                return ERROR;
            }
        }

    } // rcpt addrlist loop

    free_search_rcptaddr(&res);

    return enc_status;
}

/*
 * search_rcptaddr_delmode()
 *
 * Rcpt addr of RCTPDB is retrieved.
 *
 * ------------------------------------------------------------
 *  DB Search Result | Corresponding Action | Return Value,
 *  or policy        |                      | i.e., enc_status
 * ------------------------------------------------------------
 *  ENC              | DELETE               | ENC
 *  NOT_ENC          | NOT DELETE           | NOT_ENC
 * ------------------------------------------------------------
 *
 * config *cfg      			cfg pointer
 * struct rcptaddr *rcptlist		rcpt addr list
 * struct rcptinfo **passlist		List to delete with dummy password
 * struct rcptinfo **rdmpasslist        a dummy and empty list 
 *
 * return value
 *       ENC        	Delete.
 *       NOT_ENC    	Not Delete.
 *       ERROR   	bdb error
 *       MALLOC_ERROR   alloc error
 */
int
search_rcptaddr_delmode(struct config *cfg, struct rcptaddr *rcptlist, struct rcptinfo **passlist, struct rcptinfo ** rdmpasslist)
{
    int i, ret; 
    int enc_status = NOT_ENC; 
    int default_policy = NOT_ENC;
    char *rcptaddr = NULL;
    //int rcptaddrlen = 0;
    int pass_len = 0;
    int defalt_pass_len = 0;
    struct search_res res;

    /* Initialization */
    memset(&res, 0, sizeof(res));

    /* make onetime password */
    ret = mk_passwd(&res.onetime_pass, pass_len);// res.onetime_pass = '\0' when pass_len = 0.
    if (ret != PASSWD_SUCCESS) {
        return MALLOC_ERROR;
    }
    DEBUGLOG("Make password ok");


    /* default policy set */
    if (ismode_delete) {
        if ((cfg->cf_defaultdeletepolicy[0] == 'Y') || (cfg->cf_defaultdeletepolicy[0] == 'y')) {
            default_policy = ENC;
        }
    } else if (ismode_harmless) {
        if ((cfg->cf_defaultsendercheck[0] == 'Y') || (cfg->cf_defaultsendercheck[0] == 'y')) {
            default_policy = ENC;
        }
    }


    /* rcptdb open */
    ret = db_open(&res.rcpt_dbp, cfg->cf_rcptdbpath, cfg->cf_rcptdbtype);
    if (ret == DB_ERROR) {
        free_search_rcptaddr(&res);
        return ERROR;
    }

    for (i = 0; (rcptlist + i)->rcpt_addr != NULL; i++) {
        rcptaddr = (rcptlist + i)->rcpt_addr;
        //rcptaddrlen = (rcptlist + i)->rcpt_addr_len;
        DEBUGLOG("Check Rcpt Addr.(%s)", rcptaddr);

        /* Berkeleydb check */
        ret = search_rcptaddr_bdb(&res, cfg, rcptaddr, rdmpasslist, rdmpasslist);
        if (ret < 0) {
            free_search_rcptaddr(&res);
            return ERROR;
        } else if (ret != RECORD_NOTFOUND) {
            enc_status = ENC;
            continue;
        }

        /* default policy check */
        if (default_policy == ENC) {
            // Add address to DELETE list, i.e., rdmpasslist.
            // Note that no checks works in check_default_policy() in delete mode.
            ret = check_default_policy(defalt_pass_len, &res, cfg, 
                                       rcptaddr, rdmpasslist, rdmpasslist);
            if (ret != ADD_LIST_SUCCESS) {
                free_search_rcptaddr(&res);
                return ERROR;
            }
            enc_status = ENC;
        }
    } // rcpt addrlist loop

    free_search_rcptaddr(&res);

    return enc_status;
}

/*
 * search_rcptaddr_ldap()
 *
 * Rcpt addr of LDAP is retrieved.
 *
 * struct search_res res		resource pointer
 * config *cfg      			cfg pointer
 * char *rcptaddr      			Recipient address
 * struct rcptinfo **passlist		List encrypted by fixed password
 * struct rcptinfo ** rdmpasslist	List encrypted by random password
 *
 * return value
 *       ENC            encryption
 *       NOT_ENC        no encryption
 *       UNDEF_ENC      undefined user on ldap: follow the site-policies
 *       ERROR          database error
 *	 MALLOC_ERROR       alloc error
 */
int
search_rcptaddr_ldap(struct search_res *res, struct config *cfg, 
		     char *rcptaddr, struct rcptinfo **passlist, 
		     struct rcptinfo ** rdmpasslist)
{
    int ret;
    struct person data;
    struct tm *ti;
    time_t now;
    char pass[BUFSIZE];
    char *searchaddr =NULL;

    data.addr = NULL;
    data.pass = NULL;
    data.addr_len = 0;

    /* translate lower string */
    searchaddr = str_tolower(rcptaddr);
    if (searchaddr == NULL) {
        /* malloc error */
        return MALLOC_ERROR;
    }
    
    ret = ldap_search_policy(res->ld, cfg->cf_ldapbasedn, searchaddr, 
			      res->userdn, &data);
    free(searchaddr);
    if ((ret == LDAP_ERROR) || (ret == MALLOC_ERROR)) {
        return ERROR;
    } else if (ret == NOT_ENC) {
	return NOT_ENC;
    } else if (ret == UNDEF_ENC) {
        return UNDEF_ENC;
    }
    DEBUGLOG("UserPolicy found.(%s)", data.addr);

    if (data.pass != NULL) {
        /* get now time */
        time(&now);
        ti = localtime(&now);

        strftime(pass, BUFSIZE - 1, data.pass, ti);
        free(data.pass);
        data.pass = NULL;
    
	/* Add address list */

        if (add_enclist(cfg, &passlist, rcptaddr, rcptaddr, pass,
                        res->ext_dbp, cfg->cf_extensiondbpath, res->comm_dbp, cfg->cf_commanddbpath) != 0) {
            return ERROR;
        }
        DEBUGLOG("Add keyword to passlist structure.(%s)", rcptaddr);
    } else {
        /* Add rdmpasslist list */
        if (add_enclist(cfg, &rdmpasslist, rcptaddr, rcptaddr,
                        res->onetime_pass, res->ext_dbp,
                        cfg->cf_extensiondbpath, res->comm_dbp, cfg->cf_commanddbpath) != 0) {
            return ERROR;
        }
        free(data.addr);
        data.addr = NULL;
        DEBUGLOG("Add keyword to rdmpasslist structure.(%s)", rcptaddr);
    }

    return ENC;
}

/*
 * check_default_policy()
 *
 * Check Default Plicy.
 *
 * int defalt_pass_len			Default Password Length
 * struct search_res res		resource pointer
 * config *cfg      			cfg pointer
 * char *rcptaddr      			Recipient address
 * struct rcptinfo **passlist		List encrypted by fixed password
 * struct rcptinfo ** rdmpasslist	List encrypted by random password
 *
 * return value
 *	 ADD_LIST_SUCCESS	Success.
 *       MALLOC_ERROR   	allocate error
 */
int
check_default_policy(int defalt_pass_len, struct search_res *res, struct config *cfg, 
		     char *rcptaddr, struct rcptinfo **passlist, 
		     struct rcptinfo ** rdmpasslist)
{
    struct tm *ti;
    time_t now;
    char pass[BUFSIZE];

    if (defalt_pass_len > 0) {
        DEBUGLOG("DefaultPolicy YES: DefaultPassword YES.(%s)", rcptaddr);
        /* get now time */
        time(&now);
        ti = localtime(&now);

        strftime(pass, BUFSIZE - 1, cfg->cf_defaultpassword, ti);

        /* Add address list */
        if (add_enclist(cfg, &passlist, rcptaddr, rcptaddr, pass,
                        res->ext_dbp, cfg->cf_extensiondbpath, res->comm_dbp, cfg->cf_commanddbpath) != 0) {
            return MALLOC_ERROR;
        }

        DEBUGLOG("Add keyword to passlist structure.(%s)", rcptaddr);
    } else {
	DEBUGLOG("DefaultPolicy YES: DefaultPassword NO.(%s)", rcptaddr);

        /* Add rdmpasslist list */
        if (add_enclist(cfg, &rdmpasslist, rcptaddr, rcptaddr,
                        res->onetime_pass, res->ext_dbp,
                        cfg->cf_extensiondbpath, res->comm_dbp, cfg->cf_commanddbpath) != 0) {
            return MALLOC_ERROR;
        }

        DEBUGLOG("Add keyword to rdmpasslist structure.(%s)", rcptaddr);
    }

    return ADD_LIST_SUCCESS;
}

/*
 * search_rcptaddr_bdb()
 *
 * Rcpt addr of RCTPDB is retrieved.
 *
 * config *cfg      			cfg pointer
 * struct rcptaddr *rcptlist		rcpt addr list
 * struct rcptinfo **passlist		List encrypted by fixed password
 * struct rcptinfo ** rdmpasslist	List encrypted by random password
 *
 * return value
 *	 RECORD_FOUND		record found
 *	 RECORD_NOTFOUND	record not found
 *       DB_ERROR   		db error
 *       MALLOC_ERROR   	allocate error
 */
int
search_rcptaddr_bdb(struct search_res *res, struct config *cfg, char *rcptaddr,
		    struct rcptinfo **passlist, struct rcptinfo ** rdmpasslist)
{
    int ret;    
    char *fqdn;
    char *subdomain = NULL;
    char *passwd = NULL;
    struct tm *ti;
    time_t now;
    char tmppass[BUFSIZE];
    char *searchaddr =NULL;

    /* translate lower string */
    searchaddr = str_tolower(rcptaddr);
    if (searchaddr == NULL) {
        /* malloc error */
        return MALLOC_ERROR;
    }

    ret = search_rcptstr_bdb(res, cfg, rcptaddr, searchaddr,
                             passlist, rdmpasslist);
    if (ret < 0) {
        free(searchaddr);
        return DB_ERROR;
    } else if ((ret == NOT_ENC) || (ret == ENC)) {
        free(searchaddr);
	return RECORD_FOUND;
    }

    /* make fqdn */
    fqdn = strchr(searchaddr, ATMARK);
    if (fqdn == NULL) {
        free(searchaddr);
        return RECORD_NOTFOUND;
    }

    ret = search_rcptstr_bdb(res, cfg, rcptaddr, fqdn, passlist, rdmpasslist);
    if (ret < 0) {
        free(searchaddr);
        return DB_ERROR;
    } else if ((ret == NOT_ENC) || (ret == ENC)) {
        free(searchaddr);
	return RECORD_FOUND;
    }

    /* search subdomain */
    ret = search_subdomain_bdb(res->rcpt_dbp, cfg->cf_rcptdbpath, fqdn, &subdomain, &passwd);
    if (ret < 0) {
        free(searchaddr);
	return DB_ERROR;
    } else if (ret == NOT_ENC) {
        if (passwd != NULL) {
            free(passwd);
            passwd = NULL;
        }
        free(searchaddr);
	return RECORD_FOUND;
    }
    if (ret == ENC) {
	DEBUGLOG("Rcpt domain found.(%s)", subdomain);
        if (passwd != NULL) {
            /* Add address list */
            /* get now time */
            time(&now);
            ti = localtime(&now);

            strftime(tmppass, BUFSIZE - 1, passwd, ti);
            free(passwd);
            passwd = NULL;

            if (add_enclist(cfg, &passlist, subdomain, rcptaddr, tmppass,
                            res->ext_dbp, cfg->cf_extensiondbpath, res->comm_dbp, cfg->cf_commanddbpath) != 0) {
                free(searchaddr);
                return MALLOC_ERROR;
            }

            DEBUGLOG("Add keyword to passlist structure.(%s)", rcptaddr);
        } else {
            /* Add rdmpasslist list */
            if (add_enclist(cfg, &rdmpasslist, subdomain, rcptaddr,
                            res->onetime_pass, res->ext_dbp,
                            cfg->cf_extensiondbpath, res->comm_dbp, cfg->cf_commanddbpath) != 0) {
                free(searchaddr);
                return MALLOC_ERROR;
            }
            DEBUGLOG("Add keyword to rdmpasslist structure.(%s)", rcptaddr);
        }
        free(searchaddr);
        return RECORD_FOUND;
    }

    free(searchaddr);
    return RECORD_NOTFOUND;
}

/*
 * add_enclist()
 *
 * struct rcptinfo 	***head
 * char 		*keyword
 * char 		*addr
 * char 		*passwd
 * DB			*ext_dbp
 * char			*extensiondbpath
 * DB			*comm_dbp
 * char			*commanddbpath
 *
 * return value
 *       0		Success
 *       -1		Error
 */
int
add_enclist(struct config *cfg, struct rcptinfo ***head, char *keyword, char *addr, char *passwd, DB *ext_dbp, char *extensiondbpath, DB *comm_dbp, char *commanddbpath)
{
    struct rcptinfo *p, *tmpp = NULL, *rcptinfo;
    char *extension;
    char *command;
    char *err;
    int ret;

    if (*head != NULL) {
        for (p = **head; p != NULL; p = p->Next) {
            /* set last structure */
            tmpp = p;

            // strncmp returns 0 when p->keyword_len = 0.
            if (strncmp(p->keyword, keyword, p->keyword_len) != 0) {
                continue;
            }
            /* keyword found from rcptinfo list */
            if (push_rcptlist(&(p->rcptlist), addr) != 0) {
                return -1;
            }
            return 0;
        }
    }

    if (passwd == NULL) {
        log(ERR_PASS_MUST_BE_SET, "add_enclist");
        return -1;
    }

    /* create rcptinfo structure */
    rcptinfo = (struct rcptinfo *)malloc(sizeof(struct rcptinfo));
    if (rcptinfo == NULL) {
        log(ERR_MEMORY_ALLOCATE, "add_enclist", "rcptinfo", strerror(errno));
        return -1;
    }
    memset(rcptinfo, 0, sizeof *rcptinfo);

    /* Copy keyword to rcptinfo struction 
     * because the keyword will be freed 
     * when keyword is equivalent to the searchaddr
     * which is allocated in the function search_rcptaddr_bdb(). */
    rcptinfo->keyword = strdup(keyword);
    if (rcptinfo->keyword == NULL) {
        free(rcptinfo);
        log(ERR_MEMORY_ALLOCATE, "add_enclist", "rcptinfo->keyword", strerror(errno));
        return -1;
    }
    rcptinfo->keyword_len = strlen(keyword);

    /* allocate memory */
    rcptinfo->passwd = strdup(passwd);
    if (rcptinfo->passwd == NULL) {
        free(rcptinfo->keyword);
        free(rcptinfo);
        log(ERR_MEMORY_ALLOCATE, "add_enclist", "rcptinfo->passwd", strerror(errno));
        return -1;
    }

    if (cfg->cf_extensiondb && cfg->cf_extensiondb[0] != '\0') {
        /* set extension */
        ret = search_ext_bdb(ext_dbp, extensiondbpath, keyword, &extension);
        if (ret == DB_ERROR) {
            /* error ... */
            log(ERR_SEARCH_EXT, "add_enclist", keyword);
            free(rcptinfo->keyword);
            free(rcptinfo->passwd);
            free(rcptinfo);
            return -1;
        }

        if (extension != NULL) {
            if (check_validation_of_ext(cfg, extension) == FALSE) {
                /* validation error: Ignore extensions */
                rcptinfo->extension = NULL;
            } else {
                rcptinfo->extension = extension;
            }
        } else {
            rcptinfo->extension = NULL;
        }
    }

    if (cfg->cf_commanddb && cfg->cf_commanddb[0] != '\0') {
        /* set command */
        ret = search_ext_bdb(comm_dbp, commanddbpath, keyword, &command);
        if (ret == DB_ERROR) {
            /* error ... */
            log(ERR_SEARCH_EXT, "add_enclist", keyword);
            free(rcptinfo->keyword);
            free(rcptinfo->passwd);
            free(rcptinfo);
            return -1;
        }

        if (command != NULL) {
            if (err) {
                rcptinfo->command = NULL;
            } else {
                rcptinfo->command = command;
            }
        } else {
            rcptinfo->command = NULL;
        }
    }

    if (push_rcptlist(&(rcptinfo->rcptlist), addr) != 0) {
        if (rcptinfo->keyword) {
            free(rcptinfo->keyword);
        }
        if (rcptinfo->passwd) {
            free(rcptinfo->passwd);
        }
        if (rcptinfo->extension) {
            free(rcptinfo->extension);
        }
        if (rcptinfo->command) {
            free(rcptinfo->command);
        }
        if (rcptinfo) {
            free(rcptinfo);
        }
        return -1;
    }
    rcptinfo->Next = NULL;

    if (**head != NULL) {
        tmpp->Next = rcptinfo;
    } else {
        **head = rcptinfo;
    }

    return 0;
}

/*
 * search_subdomain_bdb()
 *
 * Check if the subdomain exists in DB.
 *
 * args:
 * DB *dbp              pointer
 * char *dbpath         string
 * char *subdomain      string
 * char **match_domain  pointer
 * char **match_passwd  pointer
 *
 * return value
 *       ENC            	encryption
 *       NOT_ENC        	no encryption
 *       RECORD_NOTFOUND	record not found
 *       DB_ERROR       	db error
 *       MALLOC_ERROR   	alloc error
 */
int
search_subdomain_bdb(DB *dbp, const char *dbpath, char *subdomain,
                     char **match_domain, char **match_passwd)
{
    char *not_subdomain;
    char *passwd = NULL;
    int ret;

    /* make not_subdomain */
    not_subdomain = malloc(strlen(subdomain) + 2);
    if (not_subdomain == NULL) {
        log(ERR_MEMORY_ALLOCATE, "search_subdomain_bdb",
                                 "not_subdomain", strerror(errno));
        return MALLOC_ERROR;
    }

    do {
        /* pointer shift */
        subdomain++;

        /* make not_subdomain */
        sprintf(not_subdomain, "!%s", subdomain);

        /* search subdomain */
        ret = search_str_bdb(dbp, dbpath,
                             subdomain, not_subdomain, &passwd);
        if (ret == DB_ERROR) {
            if (passwd != NULL) {
                DEBUGLOG("free passwd.");
                free(passwd);
                passwd = NULL;
            }
            free(not_subdomain);
            return DB_ERROR;
        }
        if (ret == NOT_ENC) {
            DEBUGLOG("NOT_Subdomain found.(%s)", not_subdomain);
            if (passwd != NULL) {
                DEBUGLOG("free passwd.");
                free(passwd);
                passwd = NULL;
            }
            free(not_subdomain);
            return NOT_ENC;
        }
        if (ret == ENC) {
            DEBUGLOG("Subdomain found.(%s)", subdomain);
            DEBUGLOG("passwd.(%s)", passwd);
            *match_passwd = passwd;
            *match_domain = subdomain;
            free(not_subdomain);
            return ENC;
        }
    } while ((subdomain = strchr(subdomain + 1, DOT)) != NULL);
    
    if (passwd != NULL) {
	DEBUGLOG("free passwd.");
        free(passwd);
        passwd = NULL;
    }
    free(not_subdomain);
    return RECORD_NOTFOUND;
}

/*
 * search_fromaddr_bdb()
 *
 * Check if the address exists in senderDB.
 *
 * args:
 * config *cfg      pointer
 * char *fromaddr   string
 *
 * return value:
 *       ENC                  encryption
 *       NOT_ENC              no encryption
 *       DB_ERROR             db error
 *       MALLOC_ERROR         alloc error
 */
int
search_fromaddr_bdb(struct config *cfg, char *fromaddr)
{
    DB *sender_dbp;
    char *mdom = NULL;
    char *passwd = NULL;
    char *not_fromaddr;
    char *fqdn;
    int ret;

    /* senderdb open */
    ret = db_open(&sender_dbp, cfg->cf_senderdbpath, cfg->cf_senderdbtype);
    if (ret == DB_ERROR) {
        return DB_ERROR;
    }

    /* make not_fromaddr */
    not_fromaddr = malloc(strlen(fromaddr) + 2);
    if (not_fromaddr == NULL) {
        log(ERR_MEMORY_ALLOCATE, "search_fromaddr_bdb", "not_fromaddr", strerror(errno));
        db_close(sender_dbp);
        return MALLOC_ERROR;
    }
    sprintf(not_fromaddr , "!%s", fromaddr);

    /* search address */
    ret = search_str_bdb(sender_dbp, cfg->cf_senderdbpath,
                         fromaddr, not_fromaddr, &passwd);
    if (passwd != NULL) {
        DEBUGLOG("free passwd.", passwd);
        free(passwd);
        passwd = NULL;
    }
    if (ret == DB_ERROR) {
        free(not_fromaddr);
        db_close(sender_dbp);
        return DB_ERROR;
    }
    if (ret == NOT_ENC) {
        DEBUGLOG("Sender not_fromaddr found.(%s)", not_fromaddr);
        free(not_fromaddr);
        db_close(sender_dbp);
        return NOT_ENC;
    }
    if (ret == ENC) {
        DEBUGLOG("Sender fromaddr found.(%s)", fromaddr);
        free(not_fromaddr);
        db_close(sender_dbp);
        return ENC;
    }

    /* make fqdn */
    fqdn = strchr(fromaddr, ATMARK);
    if (fqdn == NULL) {
        free(not_fromaddr);
        db_close(sender_dbp);
        return NOT_ENC;
    }

    /* make not_fqdn */
    sprintf(not_fromaddr , "!%s", fqdn);

    /* search fqdn */
    ret = search_str_bdb(sender_dbp, cfg->cf_senderdbpath,
                         fqdn, not_fromaddr, &passwd);
    if (passwd != NULL) {
        DEBUGLOG("free passwd.", passwd);
        free(passwd);
        passwd = NULL;
    }
    if (ret == DB_ERROR) {
        free(not_fromaddr);
        db_close(sender_dbp);
        return DB_ERROR;
    }
    if (ret == NOT_ENC) {
        DEBUGLOG("Sender not_fqdn found.(%s)", not_fromaddr);
        free(not_fromaddr);
        db_close(sender_dbp);
        return NOT_ENC;
    }
    if (ret == ENC) {
        DEBUGLOG("Sender fqdn found.(%s)", fqdn);
        free(not_fromaddr);
        db_close(sender_dbp);
        return ENC;
    }

    /* free not_fromaddr */
    free(not_fromaddr);

    /* search subdomain */
    ret = search_subdomain_bdb(sender_dbp, cfg->cf_senderdbpath, fqdn, &mdom, &passwd);
    if (passwd != NULL) {
        DEBUGLOG("free passwd.", passwd);
        free(passwd);
        passwd = NULL;
    }
    if (ret < 0) {
        /* DB_ERROR or MALLOC_ERROR */
        db_close(sender_dbp);
        return ret;
    }
    if ((ret == NOT_ENC) || (ret == RECORD_NOTFOUND)) {
        /* Not encryption */
        db_close(sender_dbp);
        return NOT_ENC;
    }
    DEBUGLOG("match subdomain: %s", mdom);
    db_close(sender_dbp);

    return ENC;
}

char seed[] = SEED;
/*
 * mk_passwd
 *
 * Args:
 *      char    **passwd        passwd string pointer
 *      int       count         passwd length
 *
 * Returns:
 *      PASSWD_SUCCESS          Success
 *      PASSWD_FAILED           Failed
 */
int
mk_passwd(char **passwd, int count)
{
    long val;
    int i;

    *passwd = (char *)malloc(sizeof(char *) * count + 1);
    if (*passwd == NULL) {
        log(ERR_MEMORY_ALLOCATE, "mk_passwd", "passwd", strerror(errno));
        return(PASSWD_FAILED);
    }

    pthread_mutex_lock(&pw_lock);

    for(i = 0; i < count; i++) {
        val = lrand48() % (sizeof(seed) - 1);

        *(*(passwd) + i) = seed[val];

    }
    *(*(passwd) + count) = '\0';

    pthread_mutex_unlock(&pw_lock);

    return(PASSWD_SUCCESS);
}

/*
 * search_str_bdb()
 *
 * Check if the string exists in DB.
 *
 * args:
 *       config *cfg      pointer
 *       char *fromaddr   string
 *
 * return value:
 *       ENC                  str found
 *       NOT_ENC              not str found
 *       RECORD_NOTFOUND      not found
 *       DB_ERROR             db error
 */
int
search_str_bdb(DB *dbp, const char *dbpath, char *search_str,
               char *not_search_str, char **match_passwd)
{
    int ret;

    if (not_search_str != NULL) {
        /* search not_search_str */
        ret = db_search(dbp, dbpath, not_search_str, match_passwd);
        if (ret == DB_ERROR) {
            return DB_ERROR;
        }
        if (ret == FOUND) {
            DEBUGLOG("not_search_str found.(%s)", not_search_str);
            return NOT_ENC;
        }
    }

    /* search search_str */
    ret = db_search(dbp, dbpath, search_str, match_passwd);
    if (ret == DB_ERROR) {
        return DB_ERROR;
    }
    if (ret == FOUND) {
        DEBUGLOG("search_str found.(%s)", search_str);
        return ENC;
    }

    return RECORD_NOTFOUND;
}

/*
 * search_ext_bdb()
 *
 * Get the extension.
 *
 * args:
 *       DB   *dbp		pointer
 *       char *dbpath		string
 *       char *keyword 		string
 *       char **extension	string pointer
 *
 * return value:
 *       RECORD_NOTFOUND	not found
 *       RECORD_FOUND		found
 *       DB_ERROR		db error
 */
int
search_ext_bdb(DB *dbp, const char *dbpath, char *keyword, char **extension)
{
    int ret;

    *extension = NULL;

    ret = db_search(dbp, dbpath, keyword, extension);
    if (ret == DB_ERROR) {
        return DB_ERROR;
    } else if (ret == FOUND){
        return RECORD_FOUND;
    }

    return RECORD_NOTFOUND;
}


/*
 * ldap_get_userdn()
 *
 * args
 *       LDAP *ld               pointer
 *       char *ldapbasedn       string
 *       char *send             string
 *       char *rcpt             string
 *       char *ldapfilter       string
 *       char **userdn          pointer
 * return value
 *       SUCCESS             userdn 
 *       NOT_ENC        no encryption 
 *       LDAP_ERROR     ldap error
 */
int
ldap_get_userdn(LDAP *ld, char *ldapbasedn, char *send, char *rcpt, char *cfgfilter, char **userdn)
{
    LDAPMessage *p = NULL;
    LDAPMessage *res = NULL;
    char *filter = NULL;
    char *attr[2];
    struct timeval tv;
    int rc;
    int count;
    int lderrno;
    struct strtag tag[1];

    // set ldap filter
    tag[0].st_tag = "";
    tag[0].st_taglen = 0;
    tag[0].st_str = send;

    filter = str_replace_tag(cfgfilter, "%", "s", tag, 1);
    if (filter == NULL) {
        log(ERR_MEMORY_ALLOCATE, "ldap_get_userdn", "filter", strerror(errno));
        return MALLOC_ERROR;
    }

    // timeout parameter
    tv.tv_sec  = LDAP_TIMEOUT_SEC;
    tv.tv_usec = 0;

    // attribute list
    attr[0] = LDAP_NO_ATTRS;
    attr[1] = NULL;

    // search for get userdn
    rc = ldap_search_ext_s(ld, ldapbasedn, LDAP_SCOPE_SUBTREE, filter,
                           attr, 0, NULL, NULL, &tv, 0, &res);
    free(filter);
    if (rc != LDAP_SUCCESS) {
        ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &lderrno);
        log(ERR_LDAP_SEARCH, "ldap_get_userdn", ldap_err2string(lderrno));
        return LDAP_ERROR;
    }

    // count the number of data
    count = ldap_count_entries(ld, res);
    if (count < 0) {
        ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &lderrno);
        log(ERR_LDAP_COUNT , "ldap_get_userdn", ldap_err2string(lderrno));
        ldap_msgfree(res);
        return LDAP_ERROR;
    } else if (count == 0) {
        ldap_msgfree(res);
        return NOT_ENC;
    }

    // get first entry
    p = ldap_first_entry(ld, res);
    if (p == NULL) {
        ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &lderrno);
        log(ERR_LDAP_ENTRIE, "ldap_get_userdn", ldap_err2string(lderrno));
        ldap_msgfree(res);
        return LDAP_ERROR;
    }

    // get userdn    
    *userdn = ldap_get_dn(ld, p);
    if (*userdn == NULL) {
        ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &lderrno);
        log(ERR_LDAP_GET_DN, "ldap_get_userdn", ldap_err2string(lderrno));
        ldap_msgfree(res);
        return LDAP_ERROR;
    }

    // free
    ldap_msgfree(res);
    return ENC;
}

/*
 * set_priority_addr()
 *
 * args
 *       struct person *data
 *       struct berval **valp_addr 
 *       struct berval **valp_pass
 *       
 * return value
 *       SUCCESS
 *       MALLOC_ERROR
 */
int
set_priority_addr (struct person *data, struct berval **valp_addr, struct berval **valp_pass)
{
     // free address
     if (data->addr != NULL) {
	 free(data->addr);
	 data->addr = NULL;
     }

     // free password
     if (data->pass != NULL) {
         free(data->pass);
         data->pass = NULL;
     }

     // set address
     data->addr = strdup(valp_addr[0]->bv_val);
     if (data->addr == NULL) {
	log(ERR_MEMORY_ALLOCATE, "set_priority_addr", "data->addr", strerror(errno));
	return MALLOC_ERROR;
     }

     // set password
     if (valp_pass != NULL && valp_pass[0]->bv_len > 0) {
         data->pass = strdup(valp_pass[0]->bv_val);
         if (data->pass == NULL) {
             log(ERR_MEMORY_ALLOCATE, "set_priority_addr", "data->pass", strerror(errno));
	     free(data->addr);
             return MALLOC_ERROR;
         }
     } else {
         data->pass = NULL;
     }

     data->addr_len = valp_addr[0]->bv_len;

     return SUCCESS;
}

/*
 * ldap_search_policy()
 *
 * args
 *       LDAP *ld               pointer
 *       char *ldapbasedn       string
 *       char *rcpt             string
 *       char *ldapfilter       string
 *       char **priority_addr   pointer
 *       char **priority_pass   pointer
 *       char *userdn           string
 *
 * return value
 *       ENC            encryption
 *       NOT_ENC        no encryption
 *       UNDEF_ENC      undefined user on ldap: follow the site-policies
 *       LDAP_ERROR     ldap error
 *       MALLOC_ERROR   alloc error
 */
int
ldap_search_policy (LDAP *ld, char *ldapbasedn, char *rcpt, char *userdn, struct person *data)
{
    LDAPMessage *res = NULL;
    LDAPMessage *p = NULL;
    char *filter = NULL;
    int rc;
    int count;
    char *attr[3];
    struct timeval tv;
    struct berval **valp_addr;
    struct berval **valp_pass;
    int lderrno;
    char* atmark = NULL;

    atmark = strchr(rcpt, ATMARK);
    if (atmark == NULL) {
        return NOT_ENC;
    }

    //make ldap filter  
    rc = make_filter(rcpt, &filter);
    if (rc != SUCCESS) {
        log(ERR_MAKE_FILTER, "ldap_search_policy", rc);
        return LDAP_ERROR;
    }

    //timeout parameter
    tv.tv_sec  = LDAP_TIMEOUT_SEC;
    tv.tv_usec = 0;

    //attribute list
    attr[0] = ENC_ADDR;
    attr[1] = ENC_PASS;
    attr[2] = NULL;

    //search for get priority address and password
    rc = ldap_search_ext_s(ld, userdn, LDAP_SCOPE_SUBTREE, filter, attr, 0, 
							NULL, NULL, &tv, 0, &res);
    free(filter);
    if (rc != LDAP_SUCCESS) {
        ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &lderrno);
        log(ERR_LDAP_SEARCH, "ldap_search_policy", ldap_err2string(lderrno));
        return LDAP_ERROR;
    }

    //count the number of data
    count = ldap_count_entries(ld, res);
    if (count < 0) {
        ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &lderrno);
        log(ERR_LDAP_COUNT , "ldap_search_policy", ldap_err2string(lderrno));
        ldap_msgfree(res);
        return LDAP_ERROR;
    } else if (count == 0) {
        ldap_msgfree(res);
        return UNDEF_ENC;
    }

    //find priority address
    for (p = ldap_first_entry(ld, res); p != NULL ; p = ldap_next_entry(ld, p)) {

        //get address
        valp_addr = ldap_get_values_len(ld, p, ENC_ADDR);
        if (valp_addr == NULL) {
            log(ERR_LDAP_VALUE, "ldap_search_policy", ldap_err2string(lderrno));
            ldap_msgfree(res);
            return LDAP_ERROR;
        }  

        if ((valp_addr[0]->bv_len > data->addr_len) ||
            ((valp_addr[0]->bv_len == data->addr_len) && (*(valp_addr[0]->bv_val) != '!'))) {

            //get pass
            valp_pass = ldap_get_values_len(ld, p, ENC_PASS);

            //set addr and pass
            if (set_priority_addr(data, valp_addr, valp_pass) != SUCCESS) {
		ldap_value_free_len(valp_addr);
		if (valp_pass != NULL) {
		    ldap_value_free_len(valp_pass);
		}
		return MALLOC_ERROR;
	    }

	    if (valp_pass != NULL) {
                ldap_value_free_len(valp_pass);
	    }
        }

        ldap_value_free_len(valp_addr);
    }

    ldap_msgfree(res);

    //no encryption 
    if (*(data->addr) == '!') {
        return NOT_ENC;
    } 

    return ENC;
}

/*
 * myldap_connect
 *
 * Args:
 *      char *uri                   connect uri  
 *      char *ldapbinddn            ldap bind DN           
 *      char *ldapbindpassword      ldap bind password         
 *
 * Returns:
 *      LDAP *ld                    ldap pointer
 *      NULL
 */
LDAP *
myldap_connect(char *uri, char *ldapbinddn, char *ldapbindpass)
{
    LDAP *ld;
    int ret;
    struct timeval tval;
    struct berval bv;
    int lderrno;

    //connect ldap
    ret = ldap_initialize(&ld, uri);
    if (ret != LDAP_SUCCESS) {
        ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &lderrno);
        log(ERR_LDAP_INIT, "myldap_connect", ldap_err2string(lderrno));
        return(NULL);
    }

    //timeout parameter
    tval.tv_sec = LDAP_TIMEOUT_SEC;
    tval.tv_usec = 0;

    //set timeout
    ret = ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, &tval);
    if (ret != LDAP_SUCCESS) {
        ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &lderrno);
        log(ERR_LDAP_SET, "myldap_connect", ldap_err2string(lderrno));
        return(NULL);
    }

    bv.bv_val = ldapbindpass;
    bv.bv_len = strlen(ldapbindpass);

    //ldap bind
    ret = ldap_sasl_bind_s(ld, ldapbinddn, LDAP_SASL_SIMPLE, &bv, NULL, NULL, NULL);
    if (ret != LDAP_SUCCESS) {
        ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &lderrno);
        log(ERR_LDAP_BIND, "myldap_connect", ldap_err2string(lderrno));
        return(NULL);
    }

    return(ld);
}

/*
 * make_filter()
 *  
 *       make filter for ldap search 
 *    
 * Args:
 *       char *rcpt       string recipient address 
 *       char **filter    stirng filter
 *
 * Returns:
 *       SUCCESS	  success make filter
 *       MALLOC_ERROR	  alloc error
 */
int
make_filter (char *rcpt ,char **filter)
{
    char* last = NULL;
    char* atmark_fqdn;
    char* sub = NULL;
    char* str = NULL;
    int rcpt_len = 0;
    int total_len = 0;

    //get a length in recipient address
    rcpt_len = strlen(rcpt);

    //get the last pointer in recipient address
    last = rcpt + rcpt_len;

    //searh an atmark
    atmark_fqdn = strchr(rcpt, ATMARK);

    //get the first pointer of fqdn
    sub = atmark_fqdn + 1;

    //make the form of the filter
    if ((make_part_filter(&str, rcpt, last, &total_len) != SUCCESS) ||
        (make_part_filter(&str, atmark_fqdn, last, &total_len) != SUCCESS) ||
        (make_part_filter(&str, sub, last, &total_len) != SUCCESS)) {
        return MALLOC_ERROR;
    }

    //subdomain set
    while (sub != NULL) {

        //search a dot
        sub = strchr(sub, DOT);
        if (sub == NULL) {
            break;
        }
        sub++;

        if (make_part_filter(&str, sub, last, &total_len) != SUCCESS) {
            return MALLOC_ERROR;
        }
    }

    //memory allocate
    *filter = malloc(total_len + 4);
    if (*filter == NULL) {
        log(ERR_MEMORY_ALLOCATE, "make_filter", "filter", strerror(errno));
	if (str != NULL) {
	    free(str);
	}
        return MALLOC_ERROR;
    }
    
    //close a parenthesis
    sprintf(*filter, FILTER_FORM, str);
    free(str);

    return SUCCESS;
}

/*
 * make_sub_filter()
 *
 * Args:
 *       char **filter           filter
 *       char *str               pointer 
 *       char *last              the last pointer
 *       int *total_len          total length 
 *
 * Returns:
 *       SUCCESS             success make filter
 *       MALLOC_ERROR   alloc error
 */
int
make_part_filter(char **filter, char *str, char *last, int *total_len)
{
    char *tmp = NULL;
    int part_filter_len = 0;
    int str_len = 0;

    //get a length in str
    str_len = last - str;

    part_filter_len = str_len * 2 + PART_FILTER_LEN;

    //memory allocate
    tmp = realloc(*filter, *total_len + part_filter_len + 1);
    if (tmp == NULL) {
        if (*filter != NULL) {
            free(*filter);
	    *filter = NULL;
        }
        log(ERR_MEMORY_ALLOCATE, "make_sub_filter", "tmp", strerror(errno));
        return MALLOC_ERROR;
    }
    *filter = tmp;

    //make subdomain filter
    sprintf(*filter + *total_len, PART_FILTER_FORM,
                  ENC_ADDR, LDAP_EXC_MARK_ESC, str,
                  ENC_ADDR, str);

    *total_len += part_filter_len;      
  
    return SUCCESS;
}

/*
 * str_tolower()
 * translate lower string
 *
 * Args:
 * char *rcptaddr           Recipient address
 *
 * Returns:
 * lower_addr               translated rcptaddr
 * NULL                     malloc error
 */
char *
str_tolower(char *rcptaddr)
{
    char *lower_addr = NULL;
    int len;
    int i;

    len = strlen(rcptaddr);

    /* allocate enough size buffer */
    lower_addr = (char *)malloc(len + 1);
    if (lower_addr == NULL) {
       /* malloc error */
       return NULL;
    }

    /* translate lower string */
    for (i = 0; i < len; i++) {
        lower_addr[i] = tolower(rcptaddr[i]);
    }
    lower_addr[i] = '\0';

    return lower_addr;
}

/*
 * check_validation_of_ext()
 *
 * struct config        *cfg
 * char                 *extension
 *
 * return value
 *       0              Success
 *       -1             Error
 */
int
check_validation_of_ext(struct config *cfg, char *extension)
{
    char ext_char[] = EXTENSION_CHAR;
    int i;
    char *ret = 0;
    int ext_len = 0;
    int zipfilename_len = 0;

    ext_len = strlen(extension);
    zipfilename_len = strlen(cfg->cf_zipfilename);
    for (i = 0; i < ext_len; i++) {
        ret = strchr(ext_char, extension[i]);
        if (ret == NULL) {
            log(INVALID_CHAR_EXTENSION, "check_validation_of_ext", extension);
            return FALSE;
        }
    }
    if (ext_len > 20 || zipfilename_len + ext_len > 256) {
        log(INVALID_LEN_EXTENSION, "check_zip_extension", extension);
        return FALSE;
    }
    return TRUE;
}
