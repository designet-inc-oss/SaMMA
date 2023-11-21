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

#ifndef _SAMMA_AUTOBCC_H_
#define _SAMMA_AUTOBCC_H_

#include "samma_policy.h"

#define BCC_NO_ENTRY	2
#define BCC_NO_MATCH	2
#define REGEXERR_BUFLEN	512
#define ADDRESS_DELIM	" ,"

/* LDAP */
#define BCC_STRING "autoBccConditionString"
#define BCC_ADDRES "autoBccMailAddress"
#define BCC_FILTER "(objectclass=sammaAutoBccOption)"

int add_bccaddr(struct config *, char *, struct rcptaddr **, struct rcptaddr **);
int check_rcptlist(struct rcptaddr *, char *);
int split_rcptlist(struct rcptaddr **, char *);
int ldap_search_autobcc_attr(LDAP *, char *, char *, char **, char **);

#endif /*_SAMMA_AUTOBCC_H_*/
