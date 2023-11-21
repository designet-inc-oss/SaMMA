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
#include <errno.h>

#include "mailzip_config.h"
#include "maildrop.h"
#include "log.h"

/*
 * push_rcptlist
 *
 * args:
 * return:
 *  0		ok
 *  -1		error
 */
int
push_rcptlist(struct rcptaddr  **head, char *str)
{
    int i;
    struct rcptaddr *tmphead;

    /* check current size */
    if (*head == NULL) {
	i = 0;
    } else {
	for (i = 0; (*head + i)->rcpt_addr != NULL; i++);
    }

    /* (re)allocate memory */
    tmphead = realloc(*head, sizeof(struct rcptaddr) * (i + 2));
    if (tmphead == NULL) {
	log(ERR_MEMORY_ALLOCATE, "push_list", "head", strerror(errno));
	if (*head != NULL) {
	    free(*head);
	}
	return -1;
    }
    *head = tmphead;

    /* copy string */
    (*head + i)->rcpt_addr = strdup(str);
    if ((*head + i)->rcpt_addr == NULL) {
	log(ERR_MEMORY_ALLOCATE, "push_list",
	    "(*head + i)->rcpt_addr", strerror(errno));
	return -1;
    }
    (*head + i)->rcpt_addr_len = strlen(str);

    /* end with NULL */
    (*head + i + 1)->rcpt_addr = NULL;

    return 0;
}

void
free_rcptlist(struct rcptaddr *head)
{
    int i;
    if (head == NULL) {
        return;
    }
    for (i = 0; (head + i)->rcpt_addr != NULL; i++) {
	if ((head + i)->rcpt_addr != NULL) {
	    free((head + i)->rcpt_addr);
	}
    }
    if (head != NULL) {
        free(head);
    }
}

