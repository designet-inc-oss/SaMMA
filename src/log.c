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
#include <stdarg.h>
#include <strings.h>

#define SYSLOG_NAMES
#include <syslog.h>

#include "log.h"

int (*logfunc)(const char *, ...);

/*
 * syslog_facility()
 *
 * converts syslog facility name to integer value
 *
 * args:
 *  *str		syslog facility name
 *
 * return value:
 *  > 0			integer value of syslog facility
 *  -1			error (invalid name)
 */
int
syslog_facility(char *str)
{
    int i;

    for (i = 0; facilitynames[i].c_name != NULL; i++) {
	if (strcasecmp(str, facilitynames[i].c_name) == 0) {
	    return(facilitynames[i].c_val);
	}
    }
    return -1;
}

/*
 * init_log()
 *
 * switch log output to stderr
 *
 * args:
 *  none
 * return value:
 *  none
 *
 */
void
init_log()
{
    logfunc = (void *) errorlog;
}

/*
 * switch_log()
 *
 * switch log output
 *
 * args:
 *  *newfacility	new facility name or NULL
 *			- facility name -> calls openlog() and switch to syslog
 *			- NULL -> switch to stderr
 * return value:
 *  none
 *
 */
void
switch_log(char *newfacility)
{
    int facility;

    closelog();

    if (newfacility != NULL &&
	(facility = syslog_facility(newfacility)) >= 0) {
	openlog(SYSLOG_IDENT, LOG_PID, facility);
	logfunc = (void *) systemlog;
    } else {
	logfunc = (void *) errorlog;
    }
}

/*
 * errorlog()
 *
 * output error log to stderr
 *
 * args:
 *  *fmt, ...
 *
 * return value:
 *  none
 */
void
errorlog(char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

/*
 * systemlog()
 *
 * output error log to syslog
 *
 * args:
 *  *fmt, ...
 *
 * return value:
 *  none
 */
void
systemlog(char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsyslog(LOG_ERR, fmt, ap);
    va_end(ap);
}
