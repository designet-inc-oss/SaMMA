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

#ifdef HAVE_STRNDUP
#define _GNU_SOURCE
#endif /* HAVE_STRNDUP */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <libdgstr.h>

#include "mailzip_config.h"
#include "mailzip_db.h"
#include "global.h"

/*
 * db_open()
 *
 * Args:
 *  char *path                  string
 *  char *search_string         string
 *  char **passwd               pointer
 *
 * Return value:
 *  0                           Success
 *  1                           Not Found
 *  -1                          Error
 */
int
db_open(DB **dbp, const char *db_file, DBTYPE db_type)
{
    int ret;

    // make handler to open DB 
    ret = db_create(dbp, NULL, 0);
    // error 
    if (ret != 0) {
        // error 
        if (*dbp) {
            (*dbp)->close(*dbp, 0);
            log(ERR_DB, "db_open", "db_create error");
            return(DB_ERROR);
        }
    }
    // open DB 
    ret = (*dbp)->open(*dbp, NULL, db_file, NULL, db_type, DB_RDONLY, 0);
    // error 
    if (ret != 0) {
        (*dbp)->err(*dbp, ret, "%s", db_file);
        if (*dbp) {
            (*dbp)->close(*dbp, 0);
            log(ERR_DB, "db_open", "open error");
            return(DB_ERROR);
        }
    }
    return(0);
}

/*
 * db_search()
 *
 * Args:
 *  DB 		*dbp
 *  const char 	*db_file
 *  char 	*search_string
 *  char 	**passwd
 *
 * Return value:
 *  FOUND                    Record Found
 *  NOT_FOUND                Record Not Found
 *  DB_ERROR                 Error
 */
int
db_search(DB *dbp, const char *db_file, char *search_string, char **passwd)
{
    DBC *dbcp = NULL;
    DBT key, data;
    int ret;
    char *tmp_passwd;

    // make cursor to search 
    ret = (dbp)->cursor(dbp, NULL, &dbcp, 0);
    // error 
    if (ret != 0) {
        (dbp)->err(dbp, ret, "%s", db_file);
        if (dbcp) {
            (dbcp)->c_close(dbcp);
        }
        if (dbp) {
            (dbp)->close(dbp, 0);
        }
        log(ERR_DB, "db_search", "create cursor error");
        return(DB_ERROR);
    }
    // Initialization of memory 
    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));
    // storage of order
    key.data = search_string;
    key.size = strlen(search_string);

    // move cursor 
    ret = (dbcp)->c_get(dbcp, &key, &data, DB_SET);
    // not found 
    if (ret == DB_NOTFOUND) {
        return(NOT_FOUND);
    // error 
    } else if (ret != 0) {
        log(ERR_DB, "db_search", "move cursor error");
        return(DB_ERROR);
    }
    // found 
    if (data.size > 0) {
	tmp_passwd = strndup(data.data, data.size);
        if (!tmp_passwd) {
            log(ERR_DB, "db_search", "memory error");
            return(DB_ERROR);
        }
	*passwd = tmp_passwd;
    }

    // close cursor
    if (dbcp) {
        (dbcp)->c_close(dbcp);
    }
    return(FOUND);
}

int
db_close(DB *dbp)
{
    if (dbp) {
        dbp->close(dbp, 0);
    }
    return(0);
}
