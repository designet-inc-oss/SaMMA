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
 * $RCSfile: client_side.h,v $
 * $Revision: 1.2 $
 * $Date: 2009/07/24 04:26:43 $
 */

#define BUF_LEN 	256	/* size of buffer */
#define OUTPUT_LEN 	300	/* size of output buffer */
#define TEXT_EXIT 	"exit"
#define TEXT_RELOAD 	"reload"
#define TEXT_ALL 	"all"
#define TEXT_TMPL 	"tmpl"
#define TEXT_WHITELIST 	"whitelist"
#define TEXT_LOGIN 	"login"
#define LEN_EXIT 	sizeof(TEXT_EXIT)
#define LEN_RELOAD 	sizeof(TEXT_RELOAD)
#define LEN_ALL 	sizeof(TEXT_ALL)
#define LEN_TMPL 	sizeof(TEXT_TMPL)
#define LEN_WHITELIST 	sizeof(TEXT_WHITELIST)
#define LEN_LOGIN 	sizeof(TEXT_LOGIN)
#define TYPE_EXIT 	1
#define TYPE_CFGRELOAD 	2
#define TYPE_TMPRELOAD 	3
#define TYPE_LOGIN 	4
#define TYPE_WHITELISTRELOAD 	5
#define TYPE_OTHER 	0
#define ST_LOGIN	0
#define ST_NOLOGIN	1
#ifdef __CUSTOMIZE2018
#define TEXT_ADDMSG	"addmsg"
#define LEN_ADDMSG	sizeof(TEXT_ADDMSG)
#define TYPE_ADDMSGRELOAD 	6
#endif	// __CUSTOMIZE2018

/* command output */
#define OUTPUT_WELCOME "Welcome to SaMMA\n"
#define LEN_OUTPUT_WELCOME sizeof(OUTPUT_WELCOME)

#define OUTPUT_NG "-NG\n"
#define OUTPUT_OK "+OK\n"
#define LEN_OUTPUT_NG sizeof(OUTPUT_NG)
#define LEN_OUTPUT_OK sizeof(OUTPUT_OK)

#define OUTPUT_ERROR "-NG Unknown command\n"
#define OUTPUT_ERROR_LOGIN "-NG authentication error\n"
#define OUTPUT_CLOSE "Connection close\n"
#define OUTPUT_RELOAD "reload successful\n"
#define OUTPUT_RELOAD_FAIL "reload failed\n"
#define OUTPUT_RELOAD_TMP_FAIL "reload failed(during reload)\n"
#define OUTPUT_RELOAD_CFG_FAIL "reload failed for config file\n"
#define LEN_OUTPUT_ERROR sizeof(OUTPUT_ERROR)
#define LEN_OUTPUT_ERROR_LOGIN sizeof(OUTPUT_ERROR_LOGIN)
#define LEN_OUTPUT_CLOSE sizeof(OUTPUT_CLOSE)
#define LEN_OUTPUT_RELOAD sizeof(OUTPUT_RELOAD)
#define LEN_OUTPUT_RELOAD_FAIL sizeof(OUTPUT_RELOAD_FAIL)
#define LEN_OUTPUT_RELOAD_TMP_FAIL sizeof(OUTPUT_RELOAD_TMP_FAIL)
#define LEN_OUTPUT_RELOAD_CFG_FAIL sizeof(OUTPUT_RELOAD_CFG_FAIL)
#ifdef __CUSTOMIZE2018
#define OUTPUT_RELOAD_ADDMSG_FAIL "reload failed(during reload)\n"
#define LEN_OUTPUT_RELOAD_ADDMSG_FAIL sizeof(OUTPUT_RELOAD_ADDMSG_FAIL)
#endif	// __CUSTOMIZE2018

#define COMTIMEOUT	60000

int check_command(char **, int);
int accept_command(char *cfgfile, char * addr, int port);
int create_connection(char *addr, int port);

struct thread_control
{
    char *configname;
    char *addr;
    int   port;
};
