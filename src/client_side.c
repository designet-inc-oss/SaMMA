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
 * $RCSfile: client_side.c,v $
 * $Revision: 1.6 $
 * $Date: 2010/04/01 04:42:39 $
 */

/* External command for samma */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <libdgnetutil.h>

#include "client_side.h"
#include "mailzip_config.h"
#include "log.h"
#include "sendmail.h"

/* 
 * check_command 
 * Function 
 *   check input command
 *   command sample
 *           restart
 *           exit
 *
 * Argument
 *   arg0 char *command
 *   arg1 int  cnt
 *
 * Return value
 *   return_flag  0  other command
 *                1  exit command
 *                2  reload command
 *
 */
int 
check_command(char **command, int cnt)
{
    int return_flag;
    return_flag = TYPE_OTHER;

    if (strncmp(command[0], TEXT_EXIT, LEN_EXIT) == 0) {
        /* case exit */
	if (cnt == 1) {
            return_flag = TYPE_EXIT;
	}
    } else if (strncmp(command[0], TEXT_RELOAD, LEN_RELOAD) == 0) {
	if (cnt == 2) {
	    if (strncmp(command[1], TEXT_ALL, LEN_ALL) == 0) {
                /* case config reload */
                return_flag = TYPE_CFGRELOAD;
	    } else if (strncmp(command[1], TEXT_TMPL, LEN_TMPL) == 0) {
                /* case template reload */
                return_flag = TYPE_TMPRELOAD;
	    } else if (strncmp(command[1], TEXT_WHITELIST, LEN_WHITELIST) == 0) {
                /* case template reload */
                return_flag = TYPE_WHITELISTRELOAD;
#ifdef __CUSTOMIZE2018
	    } else if (strncmp(command[1], TEXT_ADDMSG, LEN_ADDMSG) == 0) {
                /* case template reload */
                return_flag = TYPE_ADDMSGRELOAD;
#endif	// __CUSTOMIZE2018
            }
	}
    } else if (strncmp(command[0], TEXT_LOGIN, LEN_LOGIN) == 0) {
        /* case login */
	if (cnt == 2) {
            return_flag = TYPE_LOGIN;
	}
    }

    return return_flag;
}

/* 
 *   accept command
 *   c
 *   command sample
 *           restart
 *           exit
 *
 *   arg0	char *cfgfile
 *   arg1 char *addr
 *   arg1 int port 
 *
 *   return value
 *   0  Success
 *   1  Fail
 */
int
accept_command(char *cfgfile, char *addr, int port)
{
    int connected_socket, listen_socket;
    struct sockaddr_in peer_sin;
    socklen_t len;
    int ret;
    int ret_command;
    int ret_reload;
    int read_size;
    char *buf = NULL;
    char **arg_list;
    int cnt = 0;
    struct config *cfg;
    struct pollfd pfd;
    short event;
    struct streambuffer srb;
    int i;
    int login_stat = ST_NOLOGIN;

    listen_socket = create_connection(addr, port);
    if (listen_socket == -1) {
         return 1;
    }

    while (1) {

        len = sizeof(peer_sin);

        /* accept connection for samma */
        connected_socket = accept(listen_socket, (struct sockaddr *)&peer_sin, &len);
	if (connected_socket == -1) {
	    switch (errno) {
	        case EAGAIN: /* same errno EWOULDBLOCK */
	        case EINTR:
	    	    log(ERR_SOCKET_ACCEPT, "accept_command", strerror(errno));
	    	    continue;
		default:
	    	    log(ERR_SOCKET_ACCEPT, "accept_command", strerror(errno));
		    return 1;
	    }
	}

        /* output welcome comment*/
        if (write(connected_socket, OUTPUT_WELCOME, LEN_OUTPUT_WELCOME) == -1) {
	    log(ERR_IO_WRITE, "accept_command", OUTPUT_WELCOME);
            ret = close(connected_socket);
            if (ret == -1) {
	        log(ERR_SOCKET_CLOSE, "accept_command", strerror(errno));
                return 1;
            }
	    continue;
	}

	srb_init(&srb, connected_socket, connected_socket);

	/* set poll structure */
	pfd.fd = connected_socket;
	pfd.events = POLLIN;

        while (1){

	    event = poll(&pfd, 1, COMTIMEOUT);
	    if (event <= 0) {
		break;
	    }

            /* read line */
	    buf = srb_read_line(&srb, &read_size);
	    if (srb.srb_flag & SRB_FLAG_ERRORS) {
		log(ERR_IO_READ, "accept_command");
                if (write(connected_socket, OUTPUT_NG, LEN_OUTPUT_NG) == -1) {
		    log(ERR_IO_WRITE, "accept_command", OUTPUT_NG);
		}
                break;
	    }
	    if (buf == NULL) {
                if (write(connected_socket, OUTPUT_NG, LEN_OUTPUT_NG) == -1) {
		    log(ERR_IO_WRITE, "accept_command", OUTPUT_NG);
		}
		break;
	    }
	    for (i = 0; i < read_size; i++) {
		if (*(buf + i) == '\r') {
		    *(buf + i) = '\0';
		    break;
		}
		if (*(buf + i) == '\n') {
		    *(buf + i) = '\0';
		    break;
		}
	    }

	    cnt = arg_split(&arg_list, buf);
	    if ((cnt > 2) || (cnt < 1)) {
                /* input other command */
                if (write(connected_socket, OUTPUT_NG, LEN_OUTPUT_NG) == -1) {
		    log(ERR_IO_WRITE, "accept_command", OUTPUT_NG);
		}
		if (buf != NULL) {
		    free(buf);
		    buf = NULL;
		}
		continue;
	    }

            ret_command = check_command(arg_list, cnt);
	    switch (ret_command) {
		case TYPE_OTHER:
		    /* input other command */
                    if (write(connected_socket, OUTPUT_ERROR, LEN_OUTPUT_ERROR) == -1) {
			log(ERR_IO_WRITE, "accept_command", OUTPUT_NG);
		    }
		    break;
		case TYPE_EXIT:
                    /* close socket */
                    if (write(connected_socket, OUTPUT_CLOSE, LEN_OUTPUT_CLOSE) == -1) {
			log(ERR_IO_WRITE, "accept_command", OUTPUT_NG);
		    }
		    break;
		case TYPE_CFGRELOAD:
		    if (login_stat == ST_NOLOGIN) {
                        if (write(connected_socket, OUTPUT_ERROR_LOGIN, 
							LEN_OUTPUT_ERROR_LOGIN) == -1) {
			    log(ERR_IO_WRITE, "accept_command", OUTPUT_NG);
		        }
			break;
		    }
                    /* reload config file */
                    ret_reload = reload_config(cfgfile);
                    if (ret_reload == 0) {
                        /* case reload successfull */
			log(CONFIG_RELOADING, "accept_command", cfgfile);
                        if (write(connected_socket, OUTPUT_OK, LEN_OUTPUT_OK) == -1) {
			    log(ERR_IO_WRITE, "accept_command", OUTPUT_NG);
		        }
                    } else {
                        /* case reload fail */
                        if (write(connected_socket, OUTPUT_NG, LEN_OUTPUT_NG) == -1) {
			    log(ERR_IO_WRITE, "accept_command", OUTPUT_NG);
		        }
		    }
		    break;

		case TYPE_TMPRELOAD:
		    if (login_stat == ST_NOLOGIN) {
                        if (write(connected_socket, OUTPUT_ERROR_LOGIN, 
							LEN_OUTPUT_ERROR_LOGIN) == -1) {
			    log(ERR_IO_WRITE, "accept_command", OUTPUT_NG);
		        }
			break;
		    }
		    cfg = config_init();
                    /* reload template file */
                    ret_reload = reload_tmpl(cfg);
		    config_release(cfg);
                    if (ret_reload == 0) {
                        /* case reload successfull */
			log(TEMPLATE_RELOADING, "accept_command", cfg->cf_templatepath);
                        if (write(connected_socket, OUTPUT_OK, LEN_OUTPUT_OK) == -1) {
			    log(ERR_IO_WRITE, "accept_command", OUTPUT_NG);
		        }
                    } else {
                        /* case reload fail */
                        if (write(connected_socket, OUTPUT_NG, LEN_OUTPUT_NG) == -1) {
			    log(ERR_IO_WRITE, "accept_command", OUTPUT_NG);
		        }
		    }
		    break;

		case TYPE_WHITELISTRELOAD:
		    if (login_stat == ST_NOLOGIN) {
                        if (write(connected_socket, OUTPUT_ERROR_LOGIN, 
							LEN_OUTPUT_ERROR_LOGIN) == -1) {
			    log(ERR_IO_WRITE, "accept_command", OUTPUT_NG);
		        }
			break;
		    }
		    cfg = config_init();
                    /* reload template file */
                    ret_reload = reload_whitelist(cfg->cf_whitelistpath);
		    config_release(cfg);
                    if (ret_reload == 0) {
                        /* case reload successfull */
			log(WHITELIST_RELOADING, "accept_command", cfg->cf_whitelistpath);
                        if (write(connected_socket, OUTPUT_OK, LEN_OUTPUT_OK) == -1) {
			    log(ERR_IO_WRITE, "accept_command", OUTPUT_NG);
		        }
                    } else {
                        /* case reload fail */
                        if (write(connected_socket, OUTPUT_NG, LEN_OUTPUT_NG) == -1) {
			    log(ERR_IO_WRITE, "accept_command", OUTPUT_NG);
		        }
		    }
		    break;

		case TYPE_LOGIN:
		    cfg = config_init();
		    if (strncmp(arg_list[1], cfg->cf_commandpass, 
						strlen(cfg->cf_commandpass) + 1) == 0) { 
                        if (write(connected_socket, OUTPUT_OK, LEN_OUTPUT_OK) == -1) {
			    log(ERR_IO_WRITE, "accept_command", OUTPUT_NG);
		        }
		        login_stat = ST_LOGIN;
		    } else {
                        if (write(connected_socket, OUTPUT_ERROR_LOGIN, 
							LEN_OUTPUT_ERROR_LOGIN) == -1) {
			    log(ERR_IO_WRITE, "accept_command", OUTPUT_NG);
		        }
		    }
		    config_release(cfg);
		    break;

#ifdef __CUSTOMIZE2018
		case TYPE_ADDMSGRELOAD:
		    if (login_stat == ST_NOLOGIN) {
                        if (write(connected_socket, OUTPUT_ERROR_LOGIN, 
							LEN_OUTPUT_ERROR_LOGIN) == -1) {
			    log(ERR_IO_WRITE, "accept_command", OUTPUT_NG);
		        }
			break;
		    }
		    cfg = config_init();
                    /* reload template file */
                    ret_reload = reload_addmsg(cfg);
		    config_release(cfg);
                    if (ret_reload == 0) {
                        /* case reload successfull */
			log(ADDMSG_RELOADING, "accept_command");
                        if (write(connected_socket, OUTPUT_OK, LEN_OUTPUT_OK) == -1) {
			    log(ERR_IO_WRITE, "accept_command", OUTPUT_NG);
		        }
                    } else {
                        /* case reload fail */
                        if (write(connected_socket, OUTPUT_NG, LEN_OUTPUT_NG) == -1) {
			    log(ERR_IO_WRITE, "accept_command", OUTPUT_NG);
		        }
		    }
		    break;
#endif	// __CUSTOMIZE2018

		default:
		    break;
	    }

            /* START ADD 201503*/
            arg_list_free(arg_list, cnt);
            arg_list = NULL;

            if (buf != NULL) {
                free(buf);
                buf = NULL;
            }
            /* END ADD 201503*/

	    if (ret_command == TYPE_EXIT) {
		break;
	    }
        }

	login_stat = ST_NOLOGIN;
	arg_list_free(arg_list, cnt);
	arg_list = NULL;

	if (buf != NULL) {
	    free(buf);
	    buf = NULL;
	}
	srb_clean(&srb);

        ret = close(connected_socket);
        if (ret == -1) {
	    log(ERR_SOCKET_CLOSE, "accept_command", strerror(errno));
	    return 1;
        }
    }

    return 0;
}

/* 
 * get_port_num
 * 
 * Function
 *    get new port number
 *
 * Argument
 *
 * Return value
 *   portnum port number
 */
int
get_port_num()
{
    struct config *cfg;
    int portnum;

    /* read config file */
    cfg = config_init();

    portnum = cfg->cf_commandport;

    config_release(cfg);

    return portnum;

} 

/* 
 * create_connection
 *   
 * Function   
 *   create socket 
 *
 * Argument
 *   arg0 char *addr	bind address
 *   arg0 int port	port number
 *
 * Return value
 *   listen_socket  Success
 *   -1             Fail
 */
int 
create_connection(char *addr, int port)
{
    int listen_socket;
    struct sockaddr_in sin;
    int sock_optval = 1;
    int ret;

    /* create socket of listen */
    listen_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_socket == -1) {
	log(ERR_SOCKET_CREATE, "create_connection", strerror(errno));
        return 1;
    }

    /* set option of socket */
    if (setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR,
                    &sock_optval, sizeof(sock_optval)) == -1) {
	log(ERR_SOCKET_SET_OPTION, "create_connection", strerror(errno));
        return 1;
    }

    /* set address familly and port number and ipaddress */
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = inet_addr(addr);

    /* assign address to socket */
    if (bind(listen_socket, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
	log(ERR_SOCKET_BIND, "create_connection", strerror(errno));
        return -1;
    }

    /* check port of listen */
    ret = listen(listen_socket, SOMAXCONN);
    if ( ret == -1 ) {
	log(ERR_SOCKET_LISTEN, "create_connection", strerror(errno));
        return -1;
    }

    return listen_socket;
}

