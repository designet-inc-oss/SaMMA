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
#include <stdlib.h>
#include <libgen.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sysexits.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <gmime/gmime.h>
#include <pthread.h>
#include <libdgstr.h>
#include "mailzip_config.h"
#include "mailsave.h"
#include "zipconv.h"
#include "log.h"
#include "maildrop.h"
#include "global.h"

#define R	(0)
#define W	(1)

#define BUFSIZE 1024
#define SENDMAIL 	"/usr/sbin/sendmail"
#define SPACE	' '
#define XHEADERNAME "X-SaMMA-Enc"
#define XHEADERVALUE    "YES"

extern pthread_mutex_t gmime_lock;

static int parent_gmime(int *, GMimeObject *);

/*
 * child
 *
 * Args:
 *      int    fd               file descriptor
 *      char **arg_list         sendmail argument list
 *
 */
static void
child(int fd[2], char **arg_list)
{
    close(fd[W]);
    close(STDIN_FILENO);
    if (dup(fd[R]) < 0) {
	log(ERR_FD_CREATE, "child", strerror(errno));
        exit(EX_TEMPFAIL);      // error
    }
    close(fd[R]);

    /* exec file */
    if (execvp(arg_list[0], arg_list) < 0) {
	log(ERR_EXEC_FILE, "child", arg_list[0], strerror(errno));
        exit(EX_TEMPFAIL);      // error
    }
}

/*
 * parent
 *
 * Args:
 *      int    fd               file descriptor
 *      struct mailzip *mz      mailzip structure
 *
 * Return:
 *      0                       Success
 *      -1                      Failed
 */
static int
parent(int fd[2], struct mailzip *mz)
{
    FILE *fp;
    GMimeStream *w_stream, *f_stream;
    GMimeFilter *filter;

    close(fd[R]);

    fp = fdopen(fd[W], "w");
    if (fp == NULL) {
	log(ERR_FP_CREATE, "parent", strerror(errno));
        return -1;
    }

    pthread_mutex_lock(&gmime_lock);

    /* create write stream */
    w_stream = g_mime_stream_file_new(fp);

    /* create CFLF filter */
    filter = g_mime_filter_crlf_new(TRUE, FALSE);

    /* set CFLF filter */
#ifndef GMIME26
    f_stream = g_mime_stream_filter_new_with_stream(w_stream);
#else
    f_stream = g_mime_stream_filter_new(w_stream);
#endif

    g_object_unref (w_stream);

    g_mime_stream_filter_add((GMimeStreamFilter *)f_stream, filter);

#ifndef GMIME26
    g_mime_message_write_to_stream(mz->message, f_stream);
#else
    g_mime_stream_printf(f_stream, "%s: %s\n", XHEADERNAME, XHEADERVALUE);
    g_mime_object_write_to_stream((GMimeObject *)mz->message, f_stream);
#endif
    g_mime_stream_flush(f_stream);

    g_object_unref(filter);
    g_object_unref(f_stream);
    pthread_mutex_unlock(&gmime_lock);

    return (0);
}

/*
 * arg_split
 *
 * Args:
 * 	char ***list		sendmail option
 * 	char *str		config SendmailOpt
 *
 * Return:
 * 	num			option count
 * 	0			Error (count = 0)
 */
int
arg_split(char ***list, char *str)
{

    char *p = NULL, *tmpp = NULL, **tmplist = NULL;
    int len = 0, cnt = 0;
    *list = NULL;

    for (p = str, tmpp = str; tmpp != NULL; p = tmpp + 1) {
        tmpp = strchr(p, SPACE);
        if (tmpp != NULL) {
            len = tmpp - p;
        } else {
            len = strlen(p);
        }

        if (len == 0) {
            continue;
        }

        cnt++;

        tmplist = (char **)realloc(*list, sizeof(char *) * cnt);
        if (tmplist == NULL) {
            log(ERR_MEMORY_ALLOCATE, "sendmail", "arg_list", strerror(errno));
            if (*list != NULL) {
                free(*list);
            }
            return -1;
        }
        *list = tmplist;

        (*list)[cnt - 1] = strndup(p, len);
        if ((*list)[cnt - 1] == NULL) {
            log(ERR_MEMORY_ALLOCATE, "sendmail", "arg_list", strerror(errno));
            if (*list != NULL) {
                free(*list);
            }
            return -1;
        }
    }

    return cnt;
}

/*
 * arg_list_free
 *
 * Args:
 * 	char **arg_list		sendmail option
 * 	int    num		option count
 */
void
arg_list_free(char **arg_list, int num)
{
    int i;

    if (arg_list != NULL) {
        for (i = 0;i < num;i++) {
            free(arg_list[i]);
        }
        free(arg_list);
    }
}

/*
 * sendmail
 *
 * Args:
 * 	struct mailzip  *mz		mailzip structure
 * 	struct config   *cfg		config structure
 * 	struct rcptinfo *info		rcptinfo structure
 * 	char            *sender		envelope from address
 *
 * Rerutn:
 * 	SENDMAIL_SUCCESS		Success
 * 	SENDMAIL_FAILED			Failed
 */
int
sendmail(struct mailzip *mz, struct config *cfg, struct rcptinfo *info, char *sender)
{
    int		fd[2];
    int		ret;
    int 	num, cnt;
    int 	i, j;
    char       **list = NULL;
    char       **arg_list = NULL;
    pid_t	pid;
    struct rcptaddr *p = info->rcptlist;


    /* count sendmail command option */
    num = arg_split(&list, cfg->cf_sendmailcommand);
    if (num == 0) {
	return(SENDMAIL_FAILED);
    }

    /* count rcpt addr */
    for (cnt = 0; (p + cnt)->rcpt_addr != NULL; cnt++) {

	DEBUGLOG("rcpt_addr: %s\n", (p + cnt)->rcpt_addr);
	
    }

    arg_list = (char **)malloc(sizeof(char *) * (num + 4 + cnt));
    if (arg_list == NULL) {
	log(ERR_MEMORY_ALLOCATE, "sendmail", "arg_list", strerror(errno));
	return(SENDMAIL_FAILED);
    }
    for (i = 0; i < num; i++) {
	arg_list[i] = list[i];
    }

    arg_list[num] = strdup("-f");
    if (arg_list[num] == NULL) {
        log(ERR_MEMORY_ALLOCATE, "sendmail", "arg_list", strerror(errno));
	arg_list_free(arg_list, num);
	free(list);
	return(SENDMAIL_FAILED);
    }

    arg_list[num + 1] = strdup(sender);
    if (arg_list[num] == NULL) {
        log(ERR_MEMORY_ALLOCATE, "sendmail", "arg_list", strerror(errno));
	arg_list_free(arg_list, num + 1);
	free(list);
	return(SENDMAIL_FAILED);
    }

    arg_list[num + 2] = strdup("--");
    if (arg_list[num] == NULL) {
        log(ERR_MEMORY_ALLOCATE, "sendmail", "arg_list", strerror(errno));
	arg_list_free(arg_list, num + 2);
	free(list);
	return(SENDMAIL_FAILED);
    }

    /* add rcpt addr */
    for (j = 0; j < cnt; j++) {
	arg_list[num + 3 + j] = strdup((p + j)->rcpt_addr);
	if (arg_list[num + 3 + j] == NULL) {
            log(ERR_MEMORY_ALLOCATE, "sendmail", "arg_list", strerror(errno));
	    arg_list_free(arg_list, num + 3 + j);
	    free(list);
	    return(SENDMAIL_FAILED);
	}
    }
    arg_list[num + 3 + cnt] = NULL;


    /*
     * make pipe
     *
     * fd[R] : read only file descriptor
     * fd[W] : write only file descriptor
     */
    if (pipe(fd) == -1) {
	log(ERR_PIPE_CREATE, "sendmail", strerror(errno));
	arg_list_free(arg_list, num + 3 + cnt);
	free(list);
	return(SENDMAIL_FAILED);
    }

    /* make child process */
    if ((pid = fork()) == 0) {
	child(fd, arg_list);
    } else if (pid > 0) {
    /* make parent process */
	int	sts = 0;

	parent(fd, mz);
        /* parent process */
        ret = waitpid(pid, &sts, WUNTRACED);
        if (ret == -1) {
	    log(ERR_WAIT_CHILD, "sendmail", strerror(errno));
            return -1;
        }
	if (WIFEXITED(sts)) {
	    ret = WEXITSTATUS(sts);
	    if (ret != 0) {
        	log(ERR_MAIL_SEND, "sendmail");
	        arg_list_free(arg_list, num + 3 + cnt);
	        free(list);
        	return(SENDMAIL_FAILED);
	    }
	} else {
	    log(ERR_WAIT_CHILD, "sendmail", strerror(errno));
	    arg_list_free(arg_list, num + 3 + cnt);
	    free(list);
	    return(SENDMAIL_FAILED);
	}
    } else {
	log(ERR_FORK_CREATE, "sendmail", strerror(errno));
	arg_list_free(arg_list, num + 3 + cnt);
	free(list);
	return(SENDMAIL_FAILED);
    }

    arg_list_free(arg_list, num + 3 + cnt);
    free(list);
    return(SENDMAIL_SUCCESS);
}

/*
 * passwd_parent
 *
 * Args:
 *      int	 fd		file descriptor
 *	char	*message	message
 *
 * Return:
 *      0                       Success
 *      -1                      Failed
 */
static int
passwd_parent(int fd[2], char *message)
{
    int   ret, len, sum;

    close(fd[R]);

    len = strlen(message);

    sum = 0;
    while (sum < len) {
        ret = write(fd[W], message + sum, len - sum);
        if (ret < 0) {
	    log(ERR_IO_WRITE, "passwd_parent", "message");
	    close(fd[W]);
	    return -1;
        }
	sum += ret;
    }
    close(fd[W]);
    return (0);
}

int
passwd_sendmail(struct config *cfg, char *rcpt, char *message, char *sender)
{
    int		fd[2];
    int		ret;
    int 	num, cnt, new_num;
    int 	i;
    char       **list = NULL;
    char       **arg_list = NULL;
    pid_t	pid;

    /* sendpassword is not set*/
    if ((cfg->cf_sendpasswordcommand == NULL) || (strncmp(cfg->cf_sendpasswordcommand, OPTIONEND, OPTIONENDLEN) == 0)) {
        /* count sendmail command option */
        num = arg_split(&list, cfg->cf_sendmailcommand);

    /* sendpassword is seted*/
    } else {
        /* count sendmail command option */
        num = arg_split(&list, cfg->cf_sendpasswordcommand);
    }

    /* command invalid check*/
    if (num == 0) {
        log(ERR_INVALID_COMMAND, "passwd_sendmail", "num", num);
        return(SENDMAIL_FAILED);
    }

    /* passwordnoticesetsender is not set */
    if (cfg->cf_passwordnoticesetsender == 0) {
        cnt = 0;
    } else {
        cnt = 2;
    }
    arg_list = (char **)malloc(sizeof(char *) * (num + 3 + cnt));

    if (arg_list == NULL) {
        log(ERR_MEMORY_ALLOCATE, "passwd_sendmail", "arg_list", strerror(errno));
        return(SENDMAIL_FAILED);
    }
    for (i = 0; i < num; i++) {
        arg_list[i] = list[i];
    }

    new_num = num;

    /* passwordnoticesetsender is seted */
    if (cfg->cf_passwordnoticesetsender == 1) {
    
	arg_list[new_num] = strdup("-f");
	if (arg_list[new_num] == NULL) {
	    log(ERR_MEMORY_ALLOCATE, "passwd_sendmail", "arg_list", strerror(errno));
	    arg_list_free(arg_list, new_num);
	    free(list);
	    return(SENDMAIL_FAILED);
	}

	new_num++;

	arg_list[new_num] = strdup(sender);
	if (arg_list[new_num] == NULL) {
	    log(ERR_MEMORY_ALLOCATE, "passwd_sendmail", "arg_list", strerror(errno));
	    arg_list_free(arg_list, new_num);
	    free(list);
	    return(SENDMAIL_FAILED);
	}
	new_num++;
    }

    arg_list[new_num] = strdup("--");
    if (arg_list[new_num] == NULL) {
        log(ERR_MEMORY_ALLOCATE, "passwd_sendmail", "arg_list", strerror(errno));
        arg_list_free(arg_list, new_num);
        free(list);
        return(SENDMAIL_FAILED);
    }

    new_num++;

    arg_list[new_num] = strdup(rcpt);
    if (arg_list[new_num] == NULL) {
        log(ERR_MEMORY_ALLOCATE, "passwd_sendmail", "arg_list", strerror(errno));
        arg_list_free(arg_list, new_num);
        free(list);
        return(SENDMAIL_FAILED);
    }

    new_num++;
    arg_list[new_num] = NULL;

    /*
     * make pipe
     *
     * fd[R] : read only file descriptor
     * fd[W] : write only file descriptor
     */
    if (pipe(fd) == -1) {
	log(ERR_PIPE_CREATE, "passwd_sendmail", strerror(errno));
        arg_list_free(arg_list, new_num);
        free(list);
        return(SENDMAIL_FAILED);
    }

    /* make child process */
    if ((pid = fork()) == 0) {
        child(fd, arg_list);
    } else if (pid > 0) {
    /* make parent process */
        int     sts = 0;

        passwd_parent(fd, message);
        ret = waitpid(pid, &sts, WUNTRACED);
        if (ret == -1) {
	    log(ERR_WAIT_CHILD, "passwd_sendmail", strerror(errno));
            return(SENDMAIL_FAILED);
        }
        if (WIFEXITED(sts)) {
            ret = WEXITSTATUS(sts);
	    if (ret != 0) {
        	log(ERR_MAIL_SEND, "passwd_sendmail");
                arg_list_free(arg_list, new_num);
	        free(list);
        	return(SENDMAIL_FAILED);
	    }
        } else {
	    log(ERR_WAIT_CHILD, "passwd_sendmail", strerror(errno));
            arg_list_free(arg_list, new_num);
            free(list);
            return(SENDMAIL_FAILED);
        }
    } else {
	log(ERR_FORK_CREATE, "passwd_sendmail", strerror(errno));
        arg_list_free(arg_list, new_num);
        free(list);
        return(SENDMAIL_FAILED);
    }

    arg_list_free(arg_list, new_num);
    free(list);
    return(SENDMAIL_SUCCESS);
}

int sendmail_with_gmime_object(GMimeObject *obj, struct config *cfg, struct rcptaddr *rcptaddr, char *sender)
{
    int		fd[2];
    int		ret;
    int 	num, cnt;
    int 	i, j;
    char       **list = NULL;
    char       **arg_list = NULL;
    pid_t	pid;
    struct rcptaddr *p = rcptaddr;


    /* count sendmail command option */
    num = arg_split(&list, cfg->cf_sendmailcommand);
    if (num == 0) {
        return(SENDMAIL_FAILED);
    }

    /* count rcpt addr */
    for (cnt = 0; (p + cnt)->rcpt_addr != NULL; cnt++);

    arg_list = (char **)malloc(sizeof(char *) * (num + 4 + cnt));
    if (arg_list == NULL) {
        log(ERR_MEMORY_ALLOCATE, "sendmail_with_gmime_object", "arg_list", strerror(errno));
        return(SENDMAIL_FAILED);
    }
    for (i = 0; i < num; i++) {
        arg_list[i] = list[i];
    }

    arg_list[num] = strdup("-f");
    if (arg_list[num] == NULL) {
        log(ERR_MEMORY_ALLOCATE, "sendmail_with_gmime_object", "arg_list", strerror(errno));
        arg_list_free(arg_list, num);
        free(list);
        return(SENDMAIL_FAILED);
    }

    arg_list[num + 1] = strdup(sender);
    if (arg_list[num] == NULL) {
        log(ERR_MEMORY_ALLOCATE, "sendmail", "arg_list", strerror(errno));
        arg_list_free(arg_list, num + 1);
        free(list);
        return(SENDMAIL_FAILED);
    }

    arg_list[num + 2] = strdup("--");
    if (arg_list[num] == NULL) {
        log(ERR_MEMORY_ALLOCATE, "sendmail", "arg_list", strerror(errno));
	arg_list_free(arg_list, num + 2);
	free(list);
	return(SENDMAIL_FAILED);
    }

    /* add rcpt addr */
    for (j = 0; j < cnt; j++) {
	arg_list[num + 3 + j] = strdup((p + j)->rcpt_addr);
	if (arg_list[num + 3 + j] == NULL) {
            log(ERR_MEMORY_ALLOCATE, "sendmail", "arg_list", strerror(errno));
	    arg_list_free(arg_list, num + 3 + j);
	    free(list);
	    return(SENDMAIL_FAILED);
	}
    }
    arg_list[num + 3 + cnt] = NULL;

    /*
     * make pipe
     *
     * fd[R] : read only file descriptor
     * fd[W] : write only file descriptor
     */
    if (pipe(fd) == -1) {
	log(ERR_PIPE_CREATE, "sendmail", strerror(errno));
	arg_list_free(arg_list, num + 3 + cnt);
	free(list);
	return(SENDMAIL_FAILED);
    }

    /* make child process */
    if ((pid = fork()) == 0) {
	child(fd, arg_list);
    } else if (pid > 0) {
    /* make parent process */
	int	sts = 0;

	parent_gmime(fd, obj);
        /* parent process */
        ret = waitpid(pid, &sts, WUNTRACED);
        if (ret == -1) {
	    log(ERR_WAIT_CHILD, "sendmail", strerror(errno));
            return -1;
        }
	if (WIFEXITED(sts)) {
	    ret = WEXITSTATUS(sts);
	    if (ret != 0) {
        	log(ERR_MAIL_SEND, "sendmail");
	        arg_list_free(arg_list, num + 3 + cnt);
	        free(list);
        	return(SENDMAIL_FAILED);
	    }
	} else {
	    log(ERR_WAIT_CHILD, "sendmail", strerror(errno));
	    arg_list_free(arg_list, num + 3 + cnt);
	    free(list);
	    return(SENDMAIL_FAILED);
	}
    } else {
	log(ERR_FORK_CREATE, "sendmail", strerror(errno));
	arg_list_free(arg_list, num + 3 + cnt);
	free(list);
	return(SENDMAIL_FAILED);
    }

    arg_list_free(arg_list, num + 3 + cnt);
    free(list);
    return(SENDMAIL_SUCCESS);
}

static int
parent_gmime(int fd[2], GMimeObject *obj)
{
    FILE *fp;
    GMimeStream *w_stream, *f_stream;
    GMimeFilter *filter;

    close(fd[R]);

    fp = fdopen(fd[W], "w");
    if (fp == NULL) {
	log(ERR_FP_CREATE, "parent", strerror(errno));
        return -1;
    }

    /* create write stream */
    w_stream = g_mime_stream_file_new(fp);

    /* set CFLF filter */
    f_stream = g_mime_stream_filter_new(w_stream);

    g_object_unref (w_stream);

    filter = g_mime_filter_crlf_new(TRUE, FALSE);
    g_mime_stream_filter_add((GMimeStreamFilter *)f_stream, filter);
    g_object_unref(filter);

    g_mime_stream_printf(f_stream, "%s: %s\n", XHEADERNAME, XHEADERVALUE);
    g_mime_object_write_to_stream(obj, f_stream);

    g_mime_stream_flush(f_stream);

    g_object_unref(f_stream);

    return (0);
}


