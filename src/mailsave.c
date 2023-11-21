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

#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <limits.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "log.h"
#include "mailzip_config.h"
#include "mailsave.h"

static int mailsave_open(struct mailinfo *, char *);

/*
 * mail_write_file
 *
 * Function
 *      Write to temporary file.
 *
 * Argument
 *	int fd		filedeso
 *	char *buf	write string
 *	int size	write size
 *
 * Return value
 *      0       Normal end.
 *      -1      Abormal end.
 */
static int
mailsave_write_file(int fd, char *buf, int size)
{
    int offset;
    int len;
     
    for(offset = 0; offset < size; offset += len) {
	len = write(fd, buf + offset, size - offset);
	if(len < 0) {
	    log(ERR_FILE_WRITE, "mailsave_write_file");
	    return -1;
	}
    }
    return 0;
}

/*
 * mailsave_open
 *
 * Function
 *      Open to temporary file.
 *
 * Argument
 *	struct mailinfo *minfo	mailsave info structure
 *	char *path		temporary file path
 *
 * Return value
 *      fd      Normal end.
 *      -1      Abormal end.
 */
static int
mailsave_open(struct mailinfo *minfo, char *path)
{
    int  fd;
    char datestr[TMPFILE_LEN];
    time_t now;
    struct tm *tm;
    mode_t old_umask;

    now = time(NULL);
    tm = localtime(&now);

    strftime(datestr, TMPFILE_LEN, "%Y%m%d_%H%M%S_", tm);

    /* create file name */
    minfo->ii_name = (char *) malloc (strlen(path) + TMPFILE_LEN);
    if (minfo->ii_name == NULL) {
        log(ERR_MEMORY_ALLOCATE,
            "mailsave_open", "minfo->ii_name", strerror(errno));
	return -1;
    }

    sprintf(minfo->ii_name, TMPFILE_NAME, path, datestr);
    old_umask = umask(0077);
    fd = mkstemp(minfo->ii_name);
    umask(old_umask);
    if (fd < 0) {
        log(ERR_FILE_CREATE_TMPFILE,
            "mailsave_open", "minfo->ii_name", strerror(errno));
	return -1;
    }

    return fd;
}

/*
 * mailsave_write
 *
 * Function
 *      Write to temporary file or memory buffer.
 *
 * Argument
 *	struct mailinfo *minfo	mailsave info structure
 *	struct config *cfg	config structure
 *	char *buf		write string
 *	int  size		write size
 *
 * Return value
 *      0       Normal end.
 *      -1      Abormal end.
 */
int
mailsave_write(struct mailinfo *minfo, struct config *cfg, char *buf, int size)
{
    int             ret;

    if(minfo->ii_status & MS_STATUS_ERROR) {
	/* status XXXXX & Error 01000 */
	return -1;
    } else if(minfo->ii_status & MS_STATUS_FILE) {
	/* file write mode */
	ret = mailsave_write_file(minfo->ii_fd, buf, size);
	if(ret < 0) {
	    minfo->ii_status |= MS_STATUS_ERROR;
	    return -1;
	}
	minfo->ii_len += size;
	return 0;
    } else if(minfo->ii_len + size >= minfo->ii_bufsize) {
	/* 
	 * The size exceeds the memory buffer. 
	 * open temporary file
	 */
	minfo->ii_fd = mailsave_open(minfo, cfg->cf_mailsavetmpdir);
	if(minfo->ii_fd < 0) {
	    minfo->ii_status |= MS_STATUS_ERROR;
	    return -1;
	}

	minfo->ii_status |= MS_STATUS_FILE;

	/* copy to temporary file from memory buffer */
	ret = mailsave_write_file(minfo->ii_fd, 
			minfo->ii_mbuf, minfo->ii_len);  
	if(ret < 0) {
	    minfo->ii_status |= MS_STATUS_ERROR;
	    return -1;
	}

	/* New data write */
	ret = mailsave_write_file(minfo->ii_fd, buf, size);  
	if(ret < 0) {
	    minfo->ii_status |= MS_STATUS_ERROR;
	    return -1;
	}
	minfo->ii_len += size;
	return 0;
    } else {

	/* Add memory buffer */
	memcpy(minfo->ii_mbuf + minfo->ii_len, buf, size);
	minfo->ii_len += size;
	*(minfo->ii_mbuf + minfo->ii_len) = '\0';
	return 0;
    }
}

/*
 * mailsave_close
 *
 * Function
 *      Close to temporary file descriptor.
 *
 * Argument
 *	struct mailinfo *minfo	mailsave info structure
 *
 * Return value
 * 	It is not. 
 */
static void
mailsave_close(struct mailinfo *minfo)
{
    if(minfo->ii_fd >= 0) {
	close(minfo->ii_fd);
	minfo->ii_fd = -1;
    }
    minfo->ii_status |= MS_STATUS_CLOSED;
}

/*
 * mailsave_clean
 *
 * Function
 *      Clean to mailsave info.
 *
 * Argument
 *	struct mailinfo *minfo	mailsave info structure
 *
 * Return value
 *      0       Normal end.
 *      -1      Abormal end.
 */
int
mailsave_clean(struct mailinfo *minfo)
{
    int ret = 0;

    /* clear data length */
    minfo->ii_len = 0;
    if (minfo->ii_mbuf != NULL) {
	free(minfo->ii_mbuf);
    }

    if(minfo->ii_status & MS_STATUS_FILE) {
	/*
	 * Close and unlink tempolary file
	 */
	mailsave_close(minfo);
	ret = unlink(minfo->ii_name);
	if(ret < 0) {
	    log(ERR_FILE_REMOVE, "mailsave_clean", "minfo->ii_name");
	    minfo->ii_status |= MS_STATUS_ERROR;
	    return -1;
	}
	free(minfo->ii_name);
    }

    return 0;
}

/*
 * mailsave_reset
 *
 * Function
 *      Reset to mailsave info.
 *
 * Argument
 *	struct mailinfo *minfo	mailsave info structure
 *
 * Return value
 *      0       Normal end.
 *      -1      Abormal end.
 */
int
mailsave_reset(struct mailinfo *minfo)
{
    int ret = 0;

    /* clear data length */
    minfo->ii_len = 0;
    if (minfo->ii_mbuf != NULL) {
	memset(minfo->ii_mbuf, 0, MBSIZE + 1);
    }

    if(minfo->ii_status & MS_STATUS_FILE) {
	/*
	 * Close and unlink tempolary file
	 */
	mailsave_close(minfo);
	ret = unlink(minfo->ii_name);
	if(ret < 0) {
	    log(ERR_FILE_REMOVE, "mailsave_clean", "minfo->ii_name");
	    minfo->ii_status |= MS_STATUS_ERROR;
	    return -1;
	}
	free(minfo->ii_name);
    }

    minfo->ii_status = MS_STATUS_INIT;

    return 0;
}

