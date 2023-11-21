/*
 *  $Source$
 *  $Revision$
 *  $Date$
 */

#ifndef __MAILZIP_MAILSAVE_H__
#define __MAILZIP_MAILSAVE_H__

#define TMPFILE_NAME 	"%s/%sXXXXXX"
#define TMPFILE_LEN 	24   /* (BABEDIR)/YYYYMMDD_HHMMSS_XXXXXX(\0) */

struct mailinfo {
    int  ii_fd;               	/* temporary file descriptor */
    unsigned long long  ii_len;              /* total data length */
    int  ii_status;           	/* mailsave status */
    char *ii_name; 		/* mailsave name */
    char *ii_mbuf;		/* memory buffer */
    unsigned long long ii_off;  /* read offset */
    int ii_bufsize;		/* memory buffer size */
};

/*
 * Mailsave status
 */
#define MS_STATUS_INIT	    0
#define MS_STATUS_FILE      1
#define MS_STATUS_CLOSED    2
#define MS_STATUS_MAILSAVE  4
#define MS_STATUS_ERROR     8
#define MS_STATUS_READ	    16
#define MBSIZE              1048576

int mailsave_write(struct mailinfo *, struct config *, char *, int);
int mailsave_clean(struct mailinfo *);
int mailsave_reset(struct mailinfo *);

#endif /* __MAILZIP_MAILSAVE_H__ */
