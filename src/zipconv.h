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
 * $RCSfile: zipconv.h,v $
 * $Revision: 1.13 $
 * $Date: 2013/01/09 08:18:13 $
 */
#include <libmilter/mfapi.h>
#include <pthread.h>
#include "global.h"
#include "mailzip_config.h"
#include "mailsave.h"

#ifndef _MAILZIP_ZIPCONV_H_
#define _MAILZIP_ZIPCONV_H_

#define STRTIMENUM	128
#define OPTIONRP        "-rP"
#define OPTIONRPLEN     sizeof(OPTIONRP)
#define OPTIONEND "--"
#define OPTIONENDLEN	sizeof(OPTIONEND) 

#define OVERWRITE       1
#define ENV_ZIPOPT      "ZIPOPT"
#define ENV_SAMMA_ENVFROM   "SAMMA_ENVFROM"
#define GMIME_ENABLE_RFC2047_WORKAROUNDS  (1 << 0)

#define DOT		'.'
#define DOTLEN          1
#define FILE_NAME_MAX   255
#define EXTMAXLEN       5
#define SLASH		'/'
#define SLASH_REPLACE_CHAR	'_'

/* The last six characters should be XXXXXX. */
#define TMPDIR_TMPL		".samma_XXXXXX"

#define FILE_RENAME_NOEXT       "%s(%d)"
#define FILE_RENAME             "%s(%d)%s"
#define FILE_RENAME_LEN		12	/* '(',')' + 10 */
#define FILE_PATH		"%s/%s"
#define FILE_PATH_LEN		1	/* '/' */

#define SEED	"0123456789abcdefghijmnopqrstuvwxyzABCDEFGHIJKLMNPQRSTUVWXYZ0123456789"

#define MESSAGE_FILENAME	"RFC822.eml"

#define REF     "References: "
#define MSG_ID  "Message-ID:"
#define REF_LEN 12

#define XHEADERNAME	"X-SaMMA-Enc"
#define XHEADERVALUE	"YES"

#define MAX_LINE_SIZE	1024

extern pthread_mutex_t gmime_lock;

struct mailzip {
    const char *subject;
    char *date;
    GMimeMessage *message;
    char *zipdir;
    struct name_list *namelist;
    char *encfilepath;
    char *attachfilename;
#ifdef __CUSTOMIZE2018
    int  md_depth;
    int  md_pos;
    struct addmsg_tmpl *am_tmpl;
    struct mlfiPriv *am_priv;
#endif	// __CUSTOMIZE2018
};

struct rcptinfo {
    /* not allocate memory */
    char *keyword;
    int  keyword_len;
    /* allocate memory */
    char *passwd;
    /* allocate memory */
    char *extension;
    /* allocate memory */
    struct rcptaddr *rcptlist;
    /* allocate memory */
    struct rcptinfo *Next;
};

struct name_list {
    /* allocate memory */
    char *attach_name;
    int attach_name_len;
};

int parse_mail(struct mailinfo *, struct config *, struct mailzip *);
extern int delete_attachments_mail(SMFICTX *, struct mailinfo *, struct config *, char *, struct rcptinfo *);
extern int zip_convert_mail(SMFICTX *, struct mailinfo *, struct config *, char *, struct rcptinfo *, struct rcptinfo *);
void g_message_callback(GMimeObject *, gpointer);
int mk_new_filename(char *, const char *, char *, int);
int remove_file_with_dir_recursive(char *);
int mk_deletelistfile(struct config *, struct mailzip *);
int convert_zip(struct config *, struct mailzip *, struct rcptinfo *);
int check_ascii(char *);
int mk_encpath(struct config *, struct mailzip *);
int add_attach_file(struct config *, struct mailzip *, struct rcptinfo *);
int drop_file(GMimeObject *, struct config *, struct mailzip *);
void free_rcptinfo(struct rcptinfo *);
int get_msgid(char **, char *);
int set_references(char *, char **);
int replace_extension(char *, char *, char *);
#ifdef __CUSTOMIZE2018
void zipconv_log(char *, char *, struct rcptaddr *, struct name_list *, char *);
char * get_body_head(char *);
int replace_mime_part(GMimeObject *, GMimeObject *, int, struct mailzip *, GMimeContentType *);
int is_noenc_qp(char);
char * encode_qp(char *);
char * add_message(char *, struct mailzip *, char *, GMimeContentEncoding, GMimeContentType *ctype);
#endif	// __CUSTOMIZE2018

/* Return Values */
#define PM_SUCCESS		0
#define PM_NO_MULTIPART		1
#define PM_NO_ATTACHFILE	2
#define PM_FAILED		-1
#define PM_INVALID_FILENAME     -2
#define RM_R_SUCCESS		0
#define RM_R_NODIR		1
#define RM_R_FAILED		-1
#define RM_SUCCESS		0
#define RM_FAILED		-1

#define SENDMAIL_SUCCESS	0
#define SENDMAIL_FAILED		-1

#define AAL_SUCCESS		0
#define AAL_FAILED		-1

#define NEW_SUCCESS		0
#define NEW_FAILED		-1

#define	PASSWD_SUCCESS		0
#define	PASSWD_FAILED		-1

#define ZIP_CONVERT_SUCCESS	0
#define ZIP_CONVERT_FAILED	-1
#define ZIP_CONVERT_INVALID_FILENAME    -2
#define ZIP_CONVERT_ACCEPT	1

#define CONTENT_T_MULTIPART		"multipart"
#define LEN_CONTENT_T_MULTIPART		sizeof(CONTENT_T_MULTIPART)
#define CONTENT_SUBT_RELATED		"related"
#define LEN_CONTENT_SUBT_RELATED	sizeof(CONTENT_SUBT_RELATED)
#define CONTENT_SUBT_ALTERNATIVE        "alternative"
#define LEN_CONTENT_SUBT_ALTERNATIVE    sizeof(CONTENT_SUBT_ALTERNATIVE)

#endif /* _MAILZIP_ZIPCONV_H_ */
