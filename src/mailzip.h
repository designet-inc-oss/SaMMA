/*
 * samma
 *
 * Copyright (C) 2006,2007,2008,2011 DesigNET, INC.
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
 * $RCSfile: mailzip.h,v $
 * $Revision: 1.9 $
 * $Date: 2011/12/28 03:22:21 $
 */
#ifndef _MAILZIP_H_
#define _MAILZIP_H_

#include <libmilter/mfapi.h>
#include "harmless.h"
#include "sender_check.h"

#define IDENT   		"samma"
#define SOCKET_FILE     	"/var/run/samma.sock"
#define DEFAULT_TIMEOUT 	120
#define MAX_CONFIG_LINE 	1024
#define OCONN_LENGTH 		30
#define OCONN 			"inet:%d@%s"
#define false  			0
#define true   			1
#define ZIPCONV			0
#define NOZIPCONV		1
#define XHEADER			"X-SaMMA-Enc"
#define XHEADER_YES		"YES"
#define LOOP_CHECK		"yes"
#define MAX_ARGS		5
#define MLFICLOSE		0
#define MLFIABORT		1
#define BEFOR_RCPTCHECK		0
#define AFTER_RCPTCHECK		1
#define ENABLE_AUTOBCC		0
#define DISABLE_AUTOBCC		1
#define CODE_INVALID_FILENAME	"550"
#define XCODE_INVALID_FILENAME	"5.7.1"
#define MESSAGE_INVALID_FILENAME "Your attachment filename may include invalid encoding. Please rename attachment file and resend."
#define NOTSAFETYSENDER_CHECK		0
#define SAFETYSENDER_CHECK		1

/* milter */
sfsistat mlfi_connect(SMFICTX *, char *, _SOCK_ADDR *);
sfsistat mlfi_helo(SMFICTX *, char *);
sfsistat mlfi_envfrom(SMFICTX *, char **);
sfsistat mlfi_envrcpt(SMFICTX *, char **);
sfsistat mlfi_header(SMFICTX *, char *, char *);
sfsistat mlfi_eoh(SMFICTX *);
sfsistat mlfi_body(SMFICTX *, u_char *, size_t);
sfsistat mlfi_eom(SMFICTX *);
sfsistat mlfi_close(SMFICTX *);
sfsistat mlfi_abort(SMFICTX *);

int check_fromaddr(char *, char *);

/* extern */
extern sfsistat  mlfi_cleanup(SMFICTX *, int);

/* mail save struct */
struct mlfiPriv
{
    struct config   *mlfi_conf;
    struct rcptaddr *mlfi_savercpt;
    char            *mlfi_savefrom;
    struct mailinfo *mlfi_minfo;
    struct rcptinfo *mlfi_passlist;
    struct rcptinfo *mlfi_rdmpasslist;
    int		    mlfi_rcptcheck;
    int		    mlfi_encstatus;
    int		    mlfi_bccoption;
    struct rcptaddr *mlfi_savebcc;
    int             mlfi_whitelist;
    sender_check_arg_t mlfi_sendercheck_arg;
    int		    mlfi_safetysendercheck;
#ifdef __CUSTOMIZE2018
    int             mlfi_subject_lang;
    int             mlfi_sencstatus;
    char            *mlfi_subject;
    char            *mlfi_subjectf;
#endif	// __CUSTOMIZE2018
};

#if 0
pthread_t           child;
#endif

void listvardump(struct rcptinfo *);

#ifdef __CUSTOMIZE2018
#define SBJLANG_EN	100
#define SBJLANG_JP	200
int check_enc_subject(struct mlfiPriv *, char *, char **);
int check_str_mime(char *, char *, char **);
#endif	// __CUSTOMIZE2018

#endif	/* _MAILZIP_H_ */
