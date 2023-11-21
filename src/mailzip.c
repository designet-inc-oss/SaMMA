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

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <pthread.h>
#include <libmilter/mfapi.h>
#include <libdgmail.h>
#include <gmime/gmime.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>

#include "log.h"
#include "mailzip.h"
#include "mailzip_db.h"
#include "mailzip_config.h"
#include "client_side.h"
#include "maildrop.h"
#include "mailsave.h"
#include "zipconv.h"
#include "samma_policy.h"
#include "samma_autobcc.h"
#include "global.h"
#include "netlist.h"
#include "harmless.h"
#include "sender_check.h"

/* milter struct */
struct smfiDesc smfilter =
{
    IDENT,
    SMFI_VERSION,   /* version code -- do not change */
#ifndef __CUSTOMIZE2018
    SMFIF_DELRCPT,  /* flags */
#else	// ! __CUSTOMIZE2018
    SMFIF_DELRCPT | SMFIF_CHGHDRS,  /* flags */
#endif	// ! __CUSTOMIZE2018
    mlfi_connect,   /* connection info filter */
    mlfi_helo,           /* SMTP HELO command filter */
    mlfi_envfrom,   /* envelope sender filter */
    mlfi_envrcpt,   /* envelope recipient filter */
    mlfi_header,    /* header filter */
    mlfi_eoh,       /* end of header */
    mlfi_body,      /* body block filter */
    mlfi_eom,       /* end of message */
    mlfi_abort,     /* message aborted */
    mlfi_close      /* connection cleanup */
};


#define MLFIPRIV(ctx)        ((struct mlfiPriv *) smfi_getpriv(ctx))

/* Initialize as Encryption Mode */
int ismode_enc = 1;
int ismode_delete = 0;
int ismode_harmless = 0;

pthread_t child;

/*
 *  sfsistat mlfi_connect
 */
sfsistat
mlfi_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *addr)
{
    struct mlfiPriv *priv;
    struct mailinfo *minfo;

    char ipv4str[INET_ADDRSTRLEN];
    char ipv6str[INET6_ADDRSTRLEN];

    struct sockaddr_in *s = (struct sockaddr_in *)addr;
    struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)addr;

    int check_flg = ENC;

    DEBUGLOG("mlfi_connect start");

    /* START ADD: 20150316 */
    /* if is IPv4 */
    if (addr != NULL) {
        if(addr->sa_family == AF_INET) {
            if(inet_ntop(AF_INET, &s->sin_addr, ipv4str, sizeof(ipv4str)) == NULL) {
                log(ERR_WHITELIST_INVALID_IP, "mlfi_connect", ipv4str);
                return SMFIS_ACCEPT;
            }

            /* check ip in whitelist file  */
            check_flg = check_whitelist_file(AF_INET, ipv4str);

            /* file attach do not encrypt */
            if (check_flg == NOT_ENC) {
                log(WHITELIST_NOT_ENCRYPTION,"mlfi_connect", ipv4str);
                return SMFIS_ACCEPT;
            }

        /* if is IPv6 */
        } else if (addr->sa_family == AF_INET6) {
            if (inet_ntop(AF_INET6, &s6->sin6_addr, ipv6str, sizeof(ipv6str)) == NULL) {
                log(ERR_WHITELIST_INVALID_IP, "mlfi_connect", ipv6str);
                return SMFIS_ACCEPT;
            }
            /* check ip in whitelist file  */
            check_flg = check_whitelist_file(AF_INET6, ipv6str);
            /* file attach do not encrypt */
            if (check_flg == NOT_ENC) {
                log(WHITELIST_NOT_ENCRYPTION,"mlfi_connect", ipv6str);
                return SMFIS_ACCEPT;
            }
        }

    /* unknown */
    } else {
       log("%s: socket family is not supported\n", IDENT);
    }

    /* ENDADD 20150316 */

    /* mail save */
    priv = malloc(sizeof *priv);
    if(priv == NULL) {
        log(ERR_MEMORY_ALLOCATE, "mlfi_connect", "priv", strerror(errno));
        return SMFIS_TEMPFAIL;
    }

    memset(priv, 0, sizeof *priv);

    /* read config */
    priv->mlfi_conf = config_init();

    priv->mlfi_rcptcheck = BEFOR_RCPTCHECK;

    /* set encription flag */
    priv->mlfi_encstatus = ENC;
    //initialization for Encryption mode and Delete mode.

    if (ismode_enc) {
        if (priv->mlfi_conf->cf_autobccoption[0] == 'Y'
            || priv->mlfi_conf->cf_autobccoption[0] == 'y'
        ) {
            priv->mlfi_bccoption = ENABLE_AUTOBCC;
        }
        else {
            priv->mlfi_bccoption = DISABLE_AUTOBCC;
        }

    }

    if (ismode_harmless) {
        if (addr != NULL) {
            char *tmp_ip;
            if (addr->sa_family == AF_INET) {
                tmp_ip = malloc(INET_ADDRSTRLEN);
                if (tmp_ip == NULL) {
                    log(ERR_MEMORY_ALLOCATE,
                            "mlfi_connect", "tmp_ip", strerror(errno));
                    mlfi_cleanup(ctx, MLFIABORT);
                    return SMFIS_TEMPFAIL;
                }
                priv->mlfi_sendercheck_arg.sa.sa_in = *s;
                priv->mlfi_sendercheck_arg.af = AF_INET;

                if (inet_ntop(AF_INET, &s->sin_addr, tmp_ip, INET_ADDRSTRLEN) == NULL) {
                    log(ERR_WHITELIST_INVALID_IP, "mlfi_connect", ipv4str);
                    mlfi_cleanup(ctx, MLFIABORT);
                    return SMFIS_TEMPFAIL;
                }
            } else {
                tmp_ip = malloc(INET6_ADDRSTRLEN);
                if (tmp_ip == NULL) {
                    log(ERR_MEMORY_ALLOCATE,
                            "mlfi_connect", "tmp_ip6", strerror(errno));
                    mlfi_cleanup(ctx, MLFIABORT);
                    return SMFIS_TEMPFAIL;
                }
                priv->mlfi_sendercheck_arg.sa.sa_in6 = *s6;
                priv->mlfi_sendercheck_arg.af = AF_INET6;

                if (inet_ntop(AF_INET6, &s6->sin6_addr, tmp_ip, INET6_ADDRSTRLEN) == NULL) {
                    log(ERR_WHITELIST_INVALID_IP, "mlfi_connect", ipv4str);
                    mlfi_cleanup(ctx, MLFIABORT);
                    return SMFIS_TEMPFAIL;
                }
            }

            priv->mlfi_sendercheck_arg.ip = tmp_ip;
        } else {
            priv->mlfi_sendercheck_arg.ip = NULL;
        }
    }


    /* create mailinfo structure */
    minfo = malloc(sizeof *minfo);
    if(minfo == NULL) {
        log(ERR_MEMORY_ALLOCATE, "mlfi_connect", "minfo", strerror(errno));
        mlfi_cleanup(ctx, MLFIABORT);
        return SMFIS_TEMPFAIL;
    }
    memset(minfo, 0, sizeof *minfo);

    minfo->ii_mbuf = (char *)malloc(MBSIZE + 1);
    if(minfo->ii_mbuf == NULL) {
        log(ERR_MEMORY_ALLOCATE, "mlfi_connect", "minfo->ii_mbuf", strerror(errno));
        mlfi_cleanup(ctx, MLFIABORT);
        return SMFIS_TEMPFAIL;
    }

    minfo->ii_bufsize = MBSIZE;

    priv->mlfi_minfo = minfo;

    smfi_setpriv(ctx, priv);

    return SMFIS_CONTINUE;
}

/*
 *  sfsistat mlfi_helo
 */
sfsistat
mlfi_helo(SMFICTX *ctx, char *helohost)
{
    struct mlfiPriv *priv;

    if ((priv = MLFIPRIV(ctx)) == NULL) {
        log(ERR_GET_PRIV, "mlfi_helo");
        mlfi_cleanup(ctx, MLFIABORT);
        return SMFIS_TEMPFAIL;
    }
    DEBUGLOG("mlfi_helo start");

    free(priv->mlfi_sendercheck_arg.helo);
    priv->mlfi_sendercheck_arg.helo = NULL;

    if ((priv->mlfi_sendercheck_arg.helo = strdup(helohost)) == NULL) {
        log(ERR_GET_PRIV, "mlfi_helo");
        mlfi_cleanup(ctx, MLFIABORT);
        return SMFIS_TEMPFAIL;
    }

    return SMFIS_CONTINUE;
}

/*
 *  sfsistat mlfi_envfrom
 *  env
 */
sfsistat
mlfi_envfrom(SMFICTX *ctx, char **envfrom)
{
    char *fromaddr;
    int ret;
    struct mlfiPriv *priv;
    char *fqdn;

    if ((priv = MLFIPRIV(ctx)) == NULL) {
        log(ERR_GET_PRIV, "mlfi_envfrom");
        mlfi_cleanup(ctx, MLFIABORT);
        return SMFIS_TEMPFAIL;
    }


    DEBUGLOG("mlfi_envfrom start");

    /* get mail addr */
    fromaddr = get_addrpart((unsigned char *)*envfrom);
    if (fromaddr == NULL) {
        log(ERR_MAIL_FIND_ADDRESS, "mlfi_envfrom");
        mlfi_cleanup(ctx, MLFIABORT);
        return SMFIS_TEMPFAIL;
    }

    if (ismode_delete) {
        /* All sender accepted when SaMMA is running in delete mode. */
        /* save from addr temporally */
        priv->mlfi_savefrom = fromaddr;
        DEBUGLOG("Sender Accepted");
        return SMFIS_CONTINUE;
    }

    if (ismode_harmless) {
        priv->mlfi_savefrom = fromaddr;

        priv->mlfi_sendercheck_arg.envelope_from = strdup(fromaddr);
        if (priv->mlfi_sendercheck_arg.envelope_from == NULL) {
            log(ERR_MEMORY_ALLOCATE, "mlfi_envfrom", "enc_from", strerror(errno));
            mlfi_cleanup(ctx, MLFIABORT);
            return SMFIS_TEMPFAIL;
        }

        DEBUGLOG("Sender Accepted");
        return SMFIS_CONTINUE;
    }

    /* invalid character check */
    if (ismode_enc) {
        ret = check_fromaddr(fromaddr, priv->mlfi_conf->cf_allowcharenvelopefrom);
        if (ret != 0) {
            log(INVALID_CHAR, fromaddr);
            return SMFIS_REJECT;
        }
    }

     /* domain null check */
    fqdn = strchr(fromaddr, ATMARK);
    if (fqdn == NULL) {
        free(fromaddr);
        mlfi_cleanup(ctx, MLFIABORT);
        return SMFIS_ACCEPT;
    }

    /* search fromaddr */
    ret = search_fromaddr_bdb(priv->mlfi_conf, fromaddr);
    if (ret < 0) {
        free(fromaddr);
        mlfi_cleanup(ctx, MLFIABORT);

        return SMFIS_TEMPFAIL;
#ifndef __CUSTOMIZE2018
    } else if (ret == NOT_ENC) {
#else	// __CUSTOMIZE2018
    // force into ENC mode anyway if subject enc mode
    } else if (ret == NOT_ENC && ! priv->mlfi_conf->cff_subencmode) {
#endif	// __CUSTOMIZE2018
        if (priv->mlfi_bccoption == DISABLE_AUTOBCC) {
            free(fromaddr);
            mlfi_cleanup(ctx, MLFIABORT);

            return SMFIS_ACCEPT;
        }
        /* save envription status */
        priv->mlfi_encstatus = NOT_ENC;
    }
    /* save from addr temporally */
    priv->mlfi_savefrom = fromaddr;

    return SMFIS_CONTINUE;
}

/*
 *  sfsistat mlfi_envrcpt
 *  env
 */
sfsistat
mlfi_envrcpt(SMFICTX *ctx, char **rcptto)
{
    char *rcptaddr = NULL;
    struct mlfiPriv *priv;
    if ((priv = MLFIPRIV(ctx)) == NULL) {
        log(ERR_GET_PRIV, "mlfi_envrcpt");
        mlfi_cleanup(ctx, MLFIABORT);
        return SMFIS_TEMPFAIL;
    }

    DEBUGLOG("mlfi_envrcpt start");

    /* get mail addr */
    rcptaddr = get_addrpart_notranslate((unsigned char *)*rcptto);
    if (rcptaddr == NULL) {
        if (rcptaddr != NULL) {
            free(rcptaddr);
        }
        log(ERR_MAIL_FIND_ADDRESS, "mlfi_envrcpt");
        mlfi_cleanup(ctx, MLFIABORT);
        return SMFIS_TEMPFAIL;
    }

    DEBUGLOG("get mail addr: %s", rcptaddr);

    /* push rcpt addr */
    if (push_rcptlist(&(priv->mlfi_savercpt), rcptaddr) != 0) {
        mlfi_cleanup(ctx, MLFIABORT);
        free(rcptaddr);
        return SMFIS_TEMPFAIL;
    }
    free(rcptaddr);

    /* set RcptTo check flag */
    priv->mlfi_rcptcheck = BEFOR_RCPTCHECK;

    return SMFIS_CONTINUE;
}

/*
 * sfsistat mlfi_header
 * header
 */
sfsistat
mlfi_header(SMFICTX *ctx, char *headerf, char *headerv)
{
    char *header;
    int ret, len;
    struct mlfiPriv *priv;
    struct rcptinfo *passlist = NULL, *rdmpasslist = NULL;
#ifdef __CUSTOMIZE2018
    char *new_subject = NULL;
    int chk_ret = 0;
#endif	// __CUSTOMIZE2018

    if ((priv = MLFIPRIV(ctx)) == NULL) {
        log(ERR_GET_PRIV, "mlfi_header");
        mlfi_cleanup(ctx, MLFIABORT);
        return SMFIS_TEMPFAIL;
    }

    DEBUGLOG("mlfi_header start");

    if (strcasecmp(headerf, "Message-Id") == 0) {
        free(priv->mlfi_sendercheck_arg.message_id);
        priv->mlfi_sendercheck_arg.message_id = NULL;
        priv->mlfi_sendercheck_arg.message_id = strdup(headerv);
        if (priv->mlfi_sendercheck_arg.message_id == NULL) {
            log(ERR_MEMORY_ALLOCATE, "mlfi_header", "message-id", strerror(errno));
            mlfi_cleanup(ctx, MLFIABORT);
            return SMFIS_TEMPFAIL;
        }
    }

    // Cases for priv->mlfi_encstatus == NOT_ENC:
    //  o Not-Encryption due to the fromDB.
    //  o Not-Encryption as a result of the following rcptcheck.
    if (priv->mlfi_encstatus == NOT_ENC) {
        return SMFIS_CONTINUE;
    }

    /* START ADD: 20150323 */
    /* check loop encryption */
    if ((strcmp(priv->mlfi_conf->cf_loopcheck, LOOP_CHECK) == 0 ) &&
        (strcmp(headerf, XHEADER) == 0) &&
        (strcmp(headerv, XHEADER_YES) == 0)) {
        mlfi_cleanup(ctx, MLFIABORT);
        return SMFIS_ACCEPT;
    }
    /* END ADD: 20150323*/

    /* RcptTo Check */
    if (priv->mlfi_rcptcheck == BEFOR_RCPTCHECK) {

        if (ismode_enc) {
            /* Encryption Mode */
            if (priv->mlfi_bccoption == ENABLE_AUTOBCC) {
                ret = add_bccaddr(priv->mlfi_conf, priv->mlfi_savefrom,
                        &priv->mlfi_savercpt, &priv->mlfi_savebcc);
                if (ret != SUCCESS) {
                    mlfi_cleanup(ctx, MLFIABORT);
                    return SMFIS_TEMPFAIL;
                }
            }

#ifndef __CUSTOMIZE2018
            if (ismode_enc) {
                ret = search_rcptaddr(priv->mlfi_conf, priv->mlfi_savefrom,
                        priv->mlfi_savercpt, &passlist, &rdmpasslist);
            }
#else	// ! __CUSTOMIZE2018
            if (priv->mlfi_conf->cff_subencmode == 1) {
                ret = search_rcptaddr(priv->mlfi_conf, priv->mlfi_savefrom,
                        priv->mlfi_savercpt, &passlist, &rdmpasslist);
                if (ret == NOT_ENC) {
                    // force encryption state
                    ret = ENC;
                }
            } else {
                ret = search_rcptaddr(priv->mlfi_conf, priv->mlfi_savefrom,
                        priv->mlfi_savercpt, &passlist, &rdmpasslist);
            }
#endif	// ! __CUSTOMIZE2018
        } else {
            /* Delete Mode */
            /* harmless Mode */
            ret = search_rcptaddr_delmode(priv->mlfi_conf,
                    priv->mlfi_savercpt, &passlist, &rdmpasslist);
            // Delete recipients are added to passlist.
        }

        if (ret < 0) {
            free_rcptinfo(passlist);
            free_rcptinfo(rdmpasslist);
            mlfi_cleanup(ctx, MLFIABORT);
            return SMFIS_TEMPFAIL;
        }

        if (ret == NOT_ENC) {
            free_rcptinfo(passlist);
            free_rcptinfo(rdmpasslist);
            if (ismode_delete) {
                mlfi_cleanup(ctx, MLFIABORT);
                return SMFIS_ACCEPT;
            }
            if (priv->mlfi_bccoption == DISABLE_AUTOBCC) {
                mlfi_cleanup(ctx, MLFIABORT);
                return SMFIS_ACCEPT;
            }
            /* save encription status */
            priv->mlfi_encstatus = NOT_ENC;
            priv->mlfi_rcptcheck = AFTER_RCPTCHECK;
            return SMFIS_CONTINUE;
        }

        /* save encryption address list */
        priv->mlfi_passlist = passlist;
        priv->mlfi_rdmpasslist = rdmpasslist;

        priv->mlfi_rcptcheck = AFTER_RCPTCHECK;
    }


#ifdef DEBUG
listvardump(passlist);
#endif
//DEBUGLOG("headerf= %s", headerf);
//DEBUGLOG("headerv= %s", headerv);

#ifdef __CUSTOMIZE2018
    if (ismode_enc) {
        if (priv->mlfi_conf->cff_subencmode == 1
		    && strcasecmp(headerf, "Subject") == 0) {
            // rewrite and store subject if necessary
            if (priv->mlfi_subject == NULL) {
                chk_ret = check_enc_subject(priv, headerv, &new_subject);
                switch(chk_ret) {
                case 1:	// Do encrypt
                    priv->mlfi_subjectf = strdup(headerf);
                    if (priv->mlfi_subjectf == NULL) {
                        // memory error
                        log(ERR_MEMORY_ALLOCATE, "mlfi_header", "header", strerror(errno));
                        mlfi_cleanup(ctx, MLFIABORT);
                        free(new_subject);
                        return SMFIS_TEMPFAIL;
                    }
                    priv->mlfi_subject = new_subject;
                    priv->mlfi_sencstatus = ENC;
                    priv->mlfi_encstatus = ENC;
                    headerv = new_subject;
                    break;
                case 0:	// Do not encrypt
                    /* save encription status */
                    priv->mlfi_encstatus = NOT_ENC;
                    priv->mlfi_sencstatus = NOT_ENC;
                    if (ismode_delete) {
                        mlfi_cleanup(ctx, MLFIABORT);
                        return SMFIS_ACCEPT;
                    }
                    if (priv->mlfi_bccoption == DISABLE_AUTOBCC) {
                        mlfi_cleanup(ctx, MLFIABORT);
                        return SMFIS_ACCEPT;
                    }
                    if (new_subject != NULL) {
                        free(new_subject);
                    }
                    return SMFIS_CONTINUE;
                default:	// Error status
                    log(ERR_MEMORY_ALLOCATE, "mlfi_header", "header", strerror(errno));
                    mlfi_cleanup(ctx, MLFIABORT);
                    return SMFIS_TEMPFAIL;
                }
            }
        }
    }
#endif	// __CUSTOMIZE2018

    /* create header line */
    len = strlen(headerf) + strlen(headerv) + 4;
    header = malloc(len + 1);
    if (!header) {
        log(ERR_MEMORY_ALLOCATE, "mlfi_header", "header", strerror(errno));
        mlfi_cleanup(ctx, MLFIABORT);
        return SMFIS_TEMPFAIL;
    }
    sprintf(header, "%s: %s\n", headerf, headerv);

    /* write header */
    if (mailsave_write(priv->mlfi_minfo, priv->mlfi_conf, header, len - 1) != 0 ) {
        /* write error */
        log(ERR_MAILSAVE_WRITE, "mlfi_header", header);
        free(header);
        mlfi_cleanup(ctx, MLFIABORT);
        return SMFIS_TEMPFAIL;
    }
    free(header);


    return SMFIS_CONTINUE;
}

/*
 * mlfi_eoh
 * header & body
 */
sfsistat
mlfi_eoh(SMFICTX *ctx)
{
    struct mlfiPriv *priv;
    int ret;

    DEBUGLOG("mlfi_eoh start");

    if ((priv = MLFIPRIV(ctx)) == NULL) {
        log(ERR_GET_PRIV, "mlfi_eoh");
        mlfi_cleanup(ctx, MLFIABORT);
        return SMFIS_TEMPFAIL;
    }

#ifdef __CUSTOMIZE2018
    if (ismode_enc) {
        if (priv->mlfi_conf->cff_subencmode == 1
                && priv->mlfi_sencstatus != ENC
                && priv->mlfi_encstatus == ENC) {
            // subject not found
            free_rcptinfo(priv->mlfi_passlist);
            priv->mlfi_passlist = NULL;
            free_rcptinfo(priv->mlfi_rdmpasslist);
            priv->mlfi_rdmpasslist = NULL;
            /* save encription status */
            priv->mlfi_encstatus = NOT_ENC;
            priv->mlfi_sencstatus = NOT_ENC;
            if (ismode_delete) {
                mlfi_cleanup(ctx, MLFIABORT);
                return SMFIS_ACCEPT;
            }
            if (priv->mlfi_bccoption == DISABLE_AUTOBCC) {
                mlfi_cleanup(ctx, MLFIABORT);
                return SMFIS_ACCEPT;
            }
            return SMFIS_CONTINUE;
        }
    }
#endif	// __CUSTOMIZE2018

    if (priv->mlfi_encstatus == NOT_ENC) {
        return SMFIS_CONTINUE;
    }

    if (ismode_harmless) {
        priv->mlfi_safetysendercheck = NOTSAFETYSENDER_CHECK;
        ret = check_sender(priv);
        switch (ret) {
            case SENDER_CHECK_OK:
                if (priv->mlfi_conf->cf_safetysenderharmlessconf == NULL) {
                    // SafetySenderHarmlessConfが設定されていなければそのまま
                    return SMFIS_ACCEPT;
                } else {
                    // SafetySenderHarmlessConfが設定されていたらフラグ立てる
                    priv->mlfi_safetysendercheck = SAFETYSENDER_CHECK;
                    // 無害化処理へ
                    break;
                }
            case SENDER_CHECK_NONE:
            // SenderCheck=noneの場合は、何もせずに終了
                 return SMFIS_ACCEPT;
            case SENDER_CHECK_NG:
                log(
                    LOG_HARMLESS
                    , priv->mlfi_sendercheck_arg.ip
                    , priv->mlfi_sendercheck_arg.message_id
                    , priv->mlfi_sendercheck_arg.envelope_from
                    , priv->mlfi_sendercheck_arg.rcpt_to
                );
                break;		// 無害化処理を行う
            case SENDER_CHECK_ERR:
            default:
                mlfi_cleanup(ctx, MLFIABORT);
                return SMFIS_TEMPFAIL;
        }
    }

    /* write new line between header and body */
    if (mailsave_write(priv->mlfi_minfo, priv->mlfi_conf, "\n", 1) == -1 ) {
        /* write error */
        log(ERR_MAILSAVE_WRITE, "mlfi_eoh", "blank line");
        mlfi_cleanup(ctx, MLFIABORT);
        return SMFIS_TEMPFAIL;
    }

    return SMFIS_CONTINUE;
}

/*
 * mlfi_body
 * write body
 */
sfsistat
mlfi_body(SMFICTX *ctx, u_char *bodyp, size_t bodylen)
{
    struct mlfiPriv *priv;
    if ((priv = MLFIPRIV(ctx)) == NULL) {
        log(ERR_GET_PRIV, "mlfi_body");
        mlfi_cleanup(ctx, MLFIABORT);
        return SMFIS_TEMPFAIL;
    }

    DEBUGLOG("mlfi_body start");

    if (priv->mlfi_encstatus == NOT_ENC) {
        return SMFIS_CONTINUE;
    }

    /* write body */
    if (mailsave_write(priv->mlfi_minfo, priv->mlfi_conf, (char *)bodyp, bodylen) == -1 ) {
        /* write error */
        log(ERR_MAILSAVE_WRITE, "mlfi_body", "body data");
        mlfi_cleanup(ctx, MLFIABORT);
        return SMFIS_TEMPFAIL;
    }

    return SMFIS_CONTINUE;
}

/*
 * mlfi_eom
 * end
 */
sfsistat
mlfi_eom(SMFICTX *ctx)
{
    int ret, i;
    struct mlfiPriv *priv;
    if ((priv = MLFIPRIV(ctx)) == NULL) {
        log(ERR_GET_PRIV, "mlfi_eom");
        mlfi_cleanup(ctx, MLFIABORT);
        return SMFIS_TEMPFAIL;
    }

    DEBUGLOG("mlfi_eom start");

#ifdef __CUSTOMIZE2018
if (ismode_enc) {
    // Change header if EncStr exists
    if (priv->mlfi_conf->cff_subencmode == 1
            && priv->mlfi_sencstatus == ENC) {
        ret = smfi_chgheader(ctx, priv->mlfi_subjectf, 1, priv->mlfi_subject);
        if (ret != MI_SUCCESS) {
            log("smfi_chgheader() failed. %d", ret);
            mlfi_cleanup(ctx, MLFIABORT);
            return SMFIS_TEMPFAIL;
        }
    }
}
#endif	// __CUSTOMIZE2018

    if (priv->mlfi_savebcc != NULL) {
        for (i = 0; (priv->mlfi_savebcc + i)->rcpt_addr != NULL; i++) {
            if (smfi_addrcpt(ctx, (priv->mlfi_savebcc + i)->rcpt_addr) != MI_SUCCESS) {
        	log(ERR_AUTOBCC, "mlfi_eom", "smfi_addrcpt() failed.");
        	mlfi_cleanup(ctx, MLFIABORT);
        	return SMFIS_TEMPFAIL;
            }
        }
    }

    if (priv->mlfi_encstatus == NOT_ENC) {
        mlfi_cleanup(ctx, MLFIABORT);
        return SMFIS_ACCEPT;
    }

    if (ismode_delete) {
        /* Delete Attachments */
        ret = delete_attachments_mail(ctx, priv->mlfi_minfo,
                priv->mlfi_conf, priv->mlfi_savefrom,
                priv->mlfi_rdmpasslist);
    } else if (ismode_harmless) {
        ret = harmless(ctx, priv);
    } else {
        /* Encryption Process */
        ret = zip_convert_mail(ctx, priv->mlfi_minfo, priv->mlfi_conf,
                priv->mlfi_savefrom, priv->mlfi_passlist,
                priv->mlfi_rdmpasslist);
    }

    /* Reset MailSave Information */
    mailsave_reset(priv->mlfi_minfo);
    mlfi_cleanup(ctx, MLFIABORT);

    if (ret == PM_FAILED) {
        return SMFIS_TEMPFAIL;
    } else if (ret == ZIP_CONVERT_ACCEPT) {
        return SMFIS_ACCEPT;
    } else if (ret == ZIP_CONVERT_INVALID_FILENAME) {
        if (smfi_setreply(ctx, CODE_INVALID_FILENAME, XCODE_INVALID_FILENAME,
                          MESSAGE_INVALID_FILENAME) != MI_SUCCESS) {
            return SMFIS_TEMPFAIL;
        }
        return SMFIS_REJECT;
    }

    return SMFIS_CONTINUE;
}

/*
 * mlfi_close
 * close
 */
sfsistat
mlfi_close(SMFICTX *ctx)
{
    DEBUGLOG("mlfi_close start");

    mlfi_cleanup(ctx, MLFICLOSE);

    return SMFIS_CONTINUE;
}

/*
 * mlfi_abort
 * abort
 */
sfsistat
mlfi_abort(SMFICTX *ctx)
{
    DEBUGLOG("mlfi_abort start");

    mlfi_cleanup(ctx, MLFIABORT);
    return SMFIS_CONTINUE;
}

/*
 * check_fromaddr
 */
int
check_fromaddr(char *addr, char *allowchar)
{
    if (allowchar ==  NULL) {
        return 1;
    }

    char *p;

    for (p = addr; *p != '\0'; p++) {
        if (strchr(allowchar, *p) == NULL) {
            return 1;
        }
    }
    return 0;
}

/*
 * mlfi_cleanup
 * cleanup
 */
sfsistat
mlfi_cleanup(SMFICTX *ctx, int flag)
{
    sfsistat rstat = SMFIS_CONTINUE;
    struct mlfiPriv *priv;
    /* null data return */
    if ((priv = MLFIPRIV(ctx)) == NULL) {
        return rstat;
    }

    /* priv release */
    if (priv->mlfi_savefrom != NULL) {
        free(priv->mlfi_savefrom);
        priv->mlfi_savefrom = NULL;
    }

    if (priv->mlfi_savercpt != NULL) {
        free_rcptlist(priv->mlfi_savercpt);
        priv->mlfi_savercpt = NULL;
    }

    if (priv->mlfi_passlist != NULL) {
        free_rcptinfo(priv->mlfi_passlist);
        priv->mlfi_passlist = NULL;
    }

    if (priv->mlfi_rdmpasslist != NULL) {
        free_rcptinfo(priv->mlfi_rdmpasslist);
        priv->mlfi_rdmpasslist = NULL;
    }

    if (priv->mlfi_savebcc != NULL) {
        free_rcptlist(priv->mlfi_savebcc);
        priv->mlfi_savebcc = NULL;
    }

#ifdef __CUSTOMIZE2018
if (ismode_enc) {
    if (priv->mlfi_subject != NULL) {
        free(priv->mlfi_subject);
        priv->mlfi_subject = NULL;
    }
    if (priv->mlfi_subjectf != NULL) {
        free(priv->mlfi_subjectf);
        priv->mlfi_subjectf = NULL;
    }
}
#endif	// __CUSTOMIZE2018

    free(priv->mlfi_sendercheck_arg.ip);
    priv->mlfi_sendercheck_arg.ip = NULL;

    free(priv->mlfi_sendercheck_arg.helo);
    priv->mlfi_sendercheck_arg.helo = NULL;

    free(priv->mlfi_sendercheck_arg.envelope_from);
    priv->mlfi_sendercheck_arg.envelope_from = NULL;

    free(priv->mlfi_sendercheck_arg.message_id);
    priv->mlfi_sendercheck_arg.message_id = NULL;

    free(priv->mlfi_sendercheck_arg.rcpt_to);
    priv->mlfi_sendercheck_arg.rcpt_to = NULL;

    priv->mlfi_sendercheck_arg.af = 0;

    if (flag == MLFICLOSE) {
        /* config relase */
        if (priv->mlfi_conf != NULL) {
            config_release(priv->mlfi_conf);
            priv->mlfi_conf = NULL;
        }

        if (priv->mlfi_minfo != NULL) {
            mailsave_clean(priv->mlfi_minfo);
            free(priv->mlfi_minfo);
            priv->mlfi_minfo = NULL;
        }

        free(priv);

        /* set NULL */
        smfi_setpriv(ctx, NULL);
    }

    return rstat;
}

static void *
call_command(void *arg)
{
    struct thread_control *tcl;
    int ret = 0;

    tcl = (struct thread_control *)arg;

    if (accept_command(tcl->configname , tcl->addr, tcl->port) != 0) {
        log(ERR_RELOAD_SERVER, "call_command");
    }

    pthread_exit(&ret);
}

/*
 * usage
 *
 */
void
usage(char *arg)
{
    fprintf(stderr, "usage: %s [-v] [-d|-h] [-t timeout] [config file]\n", arg);
}

void
version()
{
    printf("SaMMA (%s) - SAfety Mail gateway with Milter Api\n\tDesignet.inc\n", SAMMA_VERSION);
}

int
main(int argc, char *argv[])
{

    char  *args = "dhvt:";
    char  *confname;
    char  *tmp;
    char   c;
    char  oconn[OCONN_LENGTH];
    int    timeout = DEFAULT_TIMEOUT;
    unsigned long tmp_val;
    struct thread_control tcl;
    struct config *cfg;

    /* set rand function */
    srand48(time(NULL));

    /* ignore sigpipe signal */
    signal(SIGPIPE, SIG_IGN);

    /* set error output to stderr */
    init_log();

    /* arg */
    while ((c = getopt(argc, argv, args)) != -1) {

        switch (c) {

        /* arg time out */
        case 't':
            if((optarg == NULL) || (optarg[0] == '\0')) {
                usage(argv[0]);
                exit(1);
            }

            tmp_val = strtoul(optarg, &tmp, 10);
            if((*tmp != '\0') ||
               ((tmp_val == ULONG_MAX) && (errno == ERANGE)) ||
               (tmp_val > INT_MAX)) {
                usage(argv[0]);
                exit(1);
            }

            timeout = (int) tmp_val;
            break;
        case 'd':
            /* Delete Mode */
            ismode_enc = 0;
            ismode_delete = 1;
            break;

        case 'h':
            ismode_enc = 0;
            ismode_harmless = 1;
            break;

        case 'v':
            version();
            exit(1);

        /* error */
        default:
            usage(argv[0]);
            exit(1);
        }
    }

    /* check arg */
    if (argc > MAX_ARGS) {
        usage(argv[0]);
        exit(1);
    } else if(optind + 1 == argc) {

        /* set config name */
        confname = argv[optind];
    } else if (optind == argc) {
        /* set default config name */
        confname = DEFAULT_CONFFILE;
    } else {
        usage(argv[0]);
        exit(1);
    }

    if (ismode_delete * ismode_harmless) {
        usage(argv[0]);
        exit(1);
    }

    /* Select config entries. */
    select_cfentry();

    /* read config file */
    if (reload_config(confname) != 0) {
        fprintf(stderr, STDERR_CONFIG_READ, confname);
        fprintf(stderr, "\n");
        exit(2);
    }

    cfg = config_init();

    /* set thread data */
    tcl.configname = confname;
    tcl.port = cfg->cf_commandport;
    tcl.addr = strdup(cfg->cf_listenip);
    if (tcl.addr == NULL) {
        fprintf(stderr, STDERR_MEMORY_ALLOCATE, "tcl.addr", strerror(errno));
        fprintf(stderr, "\n");
        exit(2);
    }

    /* initialize GMime */
    g_mime_init (GMIME_ENABLE_RFC2047_WORKAROUNDS);

    /* prepare socket string */
    sprintf(oconn, OCONN, cfg->cf_listenport, cfg->cf_listenip);

    /* config relase */
    config_release(cfg);

    /* command line thread */
    pthread_create(&child, NULL, call_command, &tcl);

    /* set socket */
    if(smfi_setconn(oconn) == MI_FAILURE) {
        fprintf(stderr, ERR_MILTER_SET_SOCKET, strerror(errno));
        fprintf(stderr, "\n");
        g_mime_shutdown();
        exit(3);
    }

    /* set time out */
    if(smfi_settimeout(timeout) == MI_FAILURE) {
        fprintf(stderr, ERR_MILTER_SET_TIMEOUT, strerror(errno));
        fprintf(stderr, "\n");
        g_mime_shutdown();
        exit(3);
    }

    /* set register */
    smfilter.xxfi_flags |= SMFIF_ADDRCPT;
    if(smfi_register(smfilter) == MI_FAILURE) {
        fprintf(stderr, ERR_MILTER_REGISTER, strerror(errno));
        fprintf(stderr, "\n");
        g_mime_shutdown();
        exit(4);
    }

    /* run main */
    if(smfi_main() == MI_FAILURE) {
        fprintf(stderr, ERR_MILTER_START, strerror(errno));
        fprintf(stderr, "\n");
        g_mime_shutdown();
        exit(5);
    }

    g_mime_shutdown();

    exit(0);
}

/* for debug  */
#ifdef DEBUG
void
listvardump(struct rcptinfo *passlist)
{
    int i;
    struct rcptinfo *x = NULL;

    for (x = passlist; x != NULL; x = x->Next) {
        for (i = 0; (x->rcptlist + i)->rcpt_addr != NULL; i++) {
            DEBUGLOG("p= %p, addr= %s, p->Next= %p",
                     x, (x->rcptlist + i)->rcpt_addr, x->Next);
        }
    }

    return;
}
#endif

#ifdef __CUSTOMIZE2018
int
check_enc_subject(struct mlfiPriv *priv, char *subject, char **new_subject)
{
    char *str_en;
    char *str_jp;
    int ret;

    str_en = priv->mlfi_conf->cf_subjectencryptstringen;
    str_jp = priv->mlfi_conf->cf_subjectencryptstringjp;

    // search String EN
    if (str_en != NULL && *str_en != '\0'
        && strncmp(subject, str_en, strlen(str_en)) == 0) {
        // found
        *new_subject = strdup(subject + strlen(str_en));
        if (*new_subject == NULL) {
            return -1;
        }
        priv->mlfi_subject_lang = SBJLANG_EN;
        return 1;
    }

    // search String EN from MIME part
    ret = check_str_mime(subject, str_en, new_subject);
    if (ret != 0) {
        if (ret == 1) {
            // found
            priv->mlfi_subject_lang = SBJLANG_EN;
        }
        return ret;
    }
    
    // search String JP
    if (str_jp != NULL && *str_jp != '\0'
        && strncmp(subject, str_jp, strlen(str_jp)) == 0) {
        // found
        *new_subject = strdup(subject + strlen(str_jp));
        if (*new_subject == NULL) {
            return -1;
        }
        priv->mlfi_subject_lang = SBJLANG_JP;
        return 1;
    }

    // search String JP from MIME part
    ret = check_str_mime(subject, str_jp, new_subject);
    if (ret != 0) {
        if (ret == 1) {
            // found
            priv->mlfi_subject_lang = SBJLANG_JP;
        }
        return ret;
    }

    // not found
    return 0;
}

int
check_str_mime(char *subject, char *needle, char **new_buf)
{
    char *dec_str, *enc_str;
    char *start, *end;
    char *p, *q;
    int ret;
    size_t n_len, new_len;

    if (needle == NULL || *needle == '\0') {
        // needle is not defined
        return 0;
    }

    *new_buf = NULL;
    if (strncmp(subject, "=?", 2) == 0) {
        p = strchr(subject + 2, '?');
        if (p != NULL && strncasecmp(p + 1, "B?", 2) == 0) {
            start = p + 3;
            q = strchr(start, '?');
            if (q != NULL && *(q + 1) == '=') {
                end = q;
                ret = decode_b64(start, &dec_str);
                if (ret < 0) {
                    // memory error
                    return -1;
                }
            }
        } else if (p != NULL && strncasecmp(p + 1, "Q?", 2) == 0) {
            start = p + 3;
            q = strchr(start, '?');
            if (q != NULL && *(q + 1) == '=') {
                end = q;
                *end = '\0';
                ret = decode_qp(start, &dec_str);
                *end = '?';
                if (ret < 0) {
                    // memory error
                    return -1;
                }
            }
        } else {
            // not mime
            return 0;
        }
    } else {
        // not mime
        return 0;
    }

    // case mime
    n_len = strlen(needle);
    if (strncmp(dec_str, needle, n_len) != 0) {
        // not match
        free(dec_str);
        return 0;
    }

    // case match
    enc_str = encode_b64(dec_str + n_len);
    if (enc_str == NULL) {
        // memory error
        free(dec_str);
        return -1;
    }

    // make new subject
    new_len = (start - subject) + strlen(enc_str) + strlen(end);
    *new_buf = (char *)malloc(new_len + 1);
    if (*new_buf == NULL) {
        // memory error
        free(dec_str);
        free(enc_str);
        return -1;
    }
    memset(*new_buf, 0, new_len + 1);
    strncpy(*new_buf, subject, (start - subject));

    // force qp -> b64
    *(*new_buf + (start - subject - 2)) = 'B';
    strcat(*new_buf, enc_str);
    strcat(*new_buf, end);
    free(dec_str);
    free(enc_str);
    return 1;
}

#endif	// __CUSTOMIZE2018
