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
 * $RCSfile: zipconv.c,v $
 * $Revision: 1.25 $
 * $Date: 2014/05/09 04:43:07 $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <gmime/gmime.h>
#include <dirent.h>
#include <pthread.h>
#include <libdgstr.h>
#include <libdgmail.h>
#include <fcntl.h>

#include "msg_convert.h"
#include "mailzip_config.h"
#include "mailsave.h"
#include "zipconv.h"
#include "log.h"
#include "mailzip_db.h"
#include "maildrop.h"
#include "sendmail.h"
#include "global.h"
#include "mailzip_tmpl.h"
#include "samma_policy.h"
#ifdef __CUSTOMIZE2018
#include <libmilter/mfapi.h>
#include <syslog.h>
#include "mailzip.h"
#define MLFIPRIV(ctx)        ((struct mlfiPriv *) smfi_getpriv(ctx))
#endif	// __CUSTOMIZE2018

pthread_mutex_t gmime_lock = PTHREAD_MUTEX_INITIALIZER;

#ifndef __CUSTOMIZE2018
static void zip_child(char **, char *, char *, char *);
#else   // __CUSTOMIZE2018
static void zip_child(char **, char *, char *, char *, char *);
#endif  // __CUSTOMIZE2018

void
free_name_list(struct name_list *head)
{
    int i;
    for (i = 0; (head + i)->attach_name != NULL; i++) {
        if ((head + i)->attach_name != NULL) {
            free((head + i)->attach_name);
        }
    }
    if (head != NULL) {
        free(head);
    }
}

void
free_rcptinfo(struct rcptinfo *info)
{
    struct rcptinfo *p, *tmpp;

    if (info != NULL) {
        for (p = info; p != NULL; p = tmpp) {
	    tmpp = p->Next;
	    if (p->passwd) {
	        free(p->passwd);
            }
            if (p->keyword) {
	        free(p->keyword);
            }
            if (p->extension) {
	        free(p->extension);
            }
	    if (p->rcptlist != NULL) {
	        free_rcptlist(p->rcptlist);
	    }
	    free(p);
        }
    }
}

void
mailzip_clean(struct mailzip mz)
{
    /* free mailzip structure */
    if (mz.zipdir != NULL) {
        /* remove zip directory */
        remove_file_with_dir_recursive(mz.zipdir);
	free(mz.zipdir);
    }

    /* free attach name list */
    if (mz.namelist != NULL) {
	free_name_list(mz.namelist);
    }

    /* free gmime memory field */
    if (mz.message != NULL) {
        pthread_mutex_lock(&gmime_lock);
        g_object_unref (mz.message);
        pthread_mutex_unlock(&gmime_lock);
    }

    if (mz.date != NULL) {
//        free(mz.date);
        /* Repairing The display of the date 2014/05/08 (Thu) */
        g_free(mz.date);
    }

    if (mz.encfilepath != NULL) {
        free(mz.encfilepath);
    }
    if (mz.attachfilename != NULL) {
        free(mz.attachfilename);
    }

#ifdef __CUSTOMIZE2018
    if (ismode_enc) {
        // release addmsg_tmpl
        addmsg_release(mz.am_tmpl);
    }
#endif	// __CUSTOMIZE2018
}
/*
 * delete_attachmetns_mail
 *
 * Functions:
 *     - Parse mail and get a list of the names of the all files 
 *       attached on the original mail, then delete the files.
 *     - Make a path string of the DeleteListName file.
 *     - Creat and write the DeleteListName file.
 *     - Attach the DeleteListName file to the copied mail.
 *     - Send the copied mail to the rcipients who are the target
 *       of the attachments-deletion.
 *     - Unlink the DeleteListName file.
 *     - Delete recipients of the original mail who are 
 *       the target of the attachments-deletion.
 * Args:
 *     See blow.
 * Returns:
 *     ZIP_CONVERT_ACCEPT
 *     ZIP_CONVERT_FAILED
 *     ZIP_CONVERT_INVALID_FILENAME
 *     ZIP_CONVERT_SUCCESS
 */
extern int
delete_attachments_mail(SMFICTX *ctx, struct mailinfo *minfo, 
                 struct config *cfg, char *from, struct rcptinfo *rdmpasslist)
{
    struct mailzip mz;
    struct rcptinfo *p;
    int i, ret;
    char *rcptaddr;
    struct rcptaddr *rdm_all = NULL;
    struct rcptinfo tmp_rcptinfo;

    memset(&mz, 0, sizeof(struct mailzip));

    /* parse mail */
    ret = parse_mail(minfo, cfg, &mz);
    if ((ret == PM_NO_MULTIPART) || (ret == PM_NO_ATTACHFILE)) {
	mailzip_clean(mz);
	return ZIP_CONVERT_ACCEPT;
    } else if (ret == PM_FAILED) {
	mailzip_clean(mz);
	return ZIP_CONVERT_FAILED;
    } else if (ret == PM_INVALID_FILENAME) {
	mailzip_clean(mz);
	return ZIP_CONVERT_INVALID_FILENAME;
    }

    /* Make a path of the DeleteListName file */
    if (mk_encpath(cfg, &mz) == -1) {
	mailzip_clean(mz);
	return ZIP_CONVERT_FAILED;
    }

    if (rdmpasslist != NULL) {
	/* deletion */
	if (mk_deletelistfile(cfg, &mz) != 0) {
	    mailzip_clean(mz);
	    return ZIP_CONVERT_FAILED;
	}

        if ((cfg->cf_attachdeletelist[0] == 'Y') || 
            (cfg->cf_attachdeletelist[0] == 'y')) {
	    /* add attach file */
	    if (add_attach_file(cfg, &mz, rdmpasslist) != 0) {
	        mailzip_clean(mz);
	        return ZIP_CONVERT_FAILED;
	    }
        }

        /* 送信先リストの作成 */
        for (p = rdmpasslist; p != NULL; p = p->Next) {
            for (i = 0; (p->rcptlist + i)->rcpt_addr; i++) {
                if (push_rcptlist(&rdm_all, (p->rcptlist + i)->rcpt_addr) != 0) {
	            mailzip_clean(mz);
                    free_rcptlist(rdm_all);
	            return ZIP_CONVERT_FAILED;
                }
            }
        }

        tmp_rcptinfo.keyword = OTHERKEYWORD;
        tmp_rcptinfo.keyword_len = strlen(OTHERKEYWORD);
        tmp_rcptinfo.passwd = NULL;
        tmp_rcptinfo.extension = NULL;
        tmp_rcptinfo.rcptlist = rdm_all;
        tmp_rcptinfo.Next = NULL;

    	/* send mail */
        if (sendmail(&mz, cfg, &tmp_rcptinfo, from) != 0) {
	    mailzip_clean(mz);
            free_rcptlist(rdm_all);
	    return ZIP_CONVERT_FAILED;
        }
        /* unlink the temporary file */
        if (unlink(mz.encfilepath) == -1) {
            log(ERR_FILE_REMOVE, "delete_attachments_mail", unlink(mz.encfilepath));
            mailzip_clean(mz);
            free_rcptlist(rdm_all);
            return ZIP_CONVERT_FAILED;
        }

        for (i = 0; (rdm_all + i)->rcpt_addr != NULL; i++) {
            rcptaddr = (rdm_all + i)->rcpt_addr;
            /* delete from envelope to */
            if (smfi_delrcpt(ctx, rcptaddr) == MI_FAILURE) {
                log(ERR_DELETE_ADDRESS, "delete_attachment_mail", rcptaddr);
	        mailzip_clean(mz);
                free_rcptlist(rdm_all);
                return ZIP_CONVERT_FAILED;
            }
        }
    } 

    /* 送信先リストを開放 */
    free_rcptlist(rdm_all);
    mailzip_clean(mz);
    return ZIP_CONVERT_SUCCESS;
}

int
zip_convert_mail(SMFICTX *ctx, struct mailinfo *minfo, struct config *cfg,
                 char *from, struct rcptinfo *passlist, struct rcptinfo *rdmpasslist)
{
    struct mailzip mz;
    struct rcptinfo *p;
    int i, ret, chk_replace, chk_replace_noconv;
    char *temp = NULL, *notify_message, *rcptaddr, *confirmation_message;
    struct noticepass_tmpl *top_noticepass_tmpl;
    char *org_p;
    struct rcptaddr *rdm_noext = NULL;
    struct rcptaddr *rdm_all = NULL;
    struct rcptinfo tmp_rcptinfo;
#ifdef __CUSTOMIZE2018
    // for password log
    struct mlfiPriv *priv;
    char *msgid;
#endif	// __CUSTOMIZE2018
#ifdef __NOTICE_PASSWD
    char *notify_message_to;
#endif // __NOTICE_PASSWD

    memset(&mz, 0, sizeof(struct mailzip));
#ifdef __CUSTOMIZE2018
    // initialize addmsg_tmpl
    mz.am_tmpl = addmsg_init();
    mz.am_priv = MLFIPRIV(ctx);
#endif	// __CUSTOMIZE2018


    /* parse mail */
    ret = parse_mail(minfo, cfg, &mz);
    if ((ret == PM_NO_MULTIPART) || (ret == PM_NO_ATTACHFILE)) {
        mailzip_clean(mz);
        return ZIP_CONVERT_ACCEPT;
    } else if (ret == PM_FAILED) {
        mailzip_clean(mz);
        return ZIP_CONVERT_FAILED;
    } else if (ret == PM_INVALID_FILENAME) {
        mailzip_clean(mz);
        return ZIP_CONVERT_INVALID_FILENAME;
    }

    if (mk_encpath(cfg, &mz) == -1) {
        mailzip_clean(mz);
        return ZIP_CONVERT_FAILED;
    }

    if (passlist != NULL) {
	for (p = passlist; p != NULL; p = p->Next) {
	    /* encryption */
	    if (convert_zip(cfg, &mz, p) != 0) {
            mailzip_clean(mz);
            return ZIP_CONVERT_FAILED;
	    }
	    /* add attach file */
	    if (add_attach_file(cfg, &mz, p) != 0) {
            mailzip_clean(mz);
            return ZIP_CONVERT_FAILED;
	    }
    	    /* send mail */
	    if (sendmail(&mz, cfg, p, from) != 0) {
            mailzip_clean(mz);
            return ZIP_CONVERT_FAILED;
	    }
#ifdef __CUSTOMIZE2018_LOG
            if (ismode_enc) {
                // for password log
                if ((priv = MLFIPRIV(ctx)) == NULL) {
                    msgid = NULL;
                } else {
                    msgid = priv->mlfi_sendercheck_arg.message_id;
                }
                zipconv_log(msgid, from, p->rcptlist, mz.namelist, p->passwd);
            }
#endif	// __CUSTOMIZE2018_LOG
            /* send confirmation mail */
            if ((cfg->cf_fixedpassnotify[0] == 'Y' || cfg->cf_fixedpassnotify[0] == 'y')) {
                org_p = p->passwd;	/* save original password */
                p->passwd = cfg->cf_fixedpassnotifypass;
	        top_noticepass_tmpl = tmpl_init();
		temp = top_noticepass_tmpl->sender_tmpl;


	        chk_replace = tmpl_tag_replace(temp, mz, p, from,
                                               &confirmation_message, 
                                               NOTICEPASS_FROM, from);
                switch(chk_replace) {
                case ERROR:
                    p->passwd = org_p;	/* restore original password */
                    tmpl_release(top_noticepass_tmpl);
                    mailzip_clean(mz);
                    return ZIP_CONVERT_FAILED;
                case CONVERT_ERROR:
                    // replace not converted string
                    chk_replace_noconv = tmpl_tag_replace_noconv(mz, p, from,
                                                                 &confirmation_message,
                                                                 cfg->cf_errmsgtemplatepath, NOTICEPASS_FROM);

                    if (chk_replace_noconv == ERROR) {
                        tmpl_release(top_noticepass_tmpl);
                        mailzip_clean(mz);
                        return ZIP_CONVERT_FAILED;
                    }
	        }
                p->passwd = org_p;	/* restore original password */
	        tmpl_release(top_noticepass_tmpl);

                // set header field "References"
                if (strcmp(cfg->cf_references, "yes") == 0) {
                    ret = set_references(minfo->ii_mbuf, &confirmation_message);
                    if (ret == ERROR) {
                        free(confirmation_message);
                        mailzip_clean(mz);
                        return ZIP_CONVERT_FAILED;
                    }
                }

	        if (passwd_sendmail(cfg, from, confirmation_message, from) != 0) {
	            free(confirmation_message);
	            mailzip_clean(mz);
	            return ZIP_CONVERT_FAILED;
	        }
	        free(confirmation_message);
            }

	    if (unlink(mz.encfilepath) == -1) {
		log(ERR_FILE_REMOVE, "convert_zip", unlink(mz.encfilepath));
		mailzip_clean(mz);
		return ZIP_CONVERT_FAILED;
	    }

            for (i = 0; (p->rcptlist + i)->rcpt_addr != NULL; i++) {
                rcptaddr = (p->rcptlist + i)->rcpt_addr;
                /* delete from envelope to */
                if (smfi_delrcpt(ctx, rcptaddr) == MI_FAILURE) {
                    log(ERR_DELETE_ADDRESS, "zip_convert_mail", rcptaddr);
		    mailzip_clean(mz);
                    return ZIP_CONVERT_FAILED;
                }
            }
	}
    }

    if (rdmpasslist != NULL) {
        /* ランダムパスワードで暗号化するメールの送信 */
        for (p = rdmpasslist; p != NULL; p = p->Next) {
            if (p->extension && p->extension[0] != '\0') {	
                /* 拡張子が指定されている場合 */
	        /* encryption */
	        if (convert_zip(cfg, &mz, p) != 0) {
	            mailzip_clean(mz);
                    free_rcptlist(rdm_noext);
                    free_rcptlist(rdm_all);
	            return ZIP_CONVERT_FAILED;
	        }

                /* add attach file */
	        if (add_attach_file(cfg, &mz, p) != 0) {
	            mailzip_clean(mz);
                    free_rcptlist(rdm_noext);
                    free_rcptlist(rdm_all);
	            return ZIP_CONVERT_FAILED;
	        }

    	        /* send mail */
	        if (sendmail(&mz, cfg, p, from) != 0) {
	            mailzip_clean(mz);
                    free_rcptlist(rdm_noext);
                    free_rcptlist(rdm_all);
	            return ZIP_CONVERT_FAILED;
	        }
#ifdef __CUSTOMIZE2018_LOG
                if (ismode_enc) {
                    // for password log
                    if ((priv = MLFIPRIV(ctx)) == NULL) {
                        msgid = NULL;
                    } else {
                        msgid = priv->mlfi_sendercheck_arg.message_id;
                    }
                    zipconv_log(msgid, from, p->rcptlist, mz.namelist, p->passwd);
                }
#endif	// __CUSTOMIZE2018_LOG
            } else {
                /* 拡張子が指定されていない場合 */
                /* まとめて送信するためのリストを作成 */
                for (i = 0; (p->rcptlist + i)->rcpt_addr; i++) {
                   if (push_rcptlist(&rdm_noext, (p->rcptlist + i)->rcpt_addr) != 0) {
		        mailzip_clean(mz);
                        free_rcptlist(rdm_noext);
                        free_rcptlist(rdm_all);
                       return ZIP_CONVERT_FAILED;
                   }
                }
            }

            /* パスワード通知を送信するためのリストを作成 */
            for (i = 0; (p->rcptlist + i)->rcpt_addr; i++) {
                if (push_rcptlist(&rdm_all, (p->rcptlist + i)->rcpt_addr) != 0) {
		    mailzip_clean(mz);
                    free_rcptlist(rdm_noext);
                    free_rcptlist(rdm_all);
                    return ZIP_CONVERT_FAILED;
                }
            }
        }

        /* 拡張子が指定されていない宛先にメール送信 */
        if (rdm_noext) {
            tmp_rcptinfo.keyword = OTHERKEYWORD;
            tmp_rcptinfo.keyword_len = strlen(OTHERKEYWORD);
            tmp_rcptinfo.passwd = rdmpasslist->passwd;
            tmp_rcptinfo.extension = NULL;
            tmp_rcptinfo.command = rdmpasslist->command;
            tmp_rcptinfo.rcptlist = rdm_noext;
            tmp_rcptinfo.Next = NULL;

            /* encryption */
            if (convert_zip(cfg, &mz, &tmp_rcptinfo) != 0) {
                mailzip_clean(mz);
                free_rcptlist(rdm_noext);
                free_rcptlist(rdm_all);
                return ZIP_CONVERT_FAILED;
            }

            /* add attach file */
            if (add_attach_file(cfg, &mz, &tmp_rcptinfo) != 0) {
                mailzip_clean(mz);
                free_rcptlist(rdm_noext);
                free_rcptlist(rdm_all);
                return ZIP_CONVERT_FAILED;
            }

            /* send mail */
            if (sendmail(&mz, cfg, &tmp_rcptinfo, from) != 0) {
                mailzip_clean(mz);
                free_rcptlist(rdm_noext);
                free_rcptlist(rdm_all);
                return ZIP_CONVERT_FAILED;
            }
#ifdef __CUSTOMIZE2018_LOG
            if (ismode_enc) {
                // for password log
                if ((priv = MLFIPRIV(ctx)) == NULL) {
                    msgid = NULL;
                } else {
                    msgid = priv->mlfi_sendercheck_arg.message_id;
                }
                zipconv_log(msgid, from, tmp_rcptinfo.rcptlist, mz.namelist, tmp_rcptinfo.passwd);
            }
#endif	// __CUSTOMIZE2018_LOG
            free_rcptlist(rdm_noext);
        }

        /* パスワード通知の受信者リスト用 rcptinfo 作成 */
        tmp_rcptinfo.keyword = OTHERKEYWORD;
        tmp_rcptinfo.keyword_len = strlen(OTHERKEYWORD);
        tmp_rcptinfo.passwd = rdmpasslist->passwd;
        tmp_rcptinfo.extension = NULL;
        tmp_rcptinfo.rcptlist = rdm_all;
        tmp_rcptinfo.Next = NULL;

        /* パスワード通知メールの送信 */
	top_noticepass_tmpl = tmpl_init();
	temp = top_noticepass_tmpl->sender_tmpl;

        chk_replace = tmpl_tag_replace(temp, mz, &tmp_rcptinfo, from, &notify_message, NOTICEPASS_FROM, from);

        switch(chk_replace) {
            case ERROR:
                tmpl_release(top_noticepass_tmpl);
                mailzip_clean(mz);
                free_rcptlist(rdm_all);
                return ZIP_CONVERT_FAILED;
            case CONVERT_ERROR:
                // replace before convert string
                chk_replace_noconv = tmpl_tag_replace_noconv(mz, &tmp_rcptinfo, from,
                                                             &notify_message, cfg->cf_errmsgtemplatepath,
                                                             NOTICEPASS_FROM);

                if (chk_replace_noconv == ERROR) {
                    tmpl_release(top_noticepass_tmpl);
                    mailzip_clean(mz);
                    free_rcptlist(rdm_all);
                    return ZIP_CONVERT_FAILED;
                }
        }

	tmpl_release(top_noticepass_tmpl);

        // set header field "references"
        if (strcmp(cfg->cf_references, "yes") == 0) {
            ret = set_references(minfo->ii_mbuf, &notify_message);
            if (ret == ERROR) {
                free(notify_message);
                mailzip_clean(mz);
                free_rcptlist(rdm_all);
                return ZIP_CONVERT_FAILED;
            }
        }

        /* if passwordnotice item set is 0 or 2 
         * then send passwordnotice mail to FROM */
#ifdef __NOTICE_PASSWD
        if ((cfg->cf_passwordnotice == 0) || (cfg->cf_passwordnotice == 2)) {
	    if (passwd_sendmail(cfg, from, notify_message, from) != 0) {
	        free(notify_message);
	        mailzip_clean(mz);
                free_rcptlist(rdm_all);
	        return ZIP_CONVERT_FAILED;
	    }
        }
#else  // __NOTICE_PASSWD
        if (passwd_sendmail(cfg, from, notify_message, from) != 0) {
            free(notify_message);
            mailzip_clean(mz);
            free_rcptlist(rdm_all);
            return ZIP_CONVERT_FAILED;
        }
#endif
	free(notify_message);

        for (i = 0; (rdm_all + i)->rcpt_addr; i++) {
            rcptaddr = (rdm_all + i)->rcpt_addr;
            /* delete from envelope to */
            if (smfi_delrcpt(ctx, rcptaddr) == MI_FAILURE) {
                log(ERR_DELETE_ADDRESS, "zip_convert_mail", rcptaddr);
	        mailzip_clean(mz);
                free_rcptlist(rdm_all);
                return ZIP_CONVERT_FAILED;
            }
        }
        free_rcptlist(rdm_all);

#ifdef __NOTICE_PASSWD
        for (p = rdmpasslist; p != NULL; p = p->Next) {
            /* loop all to then send passwordnotice */
            for (i = 0; (p->rcptlist + i)->rcpt_addr != NULL; i++) {
                rcptaddr = (p->rcptlist + i)->rcpt_addr;

                /* if passwordnotice item set is 1 or 2 then send passwordnotice mail to TO */
                if ((cfg->cf_passwordnotice == 1) || (cfg->cf_passwordnotice == 2)) {
                    /* make notify message */
                    top_noticepass_tmpl = tmpl_init();
		    temp = top_noticepass_tmpl->rcpt_tmpl;
                    chk_replace = tmpl_tag_replace(temp, mz, rdmpasslist, rcptaddr, &notify_message_to, NOTICEPASS_TO, from);

                    switch(chk_replace) {
                    case ERROR:
                        tmpl_release(top_noticepass_tmpl);
                        mailzip_clean(mz);
                        return ZIP_CONVERT_FAILED;
                    case CONVERT_ERROR:
                        // replace before convert string
                        chk_replace_noconv = tmpl_tag_replace_noconv(mz, rdmpasslist, rcptaddr,
                                                                     &notify_message_to, cfg->cf_errmsgtemplatepath,
                                                                     NOTICEPASS_TO);

                        if (chk_replace_noconv == ERROR) {
                            tmpl_release(top_noticepass_tmpl);
                            mailzip_clean(mz);
                            return ZIP_CONVERT_FAILED;
                        }
                    }
                    tmpl_release(top_noticepass_tmpl);

                    /* send notify_password to TO */
                    if (passwd_sendmail(cfg, rcptaddr, notify_message_to, from) != 0) {
                        free(notify_message_to);
                        mailzip_clean(mz);
                        return ZIP_CONVERT_FAILED;
                    }

                    /* free notify_message_to */
                    free(notify_message_to);
                }
            }
        }
#endif //__NOTICE_PASS
    } 

#ifdef	DEBUG
    if (passlist != NULL) {
	log("------------- passlist list start -------------");
        for (p = passlist; p != NULL; p = p->Next) {
	    log("keyword: %s", p->keyword);
	    log("keyword_len: %d", p->keyword_len);
	    log("passwd: %s", p->passwd);
	    for (i = 0; (p->rcptlist + i)->rcpt_addr != NULL; i++) {
	        log("rcptaddr: %s", (p->rcptlist + i)->rcpt_addr);
	    }
	    log("encfilepath: %s", mz.encfilepath);
        }
	log("-------------- passlist list end --------------");
    }
    if (rdmpasslist != NULL) {
	log("------------- rdmpasslist list start -------------");
        for (p = rdmpasslist; p != NULL; p = p->Next) {
	    log("keyword: %s", p->keyword);
	    log("keyword_len: %d", p->keyword_len);
	    log("passwd: %s", p->passwd);
	    for (i = 0; (p->rcptlist + i)->rcpt_addr != NULL; i++) {
	        log("rcptaddr: %s", (p->rcptlist + i)->rcpt_addr);
	    }
	    log("encfilepath: %s", mz.encfilepath);
        }
	log("-------------- rdmpasslist list end --------------");
    }
#endif /* DEBUG */

    mailzip_clean(mz);
    return ZIP_CONVERT_SUCCESS;
}

#define CONTENTTYPE_HEADER	"Content-Type"
#define CONTENTTYPE_ZIP		"application/zip"
#define CONTENTDISPOSITION	"attachment"
int
add_attach_file(struct config *cfg, struct mailzip *mz, struct rcptinfo *rcpt)
{
    GMimeObject *object, *att;
    GMimePart *part;
    GMimeDataWrapper *wrapper;
    GMimeStream *r_stream, *f_stream;
    GMimeFilter *filter;
    FILE *fp;
    int index, i, ret;
    const char *filename;
    char newfilename[FILE_NAME_MAX + 1];
    char *attach_ctype = NULL;
    char *mime_type = NULL;

    pthread_mutex_lock(&gmime_lock);
    object = g_mime_message_get_mime_part(mz->message);

    if (GMIME_IS_MULTIPART (object)) {

#ifndef GMIME26
        index = g_mime_multipart_get_number((GMimeMultipart *)object);
#else
        index = g_mime_multipart_get_count((GMimeMultipart *)object);
#endif

        for (i = index - 1; i > 0; i--) {
            att = g_mime_multipart_get_part((GMimeMultipart *)object, i);

	    if (GMIME_IS_MULTIPART (att)) {
#ifndef GMIME24
                g_object_unref (att);
#endif
                att = NULL;
                continue;
	    }

            filename = g_mime_part_get_filename((GMimePart *)att);

            if (filename == NULL) {
#ifndef GMIME24
                g_object_unref (att);
#endif
                att = NULL;
                continue;
            }

#ifndef GMIME26
            g_mime_multipart_remove_part((GMimeMultipart *)object, att);
#else
            g_mime_multipart_remove((GMimeMultipart *)object, att);
#endif

#ifndef GMIME24
            g_object_unref (att);
#endif
        }
    }

    fp = fopen(mz->encfilepath, "r");

    if (fp == NULL) {
	log(ERR_FILE_OPEN, "add_attach_file", mz->encfilepath);
#ifndef GMIME24
        g_object_unref (object);
#endif
        pthread_mutex_unlock(&gmime_lock);
	return -1;
    }

    /* create part object */
    part = g_mime_part_new();

    /* set part object */
    /* ここで拡張子DBに設定されている場合は */
    if (rcpt->extension && rcpt->extension[0] != '\0') {

        /* MimeTypeFileが設定されているか */
        if (cfg->cf_mimetypes) {

            /* MIMETYPEを調べる */
            attach_ctype = get_mimetype(cfg, rcpt->extension);
            if (attach_ctype == NULL) {
                attach_ctype = "application/octet-stream";
            }
        } else {
            attach_ctype = cfg->cf_zipattachmentcontenttype;
        }
    } else {
        attach_ctype = cfg->cf_zipattachmentcontenttype;
    }
#ifndef GMIME26
    g_mime_part_set_content_header(part, CONTENTTYPE_HEADER, attach_ctype);
#else
    g_mime_object_set_header((GMimeObject *)part, CONTENTTYPE_HEADER, attach_ctype);
#endif

    /* FREEする */
    if (mime_type) {
        free(mime_type);
    }

#ifndef GMIME26
    g_mime_part_set_encoding(part, GMIME_PART_ENCODING_BASE64);
    g_mime_part_set_content_disposition(part, CONTENTDISPOSITION);
#else
    g_mime_part_set_content_encoding(part, GMIME_CONTENT_ENCODING_BASE64);
    g_mime_object_set_disposition((GMimeObject *)part, CONTENTDISPOSITION);
#endif

    if (cfg->cf_extensiondb && cfg->cf_extensiondb[0] != '\0') {
        if (rcpt->extension != NULL) {

            replace_extension(newfilename, mz->attachfilename, rcpt->extension);
            g_mime_part_set_filename(part, newfilename);
        } else {
            g_mime_part_set_filename(part, mz->attachfilename);
        }
    } else {
        g_mime_part_set_filename(part, mz->attachfilename);
    }

    // もしここでメモリリークが見つかった場合、修正例
    // (文字コードのテストをしっかりすべき）
    //g_mime_object_set_content_type_parameter((GMimeObject *)part, "filename", mz->attachfilename);
    //g_mime_object_set_content_disposition_parameter((GMimeObject *)part, "filename", mz->attachfilename);

    /* open stream */
    r_stream = g_mime_stream_file_new(fp); 

    /* create filter object */
#ifndef GMIME26
    filter = g_mime_filter_basic_new_type(GMIME_FILTER_BASIC_BASE64_ENC);
#else
    filter = g_mime_filter_basic_new(GMIME_CONTENT_ENCODING_BASE64, TRUE);
#endif

    /* set filter */
#ifndef GMIME26
    f_stream = g_mime_stream_filter_new_with_stream(r_stream);
#else
    f_stream = g_mime_stream_filter_new(r_stream);
#endif

    g_object_unref (r_stream);
    g_mime_stream_filter_add((GMimeStreamFilter *)f_stream, filter);

    /* create wrapper object */
#ifndef GMIME26
    wrapper = g_mime_data_wrapper_new_with_stream(f_stream, GMIME_PART_ENCODING_BASE64);
#else
    wrapper = g_mime_data_wrapper_new_with_stream(f_stream, GMIME_CONTENT_ENCODING_BASE64);
#endif

    /* set part */
    g_mime_part_set_content_object(part, wrapper);

#ifndef GMIME26
    g_mime_multipart_add_part((GMimeMultipart *)object, (GMimeObject *)part);
#else
    g_mime_multipart_add((GMimeMultipart *)object, (GMimeObject *)part);
#endif

    g_object_unref (filter);
    g_object_unref (part);
    g_object_unref (wrapper);
    g_object_unref (f_stream);

#ifndef GMIME24 
    g_object_unref (object);
#endif

    pthread_mutex_unlock(&gmime_lock);
    return 0;
}

/*
 * mk_new_filename
 *
 * Args:
 *	char      *newfilename	new filename
 *	constchar *filename	attach file name
 *	int	   count	same name count 
 *
 * Returns:
 *	NEW_SUCCESS		Success
 */
int
mk_new_filename(char *newfilename, const char *filename, char *dir, int count)
{
    char *ext, *p;
    char data[PATH_MAX + 1];
    char fullpath[PATH_MAX + 1];
    char tmpfilename[FILE_NAME_MAX + 1];
    int name_len = 0, ext_len = 0;
    int len, tmp_num = 0;
    int filename_len = strlen(filename);

    len = filename_len + FILE_RENAME_LEN;
    memset(tmpfilename, 0, sizeof(tmpfilename));
    
    if (filename_len > FILE_NAME_MAX) {
        ext = strrchr(filename, DOT);
        if (ext == NULL) {
	    strncpy(tmpfilename, filename, FILE_NAME_MAX);
        } else {
            tmp_num = ext - filename + DOTLEN + EXTMAXLEN;
            if (tmp_num <= FILE_NAME_MAX) {
	        strncpy(tmpfilename, filename, FILE_NAME_MAX);
            } else {
		ext_len = strlen(ext + 1);
		if (ext_len > EXTMAXLEN) {
		    *(ext + EXTMAXLEN + 1) = '\0';
		    ext_len = EXTMAXLEN;
		}
                name_len = FILE_NAME_MAX - DOTLEN - ext_len;
                p = strncpy(data, filename, name_len);
                *(p + name_len) = '\0';

                /* create new filename */
                snprintf(tmpfilename, FILE_NAME_MAX + 1, "%s%s", data, ext);
            }
        }
    } else {
	strncpy(tmpfilename, filename, FILE_NAME_MAX);
    }

    if (count != 0) {
	/* extension check */
	ext = strrchr(tmpfilename, DOT);
	if (ext == NULL) {
            snprintf(newfilename, len, FILE_RENAME_NOEXT, tmpfilename, count);
        } else {

            name_len = ext - tmpfilename;

            p = strncpy(data, tmpfilename, name_len);
            *(p + name_len) = '\0';

            /* create new filename */
            snprintf(newfilename, len, FILE_RENAME, data, count, ext);
        }
    } else {
	strncpy(newfilename, tmpfilename, len);
    }

    /* create full pathname */
    snprintf(fullpath, PATH_MAX, FILE_PATH, dir, newfilename);

    if (access(fullpath, F_OK) == 0) {
	mk_new_filename(newfilename, tmpfilename, dir, count + 1);
    }

    return(NEW_SUCCESS);
}

/*
 * remove_file_with_dir
 * 
 * Args:
 * 	char *target		remove target file/directory name
 *
 * Returns:
 * 	RM_SUCCESS		Success
 * 	RM_FAILED		Failed
 */
int
remove_file_with_dir_recursive(char *target)
{
    DIR           *dp;
    struct stat    buf;
    struct dirent *p;
    char new_target[PATH_MAX + 1];

    if (stat(target, &buf) != 0) {

	/* stat failed */
        if (errno != ENOENT) {
            log("%s: Stat failed.(%s)","remove_file_with_dir_recursive", target);
            return(RM_FAILED);
        }
        return(RM_SUCCESS);
    }
    if ((buf.st_mode & S_IFMT) != S_IFDIR) {

	/* remove file */
        if (unlink(target) != 0) {
            if (errno != ENOENT) {
		log(ERR_FILE_REMOVE, "remove_file_with_dir_recursive", target);
                return(RM_FAILED);
            }
        }
        return(RM_SUCCESS);

    } else {

        dp = opendir(target);
        if (dp == NULL) {
            return(RM_FAILED);
        }
        while ((p = readdir(dp))) {

            if ((strcmp(p->d_name, ".") == 0) ||
                (strcmp(p->d_name, "..") == 0)) {
                continue;
            }

	    snprintf(new_target, PATH_MAX + 1, FILE_PATH, target, p->d_name);

            if (remove_file_with_dir_recursive(new_target) != RM_SUCCESS) {
		closedir(dp);
                return(RM_FAILED);
            }
        }
	closedir(dp);

	/* remove directory */
        if (rmdir(target) != 0) {
            if (errno != ENOENT) {
		log(ERR_DIRECTORY_REMOVE, "remove_file_with_dir_recursive", target);
                return(RM_FAILED);
            }
        }
    }

    return(RM_SUCCESS);
}

/*
 * push_attnamelist
 *
 * Args:
 *	struct name_list **head		attach namelist structure
 *	char		  *str		attach name
 *
 * Returns:
 *	0			Success
 *	-1			Failed
 */
int
push_attnamelist(struct name_list **head, char *str)
{
    int i;
    struct name_list *tmphead;

    /* check current size */
    if (*head == NULL) {
        i = 0;
    } else {
        for (i = 0; (*head + i)->attach_name != NULL; i++);
    }

    /* (re)allocate memory */
    tmphead = realloc(*head, sizeof(struct name_list) * (i + 2));
    if (tmphead == NULL) {
        log(ERR_MEMORY_ALLOCATE, "push_list", "head", strerror(errno));
        return -1;
    }
    *head = tmphead;

    /* copy string */
    (*head + i)->attach_name = strdup(str);
    if ((*head + i)->attach_name == NULL) {
        log(ERR_MEMORY_ALLOCATE, "push_list",
            "(*head + i)->attach_name", strerror(errno));
        return -1;
    }
    (*head + i)->attach_name_len = strlen(str);

    /* end with NULL */
    (*head + i + 1)->attach_name = NULL;

    return 0;
}


#define TEMPDIRNAME	"tmp"
#define TEMPDIRLEN	3
/*
 * parse_mail
 *
 * Args:
 *	struct mailinfo *minfo	mailinfo structure
 *	struct config  *cfg	config structure
 *	struct mailzip *mz	mailzip structure
 *
 * Returns:
 *	PM_SUCCESS		Success
 *	PM_NO_MULTIPART		Multi-part Nothing
 *	PM_FAILED		Failed
 */
int
parse_mail(struct mailinfo *minfo, struct config *cfg, struct mailzip *mz)
{
    GMimeStream *r_stream;
    GMimeParser *parser;
    GMimeObject *object;
    const GMimeContentType *ct_object = NULL;
    FILE *rfp;
    char *tmpdir, *tmpstr;
    int rfd, len;
    int ret;
    char *cfg_encdir = NULL;

    cfg_encdir = ismode_delete ? cfg->cf_tmpdir : cfg->cf_encryptiontmpdir;
    pthread_mutex_lock(&gmime_lock);

    /* create object */
    if(minfo->ii_status & MS_STATUS_FILE) {
	DEBUGLOG("Create message object from file");
        /* stream */
	if ((rfd = dup(minfo->ii_fd)) < 0) {
	    log(ERR_FILE_OPEN, "parse_mail", minfo->ii_fd);
	    pthread_mutex_unlock(&gmime_lock);
	    return(PM_FAILED);
	}
        rfp = fdopen(rfd, "r");
        if (rfp == NULL) {
	    log(ERR_FILE_OPEN, "parse_mail", minfo->ii_fd);
	    pthread_mutex_unlock(&gmime_lock);
	    return(PM_FAILED);
        }
        fseek(rfp, 0L, SEEK_SET);

        r_stream = g_mime_stream_file_new (rfp);
    } else {
	DEBUGLOG("Create message object from memory");
	r_stream = g_mime_stream_mem_new_with_buffer (minfo->ii_mbuf, minfo->ii_len);
    }

    /* parser */
    parser = g_mime_parser_new_with_stream(r_stream);
    g_object_unref (r_stream);

    /* gmime object */
    mz->message = g_mime_parser_construct_message(parser);
    if (mz->message == NULL) {
	log(ERR_GMIME, "parse_mail", "g_mime_parser_construct_message");
        g_object_unref (parser);
	pthread_mutex_unlock(&gmime_lock);
	return(PM_FAILED);
    }
    g_object_unref (parser);

    /* Add header */
#ifndef GMIME26
    g_mime_message_add_header(mz->message, XHEADERNAME, XHEADERVALUE);
#else
#if 0   /* [2016.09.27] Add a header when sending mail. */
    g_mime_object_append_header((GMimeObject *)mz->message, XHEADERNAME, XHEADERVALUE);
#endif
#endif

    /* Get header subject */
    mz->subject = g_mime_message_get_subject(mz->message);

    /* Get header date */
    if (cfg->cf_settimezone == 0) {
#ifndef GMIME26
        mz->date = g_mime_message_get_date_string(mz->message);
#else
        mz->date = g_mime_message_get_date_as_string(mz->message);
#endif
    } else {
        /* Repairing The display of the date 2014/05/08 (Thu) */
        mz->date =  g_mime_utils_header_format_date (mz->message->date,
                                                     cfg->cf_settimezone);
    }

    /* gmime part object */
    object = g_mime_message_get_mime_part(mz->message);

    if (!GMIME_IS_MULTIPART (object)) {
#ifndef GMIME24
        g_object_unref (object);
#endif
	pthread_mutex_unlock(&gmime_lock);
	return(PM_NO_MULTIPART);
    }

    ct_object = g_mime_object_get_content_type(object);

    /* default policy set */
    if (ismode_delete || (cfg->cf_alternativepartencrypt[0] == 'N') || (cfg->cf_alternativepartencrypt[0] == 'n')) {
        if ((strncmp(ct_object->type, CONTENT_T_MULTIPART, LEN_CONTENT_T_MULTIPART) == 0) && 
            ((strncmp(ct_object->subtype, CONTENT_SUBT_RELATED, LEN_CONTENT_SUBT_RELATED) == 0) ||
             (strncmp(ct_object->subtype, CONTENT_SUBT_ALTERNATIVE, LEN_CONTENT_SUBT_ALTERNATIVE) == 0))) {
#ifndef GMIME24
            g_object_unref (object);
#endif
    	    pthread_mutex_unlock(&gmime_lock);
	    return(PM_NO_ATTACHFILE);
        }
    }

    /* make zip directory */
    len = strlen(cfg_encdir) + strlen(TMPDIR_TMPL) + 2;
    tmpstr = (char *)malloc(len);

    if (tmpstr == NULL) {
	log(ERR_MEMORY_ALLOCATE, "parse_mail", "tmpstr", strerror(errno));
#ifndef GMIME24
        g_object_unref (object);
#endif
	pthread_mutex_unlock(&gmime_lock);
	return(PM_FAILED);
    }
    snprintf(tmpstr, len, FILE_PATH, cfg_encdir, TMPDIR_TMPL);

    tmpdir = mkdtemp(tmpstr);
    if (tmpdir == NULL) {
        log(ERR_DIRECTORY_MAKE, "parse_mail", tmpstr, strerror(errno));
#ifndef GMIME24
        g_object_unref (object);
#endif
	free(tmpstr);
	pthread_mutex_unlock(&gmime_lock);
	return(PM_FAILED);
    }
    mz->zipdir = strdup(tmpdir);
    if (mz->zipdir == NULL) {
	log(ERR_MEMORY_ALLOCATE, "parse_mail", "mz->zipdir", strerror(errno));
#ifndef GMIME24
        g_object_unref (object);
#endif
	free(tmpstr);
	pthread_mutex_unlock(&gmime_lock);
	return -1;
    }
    free(tmpstr);

    if ((ret = drop_file(object, cfg, mz)) != 0) {
#ifndef GMIME24
        g_object_unref (object);
#endif
	pthread_mutex_unlock(&gmime_lock);
        if (ret == -2) {
/* if cannot convert character code then set filename is unknown file */
            /* could not detect/convert attached filename's encoding
             * returning specific value */
            return(PM_INVALID_FILENAME);
        }
	return -1;
    }

#ifndef GMIME24
    g_object_unref (object);
#endif

    /* Not attach file */
    if (mz->namelist == NULL) {
	pthread_mutex_unlock(&gmime_lock);
        return(PM_NO_ATTACHFILE);
    }

    pthread_mutex_unlock(&gmime_lock);
    return(PM_SUCCESS);
}

int
drop_file(GMimeObject *object, struct config *cfg, struct mailzip *mz)
{
    int ret, i, index, ret_valid;
    GMimeObject *att;
    GMimeStream *w_stream;
    GMimeMessage *message;
    GMimeDataWrapper *wrapper;
    const char *filename;
    char *p_filename, *tmpname;
    char *tmpfilename;
    char *validatename = NULL;
    char lastFromChar[MAX_STRCODE_LEN]; // expects strings such as "ISO-2022-JP", "EUC-JP", "SJIS", "UTF-8"
    char *b64_tmpname = NULL;
    char *b64_tmpfilename = NULL;
    char *b64_validatename = NULL;
    char newfilename[PATH_MAX + 1];
    char tmppath[PATH_MAX + 1];
    int count = 0;
    FILE *wfp;
#ifdef __CUSTOMIZE2018
    GMimeContentType *ctype;
#endif	// __CUSTOMIZE2018

    /* get attach file number */
#ifndef GMIME26
    index = g_mime_multipart_get_number((GMimeMultipart *)object);
#else
    index = g_mime_multipart_get_count((GMimeMultipart *)object);
#endif
    for (i = index - 1; i >= 0; i--) {
	att = g_mime_multipart_get_part((GMimeMultipart *)object, i);

	if (GMIME_IS_MESSAGE_PART(att)) {
	    filename = MESSAGE_FILENAME;
	} else if (GMIME_IS_MULTIPART (att)) {
#ifdef __CUSTOMIZE2018
            if (ismode_enc) {
                // store position and depth
                mz->md_depth ++;
                mz->md_pos = i;
            }
#endif	// __CUSTOMIZE2018
	    ret = drop_file(att, cfg, mz);
#ifdef __CUSTOMIZE2018
            if (ismode_enc) {
                // restore depth
                mz->md_depth --;
            }
#endif	// __CUSTOMIZE2018

#ifndef GMIME24
	    g_object_unref (att);
#endif

	    if (ret < 0) {
		return -1;
	    } 
	    continue;

	} else {
DEBUGLOG("getting filename...");

	    /* get filename */
	    filename = g_mime_part_get_filename((GMimePart *)att);
#ifdef __CUSTOMIZE2018
            if (ismode_enc) {
                // Chcek if this part is to be added the message
                if (*(cfg->cf_useaddmessageheader) == 'Y'
                    || *(cfg->cf_useaddmessageheader) == 'y') {
                    ctype = g_mime_object_get_content_type(att);
                    if (ctype->type != NULL
                            && strcasecmp(ctype->type, "text") == 0) {
                        // case text part
                        if ((mz->md_depth == 0 && i == 0)
                             || (mz->md_depth == 1 && mz->md_pos == 0)) {
                            // case first postion
                            ret = replace_mime_part(att, object, i, mz, ctype);
                            // ZZ-ERROR SHORI
                            if (ret != 0) {
                                return -1;
                            }
                        }
                    }

                }
            }
// g_mime_object_append_header (att, "hoge", "hage");
#endif	// __CUSTOMIZE2018
	    if (filename == NULL) {
DEBUGLOG("Failed to get filename when index = %d", i);
#ifndef GMIME24 
	        g_object_unref (att);
#endif
	        continue;
	    }
	}

	/* replace slash charactor */
	for (p_filename = (char *)filename; *p_filename != '\0'; p_filename++) {
	    if (*p_filename == SLASH) {
		*p_filename = SLASH_REPLACE_CHAR;
	    }
	}

	tmpname = strdup(filename);

	if (tmpname == NULL) {
	    log(ERR_MEMORY_ALLOCATE, "drop_file", "tmpname", strerror(errno));
#ifndef GMIME24
	    g_object_unref (att);
#endif
	    return -1;
        }

        /* convert str code */
        ret_valid = dg_str2code_replace_validate(tmpname, &tmpfilename, STR_UTF8,
                        cfg->cf_strcode, &validatename, lastFromChar, MAX_STRCODE_LEN);
        if (ret_valid != 0) {
            /* When dg_str2code_replace_validate returns value 2,
             * logging failure of reversal conversion validation.
             */
            if (ret_valid == 2) {
                b64_tmpname = encode_b64(tmpname);
                b64_tmpfilename = encode_b64(tmpfilename);
                b64_validatename = encode_b64(validatename);
                log(ERR_CONVERT_VALIDATION, b64_tmpname, 
                    b64_tmpfilename, b64_validatename,
                    lastFromChar, cfg->cf_strcode);
                free(b64_tmpname);
                free(b64_tmpfilename);
                free(b64_validatename);
            }

            /* START ADD 20150323 */
            /* If the conversion of the str2code is failed, the name of 
             * the attaching file is set by cf_attachmentfilealias.
             */
            tmpfilename = strdup(cfg->cf_attachmentfilealias);
            if (tmpfilename == NULL) {
	        log(ERR_MEMORY_ALLOCATE, "drop_file", "tmpfilename", strerror(errno));

#ifndef GMIME24
	        g_object_unref (att);
#endif

	        return -1;
            }

	    log(ERR_CHARCODE_CONVERT, "drop_file");
            /* delete old code */
            //g_object_unref (att);
	    //free(tmpname);
            /* could not detect/convert encoding
             * returning specific value */
	    //return -2;

            /* END ADD 20150323 */
	}
#ifdef DEBUG
        if (ret_valid == 0) {
            b64_tmpname = encode_b64(tmpname);
            b64_tmpfilename = encode_b64(tmpfilename);
            b64_validatename = encode_b64(validatename);
            DEBUGLOG(DEBUG_CONVERT_VALIDATION, b64_tmpname, 
                b64_tmpfilename, b64_validatename,
                lastFromChar, cfg->cf_strcode);
            free(b64_tmpname);
            free(b64_tmpfilename);
            free(b64_validatename);
	}
#endif
	free(tmpname);
        if (validatename != NULL) {
            free(validatename);
            validatename = NULL;
        }

        if (ismode_delete) {
            strcpy(newfilename, tmpfilename);
        } else {
            mk_new_filename(newfilename, tmpfilename, mz->zipdir, count);
        } 

        if (push_attnamelist(&(mz->namelist), newfilename) != 0) {
#ifndef GMIME24
            g_object_unref (att);
#endif
            free(tmpfilename);
            return -1;
        }

        free(tmpfilename);

        snprintf(tmppath, PATH_MAX, FILE_PATH, mz->zipdir, newfilename);
        DEBUGLOG("attach_file_name :%s\n", tmppath);

        if (GMIME_IS_MESSAGE_PART(att)) {
            wfp = fopen(tmppath, "w");
            if (wfp == NULL) {
                log(ERR_FILE_OPEN, "drop_file", tmppath);
#ifndef GMIME24
                g_object_unref (att);
#endif
                return -1;
            }
            w_stream = g_mime_stream_file_new (wfp);

            message = g_mime_message_part_get_message((GMimeMessagePart *)att);

#ifndef GMIME26
            ret = g_mime_message_write_to_stream (message, w_stream);
#else
            ret = g_mime_object_write_to_stream ((GMimeObject *)message, w_stream);
#endif

#ifndef GMIME24
            g_object_unref (message);
#endif
            g_object_unref (w_stream);

        } else if (!ismode_delete) {
            wfp = fopen(tmppath, "w");
            if (wfp == NULL) {
                log(ERR_FILE_OPEN, "drop_file", tmppath);
#ifndef GMIME24
                g_object_unref (att);
#endif
                return -1;
            }
            w_stream = g_mime_stream_file_new (wfp);

            wrapper = g_mime_part_get_content_object((GMimePart *)att);
	    if (wrapper == NULL) {
	        log(ERR_GMIME, "drop_file", "g_mime_part_get_content_object");

#ifndef GMIME24
	        g_object_unref (att);
#endif

                g_object_unref (w_stream);
	        return -1;
	    }

	    ret = g_mime_data_wrapper_write_to_stream(wrapper, w_stream);

#ifndef GMIME24
            g_object_unref (wrapper);
#endif
            g_object_unref (w_stream);

	}
	if (ret < 0) {
	    log(ERR_GMIME, "drop_file", "g_mime_data_wrapper_write_to_stream");

#ifndef GMIME24
	    g_object_unref (att);
#endif

	    return -1;
	}

#ifndef GMIME26
        g_mime_multipart_remove_part((GMimeMultipart *)object, att);
#else
        g_mime_multipart_remove((GMimeMultipart *)object, (GMimeObject *)att);
#endif

#ifndef GMIME24
	g_object_unref (att);
#endif
    }

    return 0;
}

/*
 * mk_deletelistfile
 *
 * Function
 *      Creat a temporary file to save namelist data in.
 *
 * Argument
 *      struct config  *cfg	config structure
 *      char *tmpdir		temporary directory name
 *
 * Return value
 *      0       Normal end.
 *      -1      Abormal end.
 */
int
mk_deletelistfile(struct config *cfg, struct mailzip *mz)
{
    FILE *fp;
    int i, retw;
    
    /* open a deletelistfile named by mz->encfilepath. */
    fp = fopen(mz->encfilepath, "w");
    if (fp == NULL) {
        log(ERR_FILE_OPEN, "mk_deletelistfile", mz->encfilepath);
        return -1;
    }
    
    for (i = 0; (mz->namelist + i)->attach_name != NULL; i++) {
        retw = fwrite((mz->namelist + i)->attach_name, 
                      (mz->namelist + i)->attach_name_len, 1, fp);
        if(retw < 0) {
            log(ERR_FILE_WRITE, "mk_deletelistfile");
            fclose(fp);
            return -1;
        }
        retw = fprintf(fp, "\r\n");
        if(retw < 0) {
            log(ERR_FILE_WRITE, "mk_deletelistfile");
            fclose(fp);
            return -1;
        }

    }

    fclose(fp);

    return (0);
}
#define CDCOMMAND	"cd"
#define QOPTION		"-q"
#define ANDCOMMAND	"&&"
#define CURRENTDIR	"./"
#define ZIP_FILE_PATH   "%s/%s"

/*
 * replace_extension
 *
 * Function
 *      Recplace extension of file
 *
 * Argument
 *      char * newfilename      path of zipfile after replaced new extension
 *      char * filename         current filename
 *      char * new_ext          new extension
 *
 * Return value
 *      0       Normal end.
 *      -1      Abormal end.
 */
int
replace_extension(char *newfilename, char *filename, char *new_ext)
{
    char *p;
    char data[PATH_MAX + 1];
    int ext_len;
    int name_len;
    char *ext;

    /* search dot */
    ext = strrchr(filename, DOT);
    if (!ext) {
        /* if filename have not extension then add new extension to filename */
        snprintf(newfilename, FILE_NAME_MAX + 1, "%s.%s", filename, new_ext);
    } else {
        /* length of extension */
        ext_len = strlen(ext + 1);
        /* 1 is length of DOT */
        name_len = strlen(filename) - ext_len - 1;
        p = strncpy(data, filename, name_len);
        *(p + name_len) = '\0';

        /* create new filename */
        snprintf(newfilename, FILE_NAME_MAX + 1, "%s.%s", data, new_ext);
    }

    return 0;
}

/*
 * get_mimetype
 *
 * Function
 *      get_mimetype
 *
 * Argument
 *      struct config  *cfg     config structure
 *      char *str               extension
 *
 * Return value
 *      m_p->mimetype  MimeTypes 
 *      NULL
 */
int
get_mimetype(struct config *cfg, char *extension)
{
    mimetype_list_t *m_p;
    int res;

    /* 読み込んだmimetypefileにextensionがあるか */
    for (m_p = cfg->cf_mimetypes; m_p != NULL; m_p = m_p->next) {
        res = strcmp(m_p->extension, extension);
         if (res == 0) {
            /* 拡張子が一致したら */
            break;
        }
    }

    /* m_pがNULLでないなら拡張子が見つかった */
    if (m_p != NULL) {
        return m_p->mimetype;
    }

    /* 拡張子が見つからなかった場合はNULL */
    return NULL;
}
 
/*
 * convert_zip
 *
 * Function
 *      ZIP conversion
 *
 * Argument
 *      struct config  *cfg     config structure
 *      struct mailzip *mz      mail structure
 *      struct rcptinfo *rcpt   recipients
 *
 * Return value
 *      0       Normal end.
 *      -1      Abormal end.
 */
int
convert_zip(struct config *cfg, struct mailzip *mz, struct rcptinfo *rcpt)
{
    int    ret;
    pid_t  pid;
    char *list[5];
    int     sts = 0;

    if (rcpt->command && rcpt->command[0] != '\0') {
        list[0] = rcpt->command;
    } else {
        list[0] = cfg->cf_zipcommand;
    }
    list[1] = QOPTION;
    list[2] = mz->encfilepath;
    list[3] = CURRENTDIR;
    list[4] = NULL;

    /*
     * make child process
     */
    if ((pid = fork()) == 0) {
        /* child process */
#ifndef __CUSTOMIZE2018
        zip_child(list, cfg->cf_zipcommandopt, mz->zipdir, rcpt->passwd);
#else   // __CUSTOMIZE2018
        if (ismode_harmless) {
            zip_child(list, cfg->cf_zipcommandopt, mz->zipdir, rcpt->passwd,NULL);
        } else {
            zip_child(list, cfg->cf_zipcommandopt, mz->zipdir, rcpt->passwd, mz->am_priv->mlfi_savefrom);
        }
#endif  // __CUSTOMIZE2018
    } else if (pid > 0) {
        /* parent process */
        ret = waitpid(pid, &sts, WUNTRACED);
        if (ret == -1) {
            log(ERR_WAIT_CHILD, "convert_zip", strerror(errno));
            return -1;
        }
        if (WIFEXITED(sts)) {       /* return or exit */
            ret = WEXITSTATUS(sts); /* exit code */
            if (ret != 0) {
                log(ERR_ZIP_CONVERT, "convert_zip", mz->encfilepath);
                return -1;
            }
        } else {
            log(ERR_WAIT_CHILD, "convert_zip", strerror(errno));
            return -1;
        }
    } else {
        /* make process failed */
        log(ERR_FORK_CREATE, "convert_zip", strerror(errno));
        return -1;
    }

    return (0);
}

/*--------------------------------------------------------*
 * child process
 *--------------------------------------------------------*/
static void
#ifndef __CUSTOMIZE2018
zip_child(char **list, char *commandopt, char *dir, char *passwd)
#else   // __CUSTOMIZE2018
zip_child(char **list, char *commandopt, char *dir, char *passwd, char *from)
#endif  // __CUSTOMIZE2018
{
    char *envstr;
    /*
     * set environment variable
     */
    if ((commandopt == NULL) || (strncmp(commandopt, OPTIONEND, OPTIONENDLEN) == 0)) {
        envstr = malloc(strlen(OPTIONRP) + strlen(passwd) + 3);
        sprintf(envstr, "%s %s", OPTIONRP, passwd);
    } else {
        envstr = malloc(strlen(OPTIONRP) + strlen(passwd) + strlen(commandopt) + 3);
        sprintf(envstr, "%s %s %s", OPTIONRP, passwd, commandopt);
    }
    if (setenv(ENV_ZIPOPT, envstr, OVERWRITE) < 0) {
        log(ERR_SET_ENV, "zip_child", ENV_ZIPOPT);
        free(envstr);
        exit(1);
    }
    free(envstr);
#ifdef __CUSTOMIZE2018
    if (from && setenv(ENV_SAMMA_ENVFROM, from, OVERWRITE) < 0) {
        log(ERR_SET_ENV, "zip_child", ENV_SAMMA_ENVFROM);
        exit(1);
    }
#endif  // __CUSTOMIZE2018

    /* change encryption directory */
    if (chdir(dir) != 0) {
        log(ERR_DIRECTORY_CHANGE, "zip_child", dir);
        exit(1); 
    }

    /*
     * Execution
     */
    if (execvp(list[0], list) < 0) {
        log(ERR_EXEC_FILE, "zip_child", list[0], strerror(errno));
        exit(1);
    }
    
    unsetenv(ENV_ZIPOPT);

    exit(0);
}

/*
 * check_ascii
 *
 * args:
 *  char *str           mail address
 * return:
 *  0           is ascii
 *  -1          not ascii
 */
int
check_ascii(char *str)
{
    int ret;
    int i;

    for (i = 0; str[i] != '\0'; i++) {

        /* Ascii Check */
        ret = isascii(str[i]);

        /* Not Ascii */
        if (ret == 0) {
            log(ERR_MAILADDR_UNKNOWN_TYPE, "check_ascii", str);
            return -1;
        }
    }

    return 0;
}

int
mk_encpath(struct config *cfg, struct mailzip *mz)
{
    int strdatenum;
    struct tm *ti; 
    time_t now;
    char *filename, *path;
    char *tmpdir = mz->zipdir;
    char *cfg_attachname = NULL;

    /* Switch cfg_attachname according to the run modes */
    if (ismode_delete) {
        cfg_attachname = cfg->cf_deletelistname;
    } else if (ismode_harmless) {
        cfg_attachname = cfg->cf_zipfilename;
    } else {
        cfg_attachname = cfg->cf_zipfilename;
    }

    /* get now time */
    time(&now);
    ti = localtime(&now);

    /* allocate date string */
    strdatenum = strlen(cfg_attachname) + STRTIMENUM + 1;
    filename = malloc(strdatenum);
    if (filename == NULL) {
	log(ERR_MEMORY_ALLOCATE, "add_enclist", "rcptinfo", strerror(errno));
	return -1;
    }

    strftime(filename, strdatenum - 1, cfg_attachname, ti);
    mz->attachfilename = filename;

    /* create zip (delete-report) file path in Encryption (Delete) mode */
    path = malloc(strlen(tmpdir) + strdatenum);
    if (path == NULL) {
	log(ERR_MEMORY_ALLOCATE, "add_enclist", "rcptinfo", strerror(errno));
        free(filename);
	return -1;
    }
    sprintf(path, FILE_PATH, tmpdir, filename);

    mz->encfilepath = path;

    return 0;
}

/* get_msgid
 * 
 * get the message id from file attached mail
 *
 * Args:
 *    char **buf        buffer of set the message id
 *    char *mail        mail data of file attached mail
 *
 * Return:
 *    ERROR      -1      error
 *    SUCCESS     0      success
 */
int get_msgid(char **buf, char *mail) {

    //variables
    int id_len = 0;
    char *p = NULL;
    char *head = NULL;
    char *tail = NULL;      
    char *tmp = NULL;

    // search Message-ID field
    p = strstr(mail, MSG_ID);   
    if (p == NULL) {
        return ERROR;
    }

    // search "<"
    head = strchr(p, '<');
    if (head == NULL) {
        return ERROR;
    }
    // search ">"
    tail = strchr(head, '>');
    if (tail == NULL) {
        return ERROR;
    }
    // check the length of Message-ID
    id_len = strlen(head) - strlen(tail) + 1;

    // allocate memory for Message-ID(2 is '\n' and '\0')
    tmp = (char *)calloc(REF_LEN + id_len + 2, sizeof(char));
    if (tmp == NULL) {
        return ERROR;
    }
    *buf = tmp;

    // set References field
    strcat(*buf, REF);
    memcpy(*buf + strlen(REF), head, id_len);
    strcat(*buf, "\n\0");

    return SUCCESS;
}

/* set_references
 * 
 * add header field "References" to password confirming mail
 *
 * Args:
 *    char *mail_data	strings of mail data include header of file 
 *                      attached mail
 *    char *passwd_mail mail data of password confirming mail
 *
 * Return:
 *    ERROR      -1      error
 *    SUCCESS     0      success
 */
int set_references(char *mail_data, char **passwd_mail) {

    // variables
    char *tmp = NULL;
    char *ref = NULL;
    int ret = 0;

    //get message id
    ret = get_msgid(&ref, mail_data);
    if (ret == ERROR) {
        return ERROR;
    }

    // allocate memory for mail 
    tmp = realloc(*passwd_mail, strlen(ref) + strlen(*passwd_mail) + 1);
    if (tmp == NULL) {
        free(ref);
        return ERROR;
    }
    *passwd_mail = tmp;

    // set references
    memmove(*passwd_mail + strlen(ref), *passwd_mail, strlen(*passwd_mail) + 1);
    memcpy(*passwd_mail, ref, strlen(ref));
    free(ref);

    return SUCCESS;
}

#ifdef __CUSTOMIZE2018
/* zipconv_log
 *
 * output log with message-id, sender, rcpts, attached files, and password
 *
 * Args:
 *    char *message_id			Message-Id
 *    char *from			Sener address
 *    struct rcptaddr *rcpts		Recipients
 *    struct name_list *attachlist	File name list
 *    char *passwd			password
 *
 * Return:
 *     (void)
 */
void
zipconv_log(char *message_id, char *from, struct rcptaddr *rcpts,
		struct name_list *attachlist, char *passwd)
{
    size_t loglen = 15;	// length : 16 = FMT + '\0'
    char *msgid = NULL;
    char *fromstr = NULL;
    char *pwstr = NULL;
    char *log_msg = NULL;
    size_t msgid_len = 0;
    size_t from_len = 0;
    size_t passwd_len = 0;
    int i;
    int oft = 0;
    char *new_log = NULL;
    int ret;

    // sanitize
    msgid = (message_id == NULL)?"-":message_id;
    fromstr = (from == NULL)?"-":from;
    pwstr = (passwd == NULL)?"-":passwd;
        
    // calc log length
    msgid_len = strlen(msgid);
    loglen += msgid_len;
    from_len = strlen(fromstr);
    loglen += from_len;
    for (i = 0; (rcpts + i)->rcpt_addr != NULL; i++) {
        loglen += (rcpts + i)->rcpt_addr_len + 1;	// includes ':'
    }
    for (i = 0; (attachlist + i)->attach_name != NULL; i++) {
        loglen += (attachlist + i)->attach_name_len + 1;	// includes ':'
    }
    passwd_len = strlen(pwstr);
    loglen += passwd_len;

    // allocate memory
    log_msg = (char *)malloc(loglen);
    if (log_msg == NULL) {
        log(ERR_MEMORY_ALLOCATE, "zipconv_log", "log_msg", strerror(errno));
        return;
    }
    log_msg[0] = '\0';

    // build log message
    // Note:
    //  To avoid to reduce performance, we don't use sprintf or strcat, ...

    // message-id
    strcpy((log_msg + oft), "\"");
    oft ++;
    strcpy((log_msg + oft), msgid);
    oft += msgid_len;
    strcpy((log_msg + oft), "\" \"");
    oft += 3;

    // from addr
    strcpy((log_msg + oft), fromstr);
    oft += from_len;
    strcpy((log_msg + oft), "\" \"");
    oft += 3;

    // to addr
    for (i = 0; (rcpts + i)->rcpt_addr != NULL; i++) {
        if (i != 0) {
            // add delimiter
            *(log_msg + oft) = ':';
            oft ++;
        }
        strcpy((log_msg + oft), (rcpts + i)->rcpt_addr);
        oft += (rcpts + i)->rcpt_addr_len;
    }
    strcpy((log_msg + oft), "\" \"");
    oft += 3;

    // filename
    for (i = 0; (attachlist + i)->attach_name != NULL; i++) {
        if (i != 0) {
            // add delimiter
            *(log_msg + oft) = ':';
            oft ++;
        }
        strcpy((log_msg + oft), (attachlist + i)->attach_name);
        oft += (attachlist + i)->attach_name_len;
    }
    strcpy((log_msg + oft), "\" \"");
    oft += 3;

    // message-id
    strcpy((log_msg + oft), pwstr);
    oft += passwd_len;
    strcpy((log_msg + oft), "\"");
    oft ++;

    // change encoding
    ret = dg_str2code(log_msg, &new_log, "SJIS", "UTF-8");
    switch (ret) {
    case 0:
        free(log_msg);
        log_msg = new_log;
        break;
    default:
        // ignore silently if error occurs
        if (new_log != NULL) {
            free(new_log);
        }
        break;
    }

    // output log
    if ((void *)log == errorlog) {
        // output to stderr
        strcpy((log_msg + oft), "\n");
        fprintf(stderr, log_msg);
    } else if ((void*)log == systemlog) {
        syslog(LOG_INFO, log_msg);
    }
    free(log_msg);
    return;
}

/* get_body_head
 *
 * search the position of the body head
 *
 * Args:
 *    char *buf	String pointer to search the position of the body head
 *
 * Return:
 *    char *	The body head pointer
 */
char *
get_body_head(char *buf)
{
    char *head;
    char *p1, *p2;
    if (*buf == '\0') {
        // case no string
        head = buf;
    } else if (*buf == '\n') {
        // case no header with '\n'
        head = buf + 1;
    } else if (*buf == '\r' || *buf == '\n') {
        // case no header with '\r\n'
        head = buf + 2;
    } else {
        p1 = strstr(buf, "\n\n");
        p2 = strstr(buf, "\r\n\r\n");
        if (p1 == NULL) {
            if (p2 == NULL) {
                // case no blank line
                head = buf;
            } else {
                // found blank line with '\r\n'
                head = p2 + 4;
            }
        } else {
            if (p2 == NULL) {
                // found blank line with '\n'
                head = p1 + 2;
            } else {
                // both line feed found
                if (p1 > p2) {
                    // blank line is with '\r\n'
                    head = p2 + 4;
                } else {
                    // blank line is with '\n'
                    head = p1 + 2;
                }
            }
        }
    }
    return head;
}

/* is_noenc_qp
 *
 * evaluate the charactor necessary to encode QP
 *
 * Args:
 *    char c	to evaluate charactor
 *
 * Return:
 *    1		not necessary
 *			printable without '='
 *			'\r' '\n'
 *    0		necessary
 */
int
is_noenc_qp(char c)
{
    if ((c >= ' ' && c <= '<') || (c >= '>' && c <= '~')
         || c == '\r' || c == '\n') {
        return 1;
    } else {
        return 0;
    }
}

/* encode_qp
 *
 * encode the string to quoted-printable
 *
 * Args:
 *    char *src	to encode string
 *
 * Return:
 *    char *	encoded string allocated
 *    NULL	memory error
 */
char *
encode_qp(char *src)
{
    size_t len;
    int soft = 0, doft = 0;
    char *new_buf;
    char one_char[4];

    len = strlen(src);
    new_buf = (char *)malloc(len * 3 + 1);
    if (new_buf == NULL) {
        return NULL;
    }
    *new_buf = '\0';

    for (soft = 0, doft = 0; src[soft] != '\0'; soft ++) {
        //if (isascii(src[soft])) {
        if (is_noenc_qp(src[soft])) {
            *(new_buf + doft) = src[soft];
            *(new_buf + doft + 1) = '\0';
            doft ++;
        } else {
            snprintf(one_char, 4, "=%02x", ((unsigned int)src[soft] & 0xff));
            strcpy(new_buf + doft, one_char);
            doft += 3;
        }
    }
    return new_buf;
}

/* add_message
 *
 * add the template message to the top of the original message
 *
 * Args:
 *    char *orig_msg	original message
 *    struct mailzip *mz	mailzip structure
 *    char *charset	Charactor set
 *    GMIMEContentEncoding	c_enc	encode code
 *		GMIME_CONTENT_ENCODING_BASE64
 *		GMIME_CONTENT_ENCODING_QUOTEDPRINTABLE
 *		and other
 *
 * Return:
 *    char *	merged string allocated
 *    NULL	memory error
 */
char *
add_message(char *orig_msg, struct mailzip *mz,
            char *charset, GMimeContentEncoding c_enc, GMimeContentType *ctype)
{
    char *tmpl = NULL;
    char *tmp_tmpl = NULL, *new_tmpl = NULL;
    char *tmp_msg = NULL, *tmp_msg2 = NULL, *new_msg = NULL;
    int ret;
    size_t olen = 0, tlen = 0, nlen = 0;
    int hflag;
    char *tmpl_org = NULL;

    hflag = (strcasecmp(ctype->subtype, "html") == 0)?1:0;

    switch(mz->am_priv->mlfi_subject_lang) {
    case SBJLANG_JP:
        tmpl = (hflag == 0)?mz->am_tmpl->amt_jp:mz->am_tmpl->amt_jp_html;
        break;
    case SBJLANG_EN:
        tmpl = (hflag == 0)?mz->am_tmpl->amt_en:mz->am_tmpl->amt_en_html;
        break;
    default:
        tmpl = (hflag == 0)?mz->am_tmpl->amt_both:mz->am_tmpl->amt_both_html;
        break;
    }

    if (tmpl == NULL || *tmpl == '\0') {
        // case empty template
        new_msg = strdup(orig_msg);
        if (new_msg == NULL) {
	    log(ERR_MEMORY_ALLOCATE, "add_message", "new_msg", strerror(errno));
            return NULL;
        }
        return new_msg;
    }

    // encode template
    if (charset == NULL) {
        tmpl_org = tmpl;	    
        // case no charset force EN
        tmpl = (hflag == 0)?mz->am_tmpl->amt_en:mz->am_tmpl->amt_en_html;
        if (tmpl == NULL) {
            // case no EN template. Restore BOTH template
            tmpl = tmpl_org;
        }

        tmp_tmpl = strdup(tmpl);
        if (tmp_tmpl == NULL) {
	    log(ERR_MEMORY_ALLOCATE, "add_message", "tmp_tmpl", strerror(errno));
            return NULL;
        }
    } else if (strcasecmp(charset, "iso-2022-jp") == 0
               || strcasecmp(charset, "\"iso-2022-jp\"") == 0) {
        // case JIS
        ret = dg_str2code(tmpl, &tmp_tmpl, "SJIS", "ISO-2022-JP");
        switch (ret) {
        case -1:
            // memory error
	    log(ERR_MEMORY_ALLOCATE, "add_message", "tmp_tmpl", strerror(errno));
            return NULL;
        case 1:
            // failed to encode
	    log("Failed to encode charset : add_message");
            return NULL;
        }
    } else if (strcasecmp(charset, "utf-8") == 0
               || strcasecmp(charset, "utf8") == 0
               || strcasecmp(charset, "\"utf-8\"") == 0
               || strcasecmp(charset, "\"utf8\"") == 0) {
        // case UTF-8
        ret = dg_str2code(tmpl, &tmp_tmpl, "SJIS", "UTF-8");
        switch (ret) {
        case -1:
            // memory error
	    log(ERR_MEMORY_ALLOCATE, "add_message", "tmp_tmpl", strerror(errno));
            return NULL;
        case 1:
            // failed to encode
	    log("Failed to encode charset : add_message");
            return NULL;
        }
    } else {
        // case other includes SJIS
        tmp_tmpl = strdup(tmpl);
        if (tmp_tmpl == NULL) {
	    log(ERR_MEMORY_ALLOCATE, "add_message", "tmp_tmpl", strerror(errno));
            return NULL;
        }
    }

    // encode transfer encodings
    switch (c_enc) {
    case GMIME_CONTENT_ENCODING_BASE64:
        // decode original message
        ret = decode_b64(orig_msg, &tmp_msg);
        if (ret < 0) {
            // memory error
	    log(ERR_MEMORY_ALLOCATE, "add_message", "new_tmpl", strerror(errno));
            free(tmp_tmpl);
            return NULL;
        }
        // get length
        olen = strlen(tmp_msg);
        tlen = strlen(tmp_tmpl);
        nlen = olen + tlen;

        // build new message
        tmp_msg2 = (char *)malloc(nlen + 1);
        if (tmp_msg2 == NULL) {
            log(ERR_MEMORY_ALLOCATE, "add_message", "tmp_msg2", strerror(errno));
            free(tmp_tmpl);
            free(tmp_msg);
            return NULL;
        }
        strcpy(tmp_msg2, tmp_tmpl);
        strcpy((tmp_msg2 + tlen), tmp_msg);
        free(tmp_tmpl);
        free(tmp_msg);

        new_msg = encode_b64(tmp_msg2);
        if (new_msg == NULL) {
            // memory error
	    log(ERR_MEMORY_ALLOCATE, "add_message", "new_tmpl", strerror(errno));
            free(tmp_msg2);
            return NULL;
        }
        free(tmp_msg2);
        break;
    case GMIME_CONTENT_ENCODING_QUOTEDPRINTABLE:
        // QP encode template 
        new_tmpl = encode_qp(tmp_tmpl);
        if (new_tmpl == NULL) {
            log(ERR_MEMORY_ALLOCATE, "add_message", "new_tmpl", strerror(errno));
            free(tmp_tmpl);
            return NULL;
        }
        free(tmp_tmpl); 

        // get length
        olen = strlen(orig_msg);
        tlen = strlen(new_tmpl);
        nlen = olen + tlen;

        // build new message
        new_msg = (char *)malloc(nlen + 1);
        if (new_msg == NULL) {
            log(ERR_MEMORY_ALLOCATE, "add_message", "new_msg", strerror(errno));
            free(tmp_tmpl);
            free(tmp_msg);
            return NULL;
        }
        strcpy(new_msg, new_tmpl);
        strcpy((new_msg + tlen), orig_msg);
        free(new_tmpl);
        break;
    default:
        // unnecessary to encode

        // get length
        olen = strlen(orig_msg);
        tlen = strlen(tmp_tmpl);
        nlen = olen + tlen;

        // build new message
        new_msg = (char *)malloc(nlen + 1);
        if (new_msg == NULL) {
    	log(ERR_MEMORY_ALLOCATE, "add_message", "new_msg", strerror(errno));
            free(new_tmpl);
            return NULL;
        }
        strcpy(new_msg, tmp_tmpl);
        strcpy((new_msg + tlen), orig_msg);
        free(tmp_tmpl);
        break;
    }


    return new_msg;
}

int
replace_mime_part(GMimeObject *att, GMimeObject *object, int pos,
                  struct mailzip *mz, GMimeContentType *ctype)
{
    GMimeStream *stream;
    GMimeDataWrapper *content;
    GMimePart *mime_part;
    char *orig_body;
    char *head;
    GMimeObject *replaced;
    const char *charset;
    const char *c_ent;
    GMimeContentEncoding c_enc;
    char *new_body;

    mime_part = g_mime_part_new_with_type(ctype->type, ctype->subtype);
    charset = g_mime_object_get_content_type_parameter(att, "charset");
    if (charset != NULL) {
        g_mime_object_set_content_type_parameter((GMimeObject *)mime_part, "charset", charset);
    }
    c_ent = g_mime_object_get_header(att, "content-transfer-encoding");
    if (c_ent != NULL) {
        g_mime_object_append_header((GMimeObject *)mime_part, "content-transfer-encoding", c_ent);
    }
    c_enc = g_mime_part_get_content_encoding((GMimePart *)att);
    orig_body = g_mime_object_to_string(att);
    if (orig_body == NULL) {
        // memory error
	log(ERR_MEMORY_ALLOCATE, "replace_mime_part", "orig_body", strerror(errno));
        return -1;
    }
    head = get_body_head(orig_body);

    // Add message
    new_body = add_message(head, mz, (char *)charset, c_enc, ctype);
    if (new_body == NULL) {
        // memory error
	log(ERR_MEMORY_ALLOCATE, "replace_mime_part", "new_body", strerror(errno));
        return -1;
    }
    free(orig_body);

    stream = g_mime_stream_mem_new_with_buffer(new_body, strlen(new_body));
    content = g_mime_data_wrapper_new_with_stream(stream, c_enc);
    g_object_unref(stream);
    g_mime_part_set_content_object(mime_part, content);
    g_object_unref(content);
    replaced = g_mime_multipart_replace((GMimeMultipart *)object, pos, (GMimeObject *)mime_part);
    g_object_unref(mime_part);
    g_object_unref(replaced);
    g_mime_multipart_get_part((GMimeMultipart *)object, pos);
    free(new_body);

    return 0;
}
#endif	// __CUSTOMIZE2018
