/*
 * samma
 * harmless.c
 *
 * switch convert, encrypt, delete
 */


#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>

#include <gmime/gmime.h>

#include "global.h"
#include "zipconv.h"
#include "mailzip.h"
#include "maildrop.h"
#include "samma_policy.h"
#include "harmless.h"

#include "msg_convert.h"
#include "msg_encrypt.h"
#include "msg_delete.h"
#include "sendmail.h"

#include "log.h"


typedef struct _item_func {
    char *item;
    int (*function)();
} item_func_t;

item_func_t harmless_func_list[] = {
    { "convert", msg_convert },
    { "encrypt", msg_encrypt },
    { "delete", msg_delete },
};

#define FUNC_LIST_SIZE (sizeof(harmless_func_list) / sizeof(item_func_t))


/**
 * static function
 */
GMimeMessage *get_gmime_message_from_minfo(struct mailinfo *minfo);
void init_harmless_proc_arg(harmless_proc_arg_t *args);
void free_harmless_proc_arg(harmless_proc_arg_t *args);
void harmless_single_part(GMimeObject *parent, GMimeObject *part, gpointer user_data);
void make_message_by_mem(GMimeObject *obj, char *string, size_t length);
void make_message_by_file(GMimeObject *obj, char *path);

/**
 * config構造体に、convert,encrypt,delete の配列をセットする
 * args:
 *   char *setting : 設定ファイルの文字列
 *   void **pointer : ここにセットする
 * return:
 *   NULL : 成功
 *   char * : エラーメッセージ
 */
char *set_harmless_proc_list(char *setting, void **pointer)
{
    harmless_proc_list_t *list = NULL, *list_end = NULL;
    char *target = setting;
    char *comma = NULL;
    int i, loop_flag;

    static char errbuf[1024];

    // loop_flagはカンマが無くなったら0になる
    for (loop_flag = 1; loop_flag; target = comma + 1) {
        harmless_proc_list_t *list_elem;

        // カンマを探し、見つかったら\0に置き換える。
        // 見つからなかったら、この周を終えたらループを抜ける
        comma = strchr((const char *)target, ',');
        if (comma != NULL) {
            *comma = '\0';
        } else {
            loop_flag = 0;
        }

        while (isblank(*target)) {
            target++;
        }

        // 項目を検査し、正しい項目だったらチェック関数をセットする
        for (i = 0; i < FUNC_LIST_SIZE; i++) {

            // これじゃなかったら次のを調べる
            if (strcasecmp(harmless_func_list[i].item, target)) {
                continue;
            }

            list_elem = calloc(1, sizeof(harmless_proc_list_t));
            if (list_elem == NULL) {
                free_harmless_proc_list(list);
                sprintf(errbuf, HARMLESS_ERR_MEM, strerror(errno));
                return (errbuf);
            }

            list_elem->function = harmless_func_list[i].function;
            list_elem->next = NULL;

            // リストの末尾を更新しながらリストを長くする
            if (list == NULL) {
                list = list_elem;
                list_end = list_elem;
            } else {
                list_end->next = list_elem;
                list_end = list_elem;
            }

            break;
        }

        if (i == FUNC_LIST_SIZE) {
            free_harmless_proc_list(list);
            sprintf(errbuf, HARMLESS_ERR_INVALID, target);
            return (errbuf);
        }
    }

    *pointer = list;

    return NULL;
}

void free_harmless_proc_list(harmless_proc_list_t *list)
{
    harmless_proc_list_t *tmp = list;

    while (list != NULL) {
        tmp = list->next;
        free(list);
        list = tmp;
    }
}


/**
 * 無害化処理関数に渡す構造体の初期化
 */
void init_harmless_proc_arg(harmless_proc_arg_t *args)
{
    args->message = NULL;
    args->message_length = 0;
    args->zipdir = NULL;
    args->depth = 0;
    args->cfg = NULL;
    args->maildata = NULL;
    args->sendercheck = 0;
    args->mime_extension = NULL;
}
void free_harmless_proc_arg(harmless_proc_arg_t *args)
{
    free(args->message);
    args->message = NULL;

    args->message_length = 0;

    free(args->zipdir);
    args->zipdir = NULL;

    args->depth = 0;
    args->maildata = NULL;
    args->sendercheck = 0;

    free(args->mime_extension);
    args->mime_extension = NULL;

}

/**
 * 無害化処理として、メイン処理から呼び出される関数
 *
 *
 */
int harmless(SMFICTX *ctx, struct mlfiPriv *priv)
{
    int result = PM_SUCCESS;
    int ret, i = 0;

    GMimeObject *mail_root = NULL;
    GMimeMessage *msg_org = NULL;

    // get from ptiv
    struct mailinfo *minfo = priv->mlfi_minfo;
    struct config *cfg = priv->mlfi_conf;
    struct rcptinfo *p;
    struct rcptaddr *rdm_all = NULL;

    // 無害化関数に渡す引数
    harmless_proc_arg_t proc_arg;

    init_harmless_proc_arg(&proc_arg);

    proc_arg.depth = cfg->cf_maxmultipartdepth;
    proc_arg.cfg = cfg;
    proc_arg.maildata = &(priv->mlfi_sendercheck_arg);
    proc_arg.sendercheck = priv->mlfi_safetysendercheck;

    // GMime開始
    pthread_mutex_lock(&gmime_lock);

    // minfo に入ってるデータをGMimeに加工させる
    msg_org = get_gmime_message_from_minfo(minfo);
    if (msg_org == NULL) {
        log(ERR_FILE_OPEN, "harmless(1)", minfo->ii_fd);
        goto fail;
    }

    // X-SAMMA-ENCヘッダを付与
    // GMimeが勝手に韓国語と判定する問題の回避のため
//    g_mime_object_append_header((GMimeObject *)msg_org, XHEADERNAME, XHEADERVALUE);

    // ヘッダを除去したメッセージパート全体を取得
    mail_root = g_mime_message_get_mime_part(msg_org);

    // シングルパートをマルチパート化
    if (!GMIME_IS_MULTIPART(mail_root)) {

        GMimeMultipart *np = g_mime_multipart_new();

        const char *_type = g_mime_object_get_header((GMimeObject *)msg_org, "Content-Type");

        g_mime_multipart_add(np, mail_root);

        g_mime_object_set_header(
            (GMimeObject *)np,
            "Content-Type",
            _type == NULL ? "text/plain" : _type
        );

        g_mime_message_set_mime_part(msg_org, (GMimeObject *)np);
        g_object_unref(np);

        g_mime_object_set_header((GMimeObject *)msg_org, "Content-Type", "multipart/mixed");
        mail_root = g_mime_message_get_mime_part(msg_org);
    } else {
        GMimeContentType *_curtype = g_mime_object_get_content_type(mail_root);
        if (!g_mime_content_type_is_type(_curtype, "multipart", "mixed")) {

            GMimeMultipart *np = g_mime_multipart_new();
         
            g_mime_multipart_add(np, mail_root);
         
            g_mime_message_set_mime_part(msg_org, (GMimeObject *)np);
            g_object_unref (np);

            g_mime_object_set_header((GMimeObject *)msg_org, "Content-Type", "multipart/mixed");
            mail_root = g_mime_message_get_mime_part(msg_org);
        }
    }

    // 元メールを解析し、新メールを作る
    // message, zipflag はゼロ初期化
    ret = harmless_proc((GMimeMultipart *)mail_root, &proc_arg);
    if (!ret) {
        goto fail;
    }

    // zipにすべきものがあれば作ってくっつける
    if (proc_arg.zipdir != NULL) {
        struct mailzip mz = {
#ifndef __CUSTOMIZE2018
            NULL, NULL, NULL, proc_arg.zipdir, NULL, NULL, NULL
#else   // __CUSTOMIZE2018
            NULL, NULL, NULL, proc_arg.zipdir, NULL, NULL, NULL, 0, 0, NULL, NULL
#endif  // __CUSTOMIZE2018
        };
        struct rcptinfo rinfo = {NULL, 0, NULL, NULL, NULL};
        struct rcptinfo *rinfo_list = &rinfo;
        int _ret;

        GMimePart *zip;

        // zip作成
        if (mk_encpath(cfg, &mz) == -1) {
            free(mz.encfilepath);
            free(mz.attachfilename);
            goto fail;
        }

        if (*(cfg->cf_defaultpassword) == '\0') {
            _ret = mk_passwd(&(rinfo.passwd), cfg->cf_passwordlength);
            if (_ret == PASSWD_FAILED) {
                free(mz.encfilepath);
                free(mz.attachfilename);
                goto fail;
            }
        } else {
            rinfo.passwd = strdup(cfg->cf_defaultpassword);
            if (rinfo.passwd == NULL) {
                free(mz.encfilepath);
                free(mz.attachfilename);
                goto fail;
            }
        }

        _ret = convert_zip(cfg, &mz, rinfo_list);
        if (_ret == -1) {
            free(mz.encfilepath);
            free(mz.attachfilename);
            free(rinfo.passwd);
            goto fail;
        }

        zip = g_mime_part_new();
        g_mime_object_set_header((GMimeObject *)zip, "Content-Type", "application/x-compress");

        g_mime_part_set_content_encoding(zip, GMIME_CONTENT_ENCODING_BASE64);

        g_mime_object_set_disposition((GMimeObject *)zip, "attachment");

        // 下に同じ（メモリリーク？）
        //g_mime_part_set_filename(zip, (const char *)mz.attachfilename);
        g_mime_object_set_content_disposition_parameter((GMimeObject *)zip, "filename", mz.attachfilename);
        g_mime_object_set_content_type_parameter((GMimeObject *)zip, "filename", mz.attachfilename);

        make_message_by_file((GMimeObject *)zip, mz.encfilepath);

        g_mime_multipart_add((GMimeMultipart *)mail_root, (GMimeObject *)zip);
        g_object_unref (zip);

        log(
HARMLESS_ZIP_LOG,
 rinfo.passwd,
 proc_arg.maildata->ip,
 proc_arg.maildata->message_id,
 proc_arg.maildata->rcpt_to
);

        remove_file_with_dir_recursive(proc_arg.zipdir);
        free(proc_arg.zipdir);
        proc_arg.zipdir = NULL;
        free(mz.encfilepath);
        free(mz.attachfilename);
        free(rinfo.passwd);
    }

    // メッセージ添付ファイルを作ってくっつける
    if (proc_arg.message_length) {
        GMimePart *addmsg = NULL;

        int strdatenum;
        struct tm *ti;
        time_t now;
        char *msgfilename;
        char *tmpl = NULL;
        tmpl = cfg->cf_harmlessmessagefilename;

        time(&now);
        ti = localtime(&now);
        strdatenum = strlen(tmpl) + STRTIMENUM + 1;
        msgfilename = malloc(strdatenum);
        if (msgfilename == NULL) {
            log(HARMLESS_ERR_MEM, "msgfilename");
            goto fail;
        }
        strftime(msgfilename, strdatenum - 1, tmpl, ti);

        addmsg = g_mime_part_new();
        g_mime_object_set_header((GMimeObject *)addmsg, "Content-Type", "text/plain");

        g_mime_part_set_content_encoding(addmsg, GMIME_CONTENT_ENCODING_BASE64);
        g_mime_object_set_disposition((GMimeObject *)addmsg, "attachment");

        // なにやらメモリリークバグがあるような気がするので一旦この関数を
        // 使わないで処理を行う
        //g_mime_part_set_filename(addmsg, msgfilename);

        g_mime_object_set_content_type_parameter((GMimeObject *)addmsg, "filename", msgfilename);
        g_mime_object_set_content_disposition_parameter((GMimeObject *)addmsg, "filename", msgfilename);

        make_message_by_mem((GMimeObject *)addmsg, proc_arg.message, (size_t)proc_arg.message_length);

        g_mime_multipart_add((GMimeMultipart *)mail_root, (GMimeObject *)addmsg);
        g_object_unref(addmsg);

        free(msgfilename);
    }

    free_harmless_proc_arg(&proc_arg);

    /* 送信先リストの作成 */
    for (p = priv->mlfi_rdmpasslist; p != NULL; p = p->Next) {
        for (i = 0; (p->rcptlist + i)->rcpt_addr; i++) {
            if (push_rcptlist(&rdm_all, (p->rcptlist + i)->rcpt_addr) != 0) {
                free_rcptlist(rdm_all);
                goto fail;
            }
        }
    }

    // 新メールを送信する
    ret = sendmail_with_gmime_object(msg_org, cfg, rdm_all, priv->mlfi_savefrom);

    // milterに送信済みの人を消してもらう
    for (i = 0; (rdm_all + i)->rcpt_addr != NULL; i++) {
        if (smfi_delrcpt(ctx, (rdm_all + i)->rcpt_addr) == MI_FAILURE) {
            //log(); // TODO
            free_rcptlist(rdm_all);
            goto fail;
        } 
    }

    /* 送信先リストの開放 */
    free_rcptlist(rdm_all);

    goto end;


fail:
    result = PM_FAILED;
end:
    //g_object_unref(mail_root);
    g_object_unref(msg_org);
    pthread_mutex_unlock(&gmime_lock);
    return result;
}


GMimeMessage *get_gmime_message_from_minfo(struct mailinfo *minfo)
{
    int rfd = 0;
    FILE *rfp = NULL;

    GMimeStream *r_stream;
    GMimeParser *parser;
    GMimeMessage *tmp_msg;

    if(minfo->ii_status & MS_STATUS_FILE) {
        DEBUGLOG("Create message object from file(a924)");
        if ((rfd = dup(minfo->ii_fd)) < 0) {
            return NULL;
        }
        rfp = fdopen(rfd, "r");
        if (rfp == NULL) {
            return NULL;
        }
        fseek(rfp, 0L, SEEK_SET);

        r_stream = g_mime_stream_file_new(rfp);
    } else {
        DEBUGLOG("Create message object from memory(b924)");
        r_stream = g_mime_stream_mem_new_with_buffer(minfo->ii_mbuf, minfo->ii_len);
    }

    parser = g_mime_parser_new_with_stream(r_stream);
    g_object_unref(r_stream);

    tmp_msg = g_mime_parser_construct_message(parser);
    g_object_unref (parser);
    if (tmp_msg == NULL) {
        return NULL;
    }

    return tmp_msg;
}


/**
 * 無害化処理の本体
 * メッセージ部分を受取り、新しいメッセージにして返す
 */
int harmless_proc(GMimeMultipart *parent, harmless_proc_arg_t *arg)
{
    int index, i, ret;


    // multipart多重で再帰的に呼ばれるので、上限を決めておく
    if (arg->depth < 1) {
        log("Too deep multipart mail.(Max:%d)", arg->depth);
        return HARMLESS_NG;
    }
    (arg->depth)--;

    index = g_mime_multipart_get_count(parent);

    for (i = 0; i < index; i++) {
        GMimeObject *part;
        GMimeObject *new = NULL;

        part = g_mime_multipart_remove_at(parent, i);

        // partは破壊されるかもしれない（partがマルチパートの時など）
        ret = harmless_proc_single_part(part, &new, arg);
        if (ret != HARMLESS_OK) {
            g_object_unref(part);
            return ret;
        }

        // 削除や暗号化ではパートが帰ってこない
        if (new != NULL) {
            g_mime_multipart_insert(parent, i, new);
        } else {
            i--;
            index--;
        }
        g_object_unref(part);
    }

    return HARMLESS_OK;
}

/*
 * srcで受け取ったパートを、harmlessprocやharmlessconfで指定された方式で処理し
 * dstに格納して返す.
 * 削除や圧縮処理などの結果、dstがNULLで返ることもある
 */
int harmless_proc_single_part(GMimeObject *src, GMimeObject **dst, harmless_proc_arg_t *arg)
{
    int ret;
    harmless_proc_list_t *proc;

    // convert, encrypt, deleteの順次実行
    for (proc = arg->cfg->cf_harmlessproc; proc != NULL; proc = proc->next) {

        ret = (proc->function)(src, dst, arg);
        if (ret == HARMLESS_OK) {

            return HARMLESS_OK;
        }
    }

    // cfg->harmlessprocに設定されている処理が全て失敗した
    return HARMLESS_NG;
}


int strcat_proc_message(
    char **msg
    , int *msg_len
    , char* tmpl
    , struct strtag *strtag
    , int tagcount
    )
{
    char *new, *tmp;
    int len;

    // libdgstr
    new = str_replace_tag(tmpl, MSG_TAG_S, MSG_TAG_E, strtag, tagcount);
    if (new == NULL) {
        return HARMLESS_NG;
    }

    // 今回加える文字列長、\nを加える分も数える
    len = strlen(new) + 1;

    // \0を数える
    tmp = realloc(*msg, *msg_len + len + 1);
    if (tmp == NULL) {
        free(new);
        return HARMLESS_NG;
    }

    *msg = tmp;

    if (*msg_len == 0) {
        **msg = '\0';
    }

    strcat(*msg, new);
    strcat(*msg, "\n");

    *msg_len += len;

    free(new);

    return HARMLESS_OK;
}

void make_message_by_mem(GMimeObject *obj, char *string, size_t length)
{
    GMimeStream *r_stream, *f_stream;
    GMimeDataWrapper *wrapper;
    GMimeFilter *filter;

    r_stream = g_mime_stream_mem_new_with_buffer((const char *)string, length);
    filter = g_mime_filter_basic_new(GMIME_CONTENT_ENCODING_BASE64, TRUE);
    f_stream = g_mime_stream_filter_new(r_stream);
    g_object_unref (r_stream);

    g_mime_stream_filter_add((GMimeStreamFilter *)f_stream, filter);
    g_object_unref(filter);

    wrapper = g_mime_data_wrapper_new_with_stream(f_stream, GMIME_CONTENT_ENCODING_BASE64);
    g_object_unref(f_stream);

    g_mime_part_set_content_object((GMimePart *)obj, wrapper);
    g_object_unref(wrapper);

}

void make_message_by_file(GMimeObject *obj, char *path)
{
    GMimeStream *r_stream, *f_stream;
    GMimeDataWrapper *wrapper;
    GMimeFilter *filter;
    FILE *fp;

    fp = fopen(path, "r");

    r_stream = g_mime_stream_file_new(fp);
    f_stream = g_mime_stream_filter_new(r_stream);
    g_object_unref(r_stream);

    filter = g_mime_filter_basic_new(GMIME_CONTENT_ENCODING_BASE64, TRUE);
    g_mime_stream_filter_add((GMimeStreamFilter *)f_stream, filter);
    g_object_unref(filter);

    wrapper = g_mime_data_wrapper_new_with_stream(f_stream, GMIME_CONTENT_ENCODING_BASE64);
    g_object_unref(f_stream);

    g_mime_part_set_content_object((GMimePart *)obj, wrapper);
    g_object_unref(wrapper);
}

char *estimate_filename(GMimeObject *part)
{
    const char *filename;

    filename = g_mime_object_get_content_disposition_parameter(part, "filename");
    if (filename == NULL) {

        filename = g_mime_object_get_content_type_parameter(part, "name");
        if (filename == NULL) {

            filename = "";
        }
    }

    return (char *)filename;
}


