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
#include <sys/types.h>
#include <sys/wait.h>

#include "exec_command.h"
#include "msg_convert.h"
#include "log.h"

#define MAX_CONFIG_LINE 1024


// 変換プログラムの一覧
typedef struct _conv_func {
    char *item;
    int (*function)();
} conv_func_t;

conv_func_t msgconv_func_list[] = {
    { "alternative", convert_alternative },
    { "multipart", convert_multipart },
    { "extension", convert_extension },
    { "none", convert_none },
};
#define CONVFUNC_LIST_SIZE (sizeof(msgconv_func_list) / sizeof(conv_func_t))

/**
 * static function decraretion
 */
int exec_command_with_gmime(GMimeObject *, GMimeObject **, char **, harmless_proc_arg_t *, int msg_next);

void output_conv_log(char *fmt, char *command, sender_check_arg_t *data);


/**
 * functions
 */
void output_conv_log(char *fmt, char *command, sender_check_arg_t *data)
{
    log(
        fmt,
        command,
        data->ip,
        data->message_id,
        data->envelope_from,
        data->rcpt_to
    );

}

void free_harmlessconf(command_list_t *list)
{
    command_list_t *tmp, *del;

    for (tmp = list; tmp != NULL; tmp = tmp->next, free(del)) {
        free(tmp->mime_before);
        free(tmp->mime_after);
        free(tmp->file_extension);
        free(tmp->command_name);
        free_arg_list(tmp->arg_list);
        del = tmp;
    }
}


/**
 * free_mimetypes
 *     MIMEタイプを定義した構造体のメモリを解放する
 * args:
 *     mimetype_list_t *list  MIMEタイプを定義した構造体
 */
void free_mimetypes(mimetype_list_t *list)
{
    mimetype_list_t *tmp, *del;

    if (list != NULL) {
        for (tmp = list; tmp != NULL; tmp = tmp->next, free(del)) {
            free(tmp->extension);
            free(tmp->mimetype);
            del = tmp;
        }
    }
}


char *read_harmlessconf(char *file, void **pointer)
{
    static char errbuf[1024] = "";
    char *errmsg;
    command_list_t *new_list = NULL, *list_end = NULL, *making_list = NULL;

    FILE *fp = NULL;

    char line[MAX_CONFIG_LINE + 1];
    int nline, i;
    char *tail, *save;
    char *fst, *snd, *trd, *fth;

    errbuf[0] = '\0';

    errmsg = is_readable_file(file);
    if (errmsg) {
        sprintf(errbuf, CONV_ERR_READ, file);
        goto error;
    }

    fp = fopen(file, "r");
    if (fp == NULL) {
        sprintf(errbuf, CONV_ERR_OPEN, file, strerror(errno));
        goto error;
    }

    for (nline = 1; fgets(line, MAX_CONFIG_LINE + 1, fp) != NULL; nline++) {
        command_list_t current_list = {NULL, NULL, NULL, NULL, 
                                       -1, 0, 0, 0, NULL, NULL};

        tail = strchr(line, '\n');
        if (tail == NULL) {
            sprintf(errbuf, CONV_ERR_TOOLONGLINE, file, nline);
            goto error;
        }
        *tail = '\0';

        if ((line[0] == '#') || (line[0] == '\0')) {
            /* comment or null line */
            continue;
        }

        // 4つに分割
        fst = strtok_r(line, " \t", &save);
        if (fst == NULL) {
            sprintf(errbuf, CONV_ERR_FEW_ITEM, file, nline);
            goto error;
        }
        snd = strtok_r(NULL, " \t", &save);
        if (snd == NULL) {
            sprintf(errbuf, CONV_ERR_FEW_ITEM, file, nline);
            goto error;
        }
        trd = strtok_r(NULL, " \t", &save);
        if (trd == NULL) {
            sprintf(errbuf, CONV_ERR_FEW_ITEM, file, nline);
            goto error;
        }
        // - だったら拡張子を加工しない
        if (strcmp(trd, "-") == 0) {
            trd = "";
        }

        while (isblank(*save)) save++;
        if (save == tail) {
            sprintf(errbuf, CONV_ERR_FEW_ITEM, file, nline);
            goto error;
        }
        fth = save;

        // 先頭の@の有無のチェック
        if (*fth == '@') {
            // メッセージ抑制フラグを立て、次のポインタへ
            current_list.msg_restraint = MSG_RESTRAIN;
            fth++;
        }

        // 先頭の!の有無のチェック
        if (*fth == '!') {
            // 外部コマンド失敗のログ抑制フラグを立て、次のポインタへ
            current_list.msg_next = 1;
            fth++;
        }


        // 指定されたコマンドのチェック
        if (*fth != '/') {
            current_list.command_type = FUNCTION;
            if ((current_list.command_name = strdup(fth)) == NULL) {
                sprintf(errbuf, CONV_ERR_MEM);
                goto error;
            }

            if (strcmp(current_list.command_name, "extension") == 0) {
                current_list.msg_restraint = MSG_RESTRAIN;
            }

            // 内部関数をセット
            for (i = 0; i < CONVFUNC_LIST_SIZE; i++) {
                if (strcasecmp(msgconv_func_list[i].item, fth)) {
                    continue;
                }

                current_list.in_func = msgconv_func_list[i].function;
                break;
            }

            if (i == CONVFUNC_LIST_SIZE) {
                sprintf(errbuf, CONV_ERR_WRONG_FUNC, file, nline, fth);
                goto error;
            }

        } else {
            current_list.command_type = COMMAND;
            if ((current_list.command_name = strdup(fth)) == NULL) {
                sprintf(errbuf, CONV_ERR_MEM);
                goto error;
            }

            errmsg = parse_command(fth, &(current_list.arg_list));
            if (errmsg) {
                sprintf(errbuf, CONV_ERR_WITH_LINE, file, nline, errmsg);
                goto error;
            }
        }

        new_list = calloc(1, sizeof(command_list_t));
        if (new_list == NULL) {
            sprintf(errbuf, CONV_ERR_MEM);
            free_arg_list(current_list.arg_list);
            free(current_list.command_name);
            goto error;
        }
        *new_list = current_list;

        if (making_list == NULL) {
            making_list = new_list;
            list_end = new_list;
        } else {
            list_end->next = new_list;
            list_end = new_list;
        }

        new_list->mime_before = strdup(fst);
        if (new_list->mime_before == NULL) {
            sprintf(errbuf, CONV_ERR_MEM);
            goto error;
        }

        new_list->mime_after = strdup(snd);
        if (new_list->mime_after == NULL) {
            sprintf(errbuf, CONV_ERR_MEM);
            goto error;
        }

        new_list->file_extension = strdup(trd);
        if (new_list->file_extension == NULL) {
            sprintf(errbuf, CONV_ERR_MEM);
            goto error;
        }
    }

    *pointer = making_list;

    goto end;


// 終了処理
error:
    free_harmlessconf(making_list);

end:
    if (fp != NULL) {
        fclose(fp);
    }

    return errbuf[0] == '\0' ? NULL : errbuf;
}


/**
 * read_mimetypes
 *     MIMEタイプ定義ファイルを読み込み、
 *     拡張子をキーとしたリスト構造体へ格納する
 * Args:
 *     char *filepath  MIMEタイプ定義ファイルのファイルパス
 *     void **pointer  情報が格納されたリスト構造体へのポインタ
 * Return:
 *     errbuf          エラーメッセージ
 */
char *read_mimetypes(char *filepath, void **pointer) {
    static char errbuf[1024] = "";
    char *errmsg;
    char *tail, *save, *tmp_ex, *save_ex;
    char line[MAX_CONFIG_LINE + 1];
    char *mime, *extensions;
    FILE *fp = NULL;
    int nline;
    mimetype_list_t *making_list = NULL, *new_list = NULL, *list_end = NULL;

    /* ファイルを読み込めるか確認して開く */
    errmsg = is_readable_file(filepath);
    if (errmsg) {
        sprintf(errbuf, MIME_ERR_READ, filepath);
        free_mimetypes(making_list);
        return errbuf[0] == '\0' ? NULL : errbuf;
    }

    fp = fopen(filepath, "r");
    if (fp == NULL) {
        sprintf(errbuf, MIME_ERR_OPEN, filepath, strerror(errno));
        free_mimetypes(making_list);
        return errbuf[0] == '\0' ? NULL : errbuf;
    }

    /* 1行ずつ読み込む */
    for (nline = 1; fgets(line, MAX_CONFIG_LINE + 1, fp); nline++) {
        /* 一時的に情報を格納する構造体を初期化する 
           {extension, mimetype, next} */
        mimetype_list_t current_list = {NULL, NULL, NULL};

        /* 改行を探す */
        tail = strchr(line, '\n');
        if (tail == NULL) {
            sprintf(errbuf, MIME_TOOLONGLINE, filepath, nline);
            fclose(fp);
            free_mimetypes(making_list);
            return errbuf[0] == '\0' ? NULL : errbuf;
        }
        /* 行末を終端にする */
        *tail = '\0';

        /* コメントと空行を読み飛ばす */
        if ((line[0] == '#') || (line[0] == '\0')) {
            continue;
        }

        /* MIMEタイプ部と拡張子部の2つに分割 */
        mime = strtok_r(line, " \t", &save);
        if (mime == NULL) {
            /* 空行なので読み飛ばす */
            continue;
        }

        /* タブと空白を飛ばし、余った部分を拡張子部として確保 */
        while (isblank(*save)) save++;
        extensions = save;

       /* 拡張子がない場合は読み飛ばす */
        if (save == tail) {
            continue;
        }

        /* 拡張子を分割し構造体へ格納する */
        while ((tmp_ex = strtok_r(extensions, " \t", &save_ex)) != NULL) {
            if ((current_list.extension = strdup(tmp_ex)) == NULL) {
                sprintf(errbuf, MIME_ERR_MEM);
                fclose(fp);
                free_mimetypes(making_list);
                return errbuf[0] == '\0' ? NULL : errbuf;
            }
            if ((current_list.mimetype = strdup(mime)) == NULL) {
                sprintf(errbuf, MIME_ERR_MEM);
                fclose(fp);
                free_mimetypes(making_list);
                return errbuf[0] == '\0' ? NULL : errbuf;
            }

            /* 情報が入った構造体を別の構造体へ */
            new_list = calloc(1, sizeof(mimetype_list_t));
            if (new_list == NULL) {
                sprintf(errbuf, MIME_ERR_MEM);
                fclose(fp);
                free_mimetypes(making_list);
                return errbuf[0] == '\0' ? NULL : errbuf;
            }
            *new_list = current_list;

            /* 構造体をリスト構造にする */
            if (making_list == NULL) {
                making_list = new_list;
                list_end = new_list;
            } else {
                list_end->next = new_list;
                list_end = new_list;
            }
            extensions = NULL;
        }
    }
    *pointer = making_list;

    if (fp != NULL) {
        fclose(fp);
    }

    return errbuf[0] == '\0' ? NULL : errbuf;
}


#define MIME_BEFORE 0
#define MIME_AFTER 1
#define FILE_BEFORE 2
#define FILE_AFTER 3
int msg_convert(GMimeObject *part, GMimeObject **new, harmless_proc_arg_t *arg)
{
    int ret, safety_flag;
    char *content_type, *filename, *conf_file;
    struct strtag taglist[] = {
          { "mime-before", 11, NULL }
        , { "mime-after" , 10, NULL }
        , { "file-before", 11, NULL }
        , { "file-after" , 10, NULL }
    };
    safety_flag = 0;

    // sendercheckがOKの場合は、safetysenderharmlessconfを見るようにする
    if (arg->sendercheck < 1) {
        conf_file = arg->cfg->cf_harmlessconf;
    } else {
        conf_file = arg->cfg->cf_safetysenderharmlessconf;
    }

    command_list_t *c_p;
    command_list_t *command_list = conf_file;

    // convert_alternativeを通過していたら、取得したMIMEタイプを使用
    // 通過していない場合、メール本文から取得
    if (arg->mime_extension != NULL) {
        content_type = arg->mime_extension;
    } else {
        GMimeContentType *top_content_type_object = g_mime_object_get_content_type(part);
        content_type = g_mime_content_type_to_string(top_content_type_object);
    }

    if (content_type == NULL) {
        log("Content-Type is missing.");
        return HARMLESS_NG;
    }

    taglist[MIME_BEFORE].st_str = content_type;
    taglist[FILE_BEFORE].st_str = filename = estimate_filename(part);

    // mimeタイプ判定のループ
    for (c_p = command_list; c_p != NULL; c_p = c_p->next) {
        // 元のMIMEタイプと受信メールのMIMEタイプが一致したら0でif文に入らない
        // 元のMIMEタイプに*が指定されていた場合はif文に入らない
        // 違っていたら入る
        if ((strcasecmp(c_p->mime_before, "*") != 0) && (strcasecmp(c_p->mime_before, content_type) != 0)) {
            continue;
        }

        switch (c_p->command_type) {
            int _ret = 0;
            case FUNCTION:
                _ret = (c_p->in_func)(part, new, arg);
                if (_ret == HARMLESS_NG) {
                    if (arg->mime_extension != NULL) {
                        output_conv_log(CONV_ERR_EXEC_IN, c_p->command_name, arg->maildata);
                    }
                    free(content_type);
                    return HARMLESS_NG;
                } else if (_ret == NO_MATCH_EXTENSION) {
                    continue;
                }
                break;
            case COMMAND:
                DEBUGLOG("case COMMMAND");
                // ファイル名を環境変数に設定
                if (setenv(ENV_FILENAME, filename, 1) != 0) {
                    output_conv_log(CONV_ERR_EXEC_ENV, c_p->command_name, arg->maildata);
                    free(content_type);
                    return HARMLESS_NG;
                }

                _ret = exec_command_with_gmime(part, new, c_p->arg_list, arg, c_p->msg_next);
                if (_ret == HARMLESS_NG) {
                    free(content_type);
                    return HARMLESS_NG;
                }
                // mimetypeを更新
                if (GMIME_IS_OBJECT(*new) && strcmp(c_p->mime_after, "-")) {
                    GMimeContentType *newtype = g_mime_content_type_new_from_string(c_p->mime_after);
                    g_mime_object_set_content_type((GMimeObject *)*new, newtype);
                    g_object_unref(newtype);
                }
                // safetysenderharmless.confのMIMEtypeにマッチした
                safety_flag = 1;
                break;
        }

        // チェック関数が実行されたら以下をやってから処理を抜ける
        // ファイル名に拡張子をつける
        {
            char *newfilename = NULL;
            if (*filename != '\0') {
                newfilename =  malloc(
                    strlen(filename)
                    + strlen(c_p->file_extension)
                    + 1
                );
                if (newfilename == NULL) {
                    free(content_type);
                    return HARMLESS_NG;
                }
                sprintf(
                    newfilename,
                    "%s%s",
                    filename,
                    c_p->file_extension
                );
                taglist[FILE_AFTER].st_str = newfilename;
            } else {
                taglist[FILE_AFTER].st_str = taglist[FILE_BEFORE].st_str = arg->cfg->cf_attachmentfilealias;
            }

            taglist[MIME_AFTER].st_str = c_p->mime_after;

            // 渡された構造体のメッセージ抑制フラグを確認
            if (c_p->msg_restraint == MSG_NO_RESTRAIN) {
                ret = strcat_proc_message(
                    &(arg->message),
                    &(arg->message_length),
                    arg->cfg->cf_harmlessmessageconvert,
                    taglist,
                    4
                );
            } else {
                // メッセージ抑制の場合、retにOKの値を入れる
                ret = HARMLESS_OK;
            }

            free(content_type);
            if (newfilename != NULL) {
                //g_mime_part_set_filename((GMimePart *)*new, (const char *)newfilename);
                g_mime_object_set_content_type_parameter((GMimeObject *)*new, "filename", newfilename);
                g_mime_object_set_content_disposition_parameter((GMimeObject *)*new, "filename", newfilename);
                free(newfilename);
            }
            return ret;
        }
    }

    // ループが回りきったということは、指定されていないMimeタイプだった
    log("content-type(%s) is not in 'harmless.conf'", content_type);
    free(content_type);
    return HARMLESS_NG;
}

int convert_alternative(GMimeObject *part, GMimeObject **new, harmless_proc_arg_t *arg)
{
    int index, i;
    int alt_part = -1;
    char *conf_file;
    char *content_type = NULL;
    GMimeMultipart *top;

    // sendercheckがOKの場合は、safetysenderharmlessconfを見るようにする
    if (arg->sendercheck < 1) {
        conf_file = arg->cfg->cf_harmlessconf;
    } else {
        conf_file = arg->cfg->cf_safetysenderharmlessconf;
    }

    command_list_t *cp;
    //command_list_t *clist = arg->cfg->cf_harmlessconf;
    command_list_t *clist = conf_file;

    if (!GMIME_IS_MULTIPART(part)) {
        return HARMLESS_NG;
    }

    // いちいちキャストがめんどくさいので変数で受ける
    top = (GMimeMultipart *)part;

    index = g_mime_multipart_get_count(top);

    for (i = 0; i < index; i++) {
        GMimeObject *target = NULL;
        GMimeContentType *content_type_object = NULL;

        target = g_mime_multipart_get_part(top, i);

        // dont free this
        content_type_object = g_mime_object_get_content_type(target);

        content_type = g_mime_content_type_to_string(content_type_object);
        if (content_type == NULL) {
            continue;
        }

        // 最初に見つかったtext/plainを処理して返す
        if (!strcasecmp(content_type, "text/plain")) {
            int ret;
            // HARMLESS_OK or NG
            ret = harmless_proc_single_part(target, new, arg);
            return ret;
        }

        // text/plainに変換出来るものかどうかをチェック.
        // もう見つかっていたら更新しない.
        // もし見つかっても、この先にtext/plainがあるかもしれないので
        // ループを続ける
        if (alt_part == -1) {
            for (cp = clist; cp != NULL; cp = cp->next) {
                if (strcasecmp(content_type, cp->mime_before)) {
                    continue;
                }

                if (strcasecmp(cp->mime_after, "text/plain")) {
                    continue;
                }

                alt_part = i;
            }
        }
    }

    if (alt_part != -1) {
        GMimeObject *target;

        target = g_mime_multipart_get_part(top, alt_part);
        return harmless_proc_single_part(target, new, arg);
    }

    log("Alternative part has no convert-able part to text/plain.");
    return HARMLESS_NG;
}

int convert_multipart(GMimeObject *part, GMimeObject **new, harmless_proc_arg_t *arg)
{
    int ret;

    if (!GMIME_IS_MULTIPART(part)) {
        return HARMLESS_NG;
    }

    ret = harmless_proc((GMimeMultipart *)part, arg);
    if (ret != HARMLESS_OK) {
        return ret;
    }

    // OKだったら加工されたパートを返す
    *new = part;

    return HARMLESS_OK;
}

int convert_none(GMimeObject *part, GMimeObject **new, harmless_proc_arg_t *arg)
{
    *new = part;
    return HARMLESS_OK;
}

/**
 * convert_extension (add 20170126)
 *     arg->cfg->cf_mimetypesと添付ファイルの拡張子を比較し、
 *     extensionコマンドを除き再びmsg_convert関数へ渡す
 */
int convert_extension(GMimeObject *part, GMimeObject **new, harmless_proc_arg_t *arg)
{
    mimetype_list_t *m_p, *mime_list = arg->cfg->cf_mimetypes;
    char *attachment_extension;
    const char *filename;
    int res, ret = 0;

    /* argのMaxExtensionDepthの検査 */
    if (arg->used_extension == USED_EXTENSION) {
        log(ERR_REPEAT_EXTENSION, arg->mime_extension);
        return HARMLESS_NG;
    }

    /* 添付ファイル名を取得 */
    filename = estimate_filename(part);

    /* 添付ファイル名の有無を判断 */
    if (filename[0] != '\0') {
        /* 拡張子を取得 */
        attachment_extension = strrchr(filename, '.');

        if (attachment_extension == NULL || 
            strcmp(attachment_extension, ".") == 0) {
            /* 拡張子が無ければ次のharmless.confの行の処理へ  */
            log(NOT_FOUND_EXTENSION, filename);
            return NO_MATCH_EXTENSION;
        }

        /* ドット以降を取得 */
        attachment_extension++;

    } else {
        /* ファイル名が無ければ次のharmless.confの行の処理へ */
        log(NOT_FOUND_FILENAME);
        return NO_MATCH_EXTENSION;
    }

    /* 拡張子を検索する */
    for (m_p = mime_list; m_p != NULL; m_p = m_p->next) {
        res = strcmp(m_p->extension, attachment_extension);
        if (res == 0) {
            /* 拡張子が一致したら定義されたMIMEタイプを取得 */
            arg->mime_extension = strdup(m_p->mimetype);
            if (arg->mime_extension == NULL) {
                log(EXTE_ERR_MEM);
                return HARMLESS_NG;
            }
            break;
        }
    }

    /* 拡張子の一致がなければ次のharmless.confの行の処理へ */
    if (arg->mime_extension == NULL) {
        log(NO_EXTENSION_INMIME, filename);
        return NO_MATCH_EXTENSION;
    }

    /* argにextensionコマンドを通ったフラグを立てる */
    arg->used_extension = USED_EXTENSION;

    /* msg_convertに変更を加えた構造体を渡す */
    ret = msg_convert(part, new, arg);

    /* 構造体を渡してしまったのでMIMEタイプとフラグを元に戻す */
    arg->mime_extension = NULL;
    arg->used_extension = 0;

    /* 再処理した結果を返す */
    return ret;
}

/*
 * exec_command_with_gmime()
 */
int exec_command_with_gmime(GMimeObject *part, GMimeObject **new, char **cmd_arg, harmless_proc_arg_t *arg, int msg_next)
{
    char *after = NULL;
    size_t aftersize;

    if (!GMIME_IS_PART(part)) {
        log("exec_command_with_gmime: Given part is not a single part");
        return HARMLESS_NG;
    }


    int eret = exec_external(part, cmd_arg, &after, &aftersize, arg->maildata, arg->cfg->cf_harmlesscommandtimeout, msg_next);

    if (eret != EXEC_EXTERNAL_SUCCESS) {
        return HARMLESS_NG;
    }


    GMimeStream *r_stream = g_mime_stream_mem_new_with_buffer(after, aftersize);
    free(after);
    GMimeStream *f_r_stream = g_mime_stream_filter_new(r_stream);
    g_object_unref(r_stream);


    GMimeContentEncoding enctype = g_mime_part_get_content_encoding((GMimePart *)part);

    GMimeFilter *r_filter = g_mime_filter_basic_new(enctype, TRUE);
    g_mime_stream_filter_add((GMimeStreamFilter *)f_r_stream, r_filter);
    g_object_unref(r_filter);

    GMimeDataWrapper *converted = g_mime_data_wrapper_new_with_stream(f_r_stream, enctype);
    g_object_unref(f_r_stream);

    g_mime_part_set_content_object((GMimePart *)part, converted);
    g_object_unref(converted);

    *new = part;
    return HARMLESS_OK;
}
