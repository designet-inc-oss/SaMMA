/*
 * samma
 * msg_encrypt.c
 *
 * encrypt
 */



#include <string.h>
#include <stdlib.h>
#include <libdgstr.h>
#include <libdgmail.h>

#include <gmime/gmime.h>

#include "zipconv.h"
#include "harmless.h"
#include "msg_encrypt.h"
#include "log.h"



char *make_zip_dir(char *dir);

int msg_encrypt(GMimeObject *part, GMimeObject **new, harmless_proc_arg_t *arg)
{
    //GMimeObject *g_msg;
    //GMimeMessage *g_msg;
    GMimeStream *w_stream;

    int ret = 0, count = 0;
    char *path;
    char *p;
    char *tmpname, *filename;
    char newfilename[PATH_MAX + 1];
    char tmppath[PATH_MAX + 1];
    struct strtag tag = { "filename", 8, NULL };
    int ret_valid = 0;
    char *validatename = NULL;
    char lastFromChar[MAX_STRCODE_LEN]; // expecting strings such as "ISO-2022-JP", "EUC-JP", "SJIS", "UTF-8"
    char *b64_filename = NULL;
    char *b64_tmpname = NULL;
    char *b64_validatename = NULL;

    FILE *wfp;

    filename = estimate_filename(part);
    tag.st_str = filename[0] == '\0' ? arg->cfg->cf_attachmentfilealias : filename;

    // 初めてだったらディレクトリを作る
    if (arg->zipdir == NULL) {
        path = make_zip_dir(arg->cfg->cf_encryptiontmpdir);
        if (path == NULL) {
            return HARMLESS_ERR;
        }
        arg->zipdir = path;
    }

    /*
     * ファイル作成パート
     */
    // /を_に変換
    for (p = filename; *p != '\0'; p++) {
        if (*p == SLASH) {
            *p = SLASH_REPLACE_CHAR;
        }
    }

    if (filename[0] == '\0') {
        tmpname = strdup(arg->cfg->cf_attachmentfilealias);
        if (tmpname == NULL) {
            log(ERR_MEMORY_ALLOCATE, "msg_encrypt", "tmpname(66)", strerror(errno));
            return HARMLESS_ERR;
        }
    } else {
        /* convert str code */
        ret_valid = dg_str2code_replace_validate(filename, &tmpname, STR_UTF8, 
                        arg->cfg->cf_strcode, &validatename, lastFromChar, MAX_STRCODE_LEN);
        if (ret_valid != 0) {
        /* When the str code conversion failed. */
            if (ret_valid == 2) {
                // logging failure of reversal conversion validation.
                b64_filename = encode_b64(filename);
                b64_tmpname = encode_b64(tmpname);
                b64_validatename = encode_b64(validatename);
                log(ERR_CONVERT_VALIDATION, b64_filename, 
                    b64_tmpname, b64_validatename, 
                    lastFromChar, arg->cfg->cf_strcode);
                free(b64_filename);
                free(b64_tmpname);
                free(b64_validatename);
            }

            tmpname = strdup(arg->cfg->cf_attachmentfilealias);
            if (tmpname == NULL) {
                log(ERR_MEMORY_ALLOCATE, "msg_encrypt", "tmpname", strerror(errno));
                return HARMLESS_ERR;
            }

            log(ERR_CHARCODE_CONVERT, "msg_encrypt");
        }
        if (validatename != NULL) {
            free(validatename);
        }
    }

    mk_new_filename(newfilename, tmpname, arg->zipdir, count);
    free(tmpname);

    snprintf(tmppath, PATH_MAX, FILE_PATH, arg->zipdir, newfilename);

    // ファイルに書き出し
    wfp = fopen(tmppath, "w");
    if (wfp == NULL) {
        log(ERR_FILE_OPEN, "msg_encrypt", tmppath);
        return HARMLESS_ERR;
    }
    w_stream = g_mime_stream_file_new(wfp);

    if (GMIME_IS_PART(part)) {
        GMimeDataWrapper *wrapper = g_mime_part_get_content_object((GMimePart *)part);
        g_mime_data_wrapper_write_to_stream(wrapper, w_stream);
        g_object_unref (w_stream);
    } else {
        ret = g_mime_object_write_to_stream(part, w_stream);
        g_object_unref (w_stream);
    }

    if (ret < 0) {
        log(ERR_GMIME, "msg_encrypt", "g_mime_data_wrapper_write_to_stream");
        return HARMLESS_ERR;
    }

    return strcat_proc_message(
        &(arg->message),
        &(arg->message_length),
        arg->cfg->cf_harmlessmessageencrypt,
        &tag,
        1
    );
}

char *make_zip_dir(char *dir)
{
    int len;
    char *tmpstr, *tmp, *final;

    len = strlen(dir) + strlen(TMPDIR_TMPL) + 2;
    tmpstr = (char *)malloc(len);
    if (tmpstr == NULL) {
        log(ERR_MEMORY_ALLOCATE, "make_zip_dir", "tmpstr", strerror(errno));
        return NULL;
    }

    snprintf(tmpstr, len, FILE_PATH, dir, TMPDIR_TMPL);

    tmp = mkdtemp(tmpstr);
    if (tmp == NULL) {
        log(ERR_DIRECTORY_MAKE, "parse_mail", tmp, strerror(errno));
        free(tmpstr);
        return NULL;
    }


    final = strdup(tmp);
    if (final == NULL) {
        log(ERR_MEMORY_ALLOCATE, "make_zip_dir", "tmpstr", strerror(errno));
        free(tmpstr);
        return NULL;
    }

    free(tmpstr);
    return final;
}
