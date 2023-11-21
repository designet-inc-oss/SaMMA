/*
 * Mail Utility Library
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <iconv.h>
#include <errno.h>

#include <libdgstr.h>
#include "libdgmail.h"

/*--- static関数宣言 ---*/

static int euc_str_divide(char *, char *, int);
static int encode_mime_one_line(struct strset *, char *, int);

/*--- 外部変数 ---*/

/* Basic BASE64 conversion table */
char base64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*--- 関数 ---*/

/*
 * get_field
 *
 * 機能
 *	ヘッダの値を取得する
 *
 * 引数
 *	char  *buftop	フィールドの先頭
 *	char **nadr	次のヘッダへのポインタ
 *
 * 返り値
 *	NULL		アロケートエラー             
 *	rstr		ヘッダの値
 */
char *
get_field(char *buftop, char **nadr)
{
    char   *rstr = NULL;        /* encoded string */
    char   *ptr, *tptr;         /* work pointer */
    int     rsize = 1;          /* total size of encoded string */
    int     len;
    int     i;

    rstr = (char *) malloc(1);
    if (rstr == NULL) {
        return NULL;
    }
    *rstr = '\0';
    /* Retrieve lines without LWSP at the top of the line */
    ptr = buftop;
    while (1) {
        tptr = strchr(ptr, '\n');
        len = (tptr != NULL) ? (tptr - ptr) : strlen(ptr);
        /* remove '\r' */
        if (len > 0 && *(ptr + len - 1) == '\r') {
            len--;
        }
        /* Delete LWSP */
        for (i = 0; i < len; i++) {
            if (isblank(*(ptr + i)) == 0) {
                break;
            }
        }
        ptr += i;
        /* Copy the line */
        rsize += len - i;
        rstr = (char *) dg_realloc(rstr, rsize);
        if (rstr == NULL) {
            return NULL;
        }
        rstr = strncat(rstr, ptr, len - i);

        if (tptr == NULL || isblank(*(tptr + 1)) == 0) {
            break;
        }
        ptr = tptr + 1;
    }
    *nadr = (tptr == NULL) ? NULL : (tptr + 1);

    return rstr;
}

/*
 * get_subject
 *
 * 機能
 *	メールのサブジェクトを取り出す
 *
 * 引数
 *	char  *buftop	フィールドの先頭
 *	char **nadr	次のヘッダへのポインタ
 *	char **rstr	MIMEデコードされる前のサブジェクトヘッダの値
 *
 * 返り値:
 *  NULL		アロケートエラー
 *  dstr		MIMEデコードされたヘッダの値
 */
char *
get_subject(char *buftop, char **nadr, char **rstr)
{
    char   *dstr = NULL;

    *rstr = get_field(buftop, nadr);
    if (*rstr == NULL) {
        return NULL;
    }

    /* decode MIME */
    dstr = decode_mime(*rstr);
    if (dstr == NULL) {
        free(*rstr);
        return NULL;
    }
    return dstr;
}

/*
 * decode_mime
 *
 * 機能
 *	MIMEデコード
 *
 * 引数
 *	char *sstr	エンコードされた文字列
 *
 * 返り値
 *	NULL		アロケートエラー
 *	retbuf_addr	MIMEデコードされた文字列
 */
char *
decode_mime(char *sstr)
{
    char   *decbuf = NULL;
    char   *trbuf = NULL;
    char   *wbuf = NULL;
    char   *retbuf = NULL;
    char   *retbuf_addr = NULL;
    char   *ptr;
    int     ret;
    int     emime_flag = 0;
    char   *pretbuf = NULL;
    int     rbsize = 0;
    int     tmplen;

    /* Allocate memory */
    rbsize = strlen(sstr);
    retbuf_addr = retbuf = (char *) malloc(rbsize + 1);
    if (retbuf_addr == NULL) {
        /* error */
        return NULL;
    }
    *retbuf = '\0';

    /* Copy string */
    wbuf = (char *) malloc(strlen(sstr) + 1);
    if (wbuf == NULL) {
        /* error */
        free(retbuf_addr);
        return NULL;
    }
    strcpy(wbuf, sstr);

    ptr = wbuf;

    while (*ptr != '\0') {
        if (*ptr == '=' && *(ptr + 1) == '?') {
            char   *subptr, *mimeend, *tmpptr;
            int     skiplen;
            int     bqflag;
            int     codeflag;

            subptr = ptr + 2;
            /* Decode MIME (JIS+BASE64) */
            if (!strncasecmp(subptr, MIME_JISB_STR, 14) &&
                (mimeend = strstr(subptr + 14, "?="))) {
                skiplen = 14;
                bqflag = BQ_B64;
                codeflag = CODE_JIS;
                /* Decode MIME (JIS+QP) */
            } else if (!strncasecmp(subptr, MIME_JISQ_STR, 14) &&
                       (mimeend = strstr(subptr + 14, "?="))) {
                skiplen = 14;
                bqflag = BQ_QP;
                codeflag = CODE_JIS;
                /* Decode MIME (SJIS+BASE64) */
            } else if (strncasecmp(subptr, MIME_SJISB_STR, 12) == 0 &&
                       (mimeend = strstr(subptr + 12, "?="))) {
                skiplen = 12;
                bqflag = BQ_B64;
                codeflag = CODE_SJIS;
                /* Decode MIME (SJIS+QP) */
            } else if (strncasecmp(subptr, MIME_SJISQ_STR, 12) == 0 &&
                       (mimeend = strstr(subptr + 12, "?="))) {
                skiplen = 12;
                bqflag = BQ_QP;
                codeflag = CODE_SJIS;
                /* Decode MIME (EUC+BASE64) */
            } else if (strncasecmp(subptr, MIME_EUCB_STR, 9) == 0 &&
                       (mimeend = strstr(subptr + 9, "?="))) {
                skiplen = 9;
                bqflag = BQ_B64;
                codeflag = CODE_EUC;
                /* Decode MIME (EUC+QP) */
            } else if (strncasecmp(subptr, MIME_EUCQ_STR, 9) == 0 &&
                       (mimeend = strstr(subptr + 9, "?="))) {
                skiplen = 9;
                bqflag = BQ_QP;
                codeflag = CODE_EUC;
            } else if ((tmpptr = strstr(subptr, "?B?")) &&
                       (mimeend = strstr(tmpptr, "?="))) {
                skiplen = tmpptr - subptr + 3;
                bqflag = BQ_B64;
                codeflag = CODE_UNKNOWN;
            } else if ((tmpptr = strstr(subptr, "?Q?")) &&
                       (mimeend = strstr(tmpptr, "?="))) {
                skiplen = tmpptr - subptr + 3;
                bqflag = BQ_QP;
                codeflag = CODE_UNKNOWN;
            } else {
                /* It isn't MIME part */
                if (retbuf - retbuf_addr == rbsize) {
                    ALLOC_RETBUF(BUFSIZE);
                    if (retbuf_addr == NULL) {
                        free(wbuf);
                        return NULL;
                    }
                }
                *retbuf++ = *ptr++;
                emime_flag = 0;
                continue;
            }

            /* NULL terminate at the end of MIME part */
            *mimeend = '\0';

            /* Decode Encode */
            switch (bqflag) {
            case BQ_B64:
                ret = decode_b64(subptr + skiplen, &decbuf);
                break;
            case BQ_QP:
                ret = decode_qp(subptr + skiplen, &decbuf);
                break;
            }
            if (decbuf == NULL) {
                if (ret > 0) {
                    *mimeend = '?';
                    if (retbuf - retbuf_addr == rbsize) {
                        ALLOC_RETBUF(BUFSIZE);
                        if (retbuf_addr == NULL) {
                            free(wbuf);
                            return NULL;
                        }
                    }
                    *retbuf++ = *ptr++;
                    emime_flag = 0;
                    continue;
                } else {
                    /* memory error */
                    free(retbuf_addr);
                    free(wbuf);
                    return NULL;
                }
            }

            /* Translate to JIS */
            if (!check_7bit(decbuf)) {
                /* JIS or 7bit encoding */
                trbuf = strdup(decbuf);
                if (trbuf == NULL) {
                    /* memory error */
                    free(retbuf_addr);
                    free(wbuf);
                    free(decbuf);
                    return NULL;
                }
            } else {
                /* Translate to JIS */
                switch (codeflag) {
                case CODE_JIS:
                case CODE_UNKNOWN:
                    ret = jis2jis_iconv(decbuf, &trbuf);
                    break;
                case CODE_EUC:
                    ret = euc2jis_iconv(decbuf, &trbuf);
                    break;
                case CODE_SJIS:
                    ret = sjis2jis_iconv(decbuf, &trbuf);
                    break;
                }
            }

            if (trbuf == NULL) {
                if (ret > 0) {
                    *mimeend = '?';
                    if (retbuf - retbuf_addr == rbsize) {
                        ALLOC_RETBUF(BUFSIZE);
                        if (retbuf_addr == NULL) {
                            free(wbuf);
                            free(decbuf);
                            return NULL;
                        }
                    }
                    *retbuf++ = *ptr++;
                    free(decbuf);
                    emime_flag = 0;
                    continue;
                } else {
                    /* memory error */
                    free(retbuf_addr);
                    free(wbuf);
                    free(decbuf);
                    return NULL;
                }
            }

            if (emime_flag) {
                retbuf = pretbuf;
            }
            tmplen = strlen(trbuf);
            if (retbuf - retbuf_addr + tmplen > rbsize) {
                ALLOC_RETBUF(tmplen);
                if (retbuf_addr == NULL) {
                    free(wbuf);
                    free(decbuf);
                    free(trbuf);
                    return NULL;
                }
            }
            strcpy(retbuf, trbuf);
            retbuf += strlen(trbuf);
            emime_flag = 1;
            pretbuf = retbuf;
            ptr = mimeend + 2;
            free(decbuf);
            free(trbuf);

            continue;

        } else {
            if (!isblank(*ptr)) {
                emime_flag = 0;
            }
            if (retbuf - retbuf_addr == rbsize) {
                ALLOC_RETBUF(BUFSIZE);
                if (retbuf_addr == NULL) {
                    free(wbuf);
                    return NULL;
                }
            }
            *retbuf++ = *ptr++;
            continue;
        }
    }

    *retbuf = '\0';
    free(wbuf);

    /* convert if the subject seems JIS */
    if (strchr(retbuf_addr, 0x1b) != NULL) {
        /* it seems JIS */
        ret = jis2euc_iconv(retbuf_addr, &trbuf);
        if (trbuf == NULL) {
            if (ret < 0) {
                /* memory error */
                free(retbuf_addr);
                free(decbuf);
                return NULL;
            }
        } else {
            /* It was JIS string. Change return buffer */
            free(retbuf_addr);
            retbuf_addr = trbuf;
        }
        trbuf = NULL;
        ret = euc2sjis_iconv(retbuf_addr, &trbuf);
        if (trbuf == NULL) {
            if (ret < 0) {
                /* memory error */
                free(retbuf_addr);
                free(decbuf);
                return NULL;
            }
        } else {
            /* It was JIS string. Change return buffer */
            free(retbuf_addr);
            retbuf_addr = trbuf;
        }
    } else {
        ret = euc2sjis_iconv(retbuf_addr, &trbuf);
        if (trbuf != NULL) {
            /* It was JIS string. Change return buffer */
            free(retbuf_addr);
            retbuf_addr = trbuf;
        }
    }
    return (retbuf_addr);
}

/*
 * check_7bit
 *
 * 機能
 *	7bit文字のチェック
 *
 * 引数
 *	char *str	チェックする文字列
 *
 * 返り値 
 *	0		8ビットの文字列ではない
 *	1		8ビットの文字列である
 */
int
check_7bit(char *str)
{
    int     i;

    for (i = 0; *(str + i) != '\0'; i++) {
        if (*(str + i) & 0x80) {
            /* Found 8-bit charactor */
            return 1;
        }
    }
    return 0;
}

/*
 * decode_qp
 *
 * 機能
 *	quoted printableのデコード
 *
 * 引数
 *	char  *src_buf	デコードしたい文字列
 *	char **ret_buf	デコードされ、アロケートされた文字列
 *
 * 返り値
 *	 0		成功
 *	>0		デコードエラー
 *	<0		メモリエラー
 */
int
decode_qp(char *src_buf, char **ret_buf)
{
    char   *src = src_buf;
    char   *dst, *dst_buf;
    int     c, d1 = 0, d2 = 0;
    int     state = STATE_NORMAL;

    if ((dst_buf = (char *) malloc(strlen(src_buf) + 1)) == NULL) {
        /* error */
        *ret_buf = NULL;
        return -1;
    }
    dst = dst_buf;

    while ((c = *src++) != '\0') {
        switch (state) {
        case STATE_NORMAL:
            if (c == '=') {
                state = STATE_QUOTE1;
            } else {
                *dst++ = c;
            }
            break;
        case STATE_QUOTE1:
            switch (c) {
            case '\r':
                break;
            case '\n':
                state = STATE_NORMAL;
                break;
            default:
                if ((d1 = hex2i(c)) < 0) {
                    free(dst_buf);
                    *ret_buf = NULL;
                    return 1;
                }
                state = STATE_QUOTE2;
                break;
            }
            break;
        case STATE_QUOTE2:
            if ((d2 = hex2i(c)) < 0) {
                free(dst_buf);
                *ret_buf = NULL;
                return 1;
            }
            *dst++ = (d1 << 4) | d2;
            state = STATE_NORMAL;
            break;
        }
    }

    if (state != STATE_NORMAL) {
        free(dst_buf);
        *ret_buf = NULL;
        return 1;
    }

    *dst = '\0';
    *ret_buf = dst_buf;
    return 0;
}

/*
 * hex2i
 *
 * 機能
 *	16進数の文字を整数値に変換。
 *
 * 引数
 *	int c	変換する16進数
 *
 * 返り値
 *	-1以外	変換後の整数値
 *	-1	エラー
 */
int
hex2i(int c)
{
    int     d;

    if (c >= '0' && c <= '9') {
        d = c - '0';
    } else if (c >= 'A' && c <= 'Z') {
        d = c - 'A' + 10;
    } else if (c >= 'a' && c <= 'z') {
        d = c - 'a' + 10;
    } else {
        d = -1;
    }

    return d;
}

/*
 * decode_b64
 *
 * 機能
 *	Base64のデコード
 *
 * 引数
 *	char  *src_buf	デコードしたい文字列
 *	char **ret_buf	デコードされ、アロケートされた文字列
 *
 * 返り値
 *	 0		成功
 *	>0		デコードエラー
 *	<0		メモリエラー
 */
int
decode_b64(char *src_buf, char **ret_buf)
{
    char   *src = src_buf;
    char   *dst, *dst_buf;
    int     c, d[4];
    int     i = 0;

    if ((dst_buf = (char *) malloc(strlen(src_buf) + 1)) == NULL) {
        *ret_buf = NULL;
        return -1;
    }
    dst = dst_buf;

    while ((c = *src++) != '\0') {
        if (c == '=' || c == '?') {
            break;
        } else if (!isspace(c)) {
            d[i] = b64char2i(c);
            if (d[i] < 0) {
                free(dst_buf);
                *ret_buf = NULL;
                return 1;
            }
            switch (i) {
            case 1:
                *dst++ = d[0] << 2 | d[1] >> 4;
                break;
            case 2:
                *dst++ = (d[1] << 4 | d[2] >> 2) & 0xff;
                break;
            case 3:
                *dst++ = (d[2] << 6 | d[3]) & 0xff;
                break;
            }
            i = (i + 1) & 0x03;
        }
    }

    *dst = '\0';
    *ret_buf = dst_buf;
    return 0;
}

/*
 * encode_b64
 *
 * 機能
 *	Base64のエンコード
 *
 * 引数
 *	char  *str	エンコードしたい文字列
 *
 * 返り値
 *	bstr		エンコードした文字列
 *	NULL		アロケートエラー
 */
char *
encode_b64(char *str)
{
    int     cnt = 0;
    int     bcnt = 0;
    char   *bstr = NULL;
    int     rlen;
    int     blen;

    rlen = strlen(str);
    blen = (int) (rlen * 4 / 3);
    if (rlen % 3)
        blen++;
    blen += (4 - (blen % 4));

    bstr = (char *) malloc(blen + 1);
    if (bstr == NULL) {
        return NULL;
    }

    for (cnt = 0; cnt < rlen; cnt += 3) {
        switch (rlen - cnt) {
        case 1:
            bstr[bcnt] = base64[(str[cnt] >> 2) & 0x3f];
            bstr[bcnt + 1] = base64[(str[cnt] & 0x3) << 4];
            bcnt += 2;
            for (; bcnt < blen; bcnt++) {
                bstr[bcnt] = '=';
            }
            break;
        case 2:
            bstr[bcnt] = base64[(str[cnt] >> 2) & 0x3f];
            bstr[bcnt + 1] =
                base64[((str[cnt] & 0x03) << 4) +
                    ((str[cnt + 1] >> 4) & 0x0f)];
            bstr[bcnt + 2] = base64[(str[cnt + 1] & 0x0f) << 2];
            bcnt += 3;
            for (; bcnt < blen; bcnt++) {
                bstr[bcnt] = '=';
            }
            break;
        default:
            bstr[bcnt] = base64[(str[cnt] >> 2) & 0x3f];
            bstr[bcnt + 1] =
                base64[((str[cnt] & 0x03) << 4) +
                    ((str[cnt + 1] >> 4) & 0x0f)];
            bstr[bcnt + 2] =
                base64[((str[cnt + 1] & 0x0f) << 2) +
                    ((str[cnt + 2] >> 6) & 0x03)];
            bstr[bcnt + 3] = base64[str[cnt + 2] & 0x3f];
            bcnt += 4;
            break;
        }
    }
    bstr[bcnt] = '\0';
    return bstr;
}

/*
 * b64char2i
 *
 * 機能
 *	Base64エンコード文字を値に変換
 *
 * 引数
 *	int c	変換したい文字 
 *
 * 返り値
 *	-1以外	変換後の整数値
 *	-1	エラー
 */
int
b64char2i(int c)
{
    int     d;

    if (c >= 'A' && c <= 'Z') {
        d = c - 'A' + 0;
    } else if (c >= 'a' && c <= 'z') {
        d = c - 'a' + 26;
    } else if (c >= '0' && c <= '9') {
        d = c - '0' + 52;
    } else if (c == '+') {
        d = 62;
    } else if (c == '/') {
        d = 63;
    } else {
        d = -1;
    }

    return d;
}

/*
 * get_addrpart_real
 *
 * 機能
 *	メールアドレス部の取得。
 * 	"name <address>'' または "address (name)'' または"address"の形式。
 *
 * 引数
 *	unsigned char *str	メールアドレス関連ヘッダの値
 *	int translateflg	TRANSLATE:小文字に変換する
 *				NOTRANSLATE:小文字に変換しない
 *
 * 返り値
 *	bstr			メールアドレス文字列
 *	NULL			アロケートエラー
 */
char *
get_addrpart_real(unsigned char *str, int translateflg)
{
    int mode = MODE_0;
    int len = strlen(str);
    int i;
    int astart = -1;
    int aend = -1;
    int nstart = -1;
    int nend = -1;
    int bstart = -1;
    int amode = ADD_ASIS;
    int start = 0, end = 0;
    unsigned char *addr = NULL;
    int nlen;

    /* allocate enough size buffer */
    addr = (char *)malloc(len + 1);
    if (addr == NULL) {
        /* error */
        return NULL;
    }
    /* search <, >, (, or ) charactors */
    for (i = 0; i < len; i ++) {
        if (mode == MODE_0) {
            /* skip blank charactors begining of the line */
            if (isspace(str[i]) == 0) {
                mode = MODE_N;
                bstart = i;
            } else {
                continue;
            }
        }
        if (str[i] == '\\') {
            /* case \ */
            switch (mode) {
            case MODE_Q:
                /* quote char */
                mode = MODE_QS;
                continue;
            case MODE_S:
                /* need to escape char */
                mode = MODE_N;
                continue;
            case MODE_QS:
                /* need to escape char during quoted string */
                mode = MODE_S;
                continue;
            default:
                /* normal mode */
                mode = MODE_S;
                continue;
            }
        }
        if (mode == MODE_S) {
            /* case need to escape char */
            mode = MODE_N;
            continue;
        }
        if (mode == MODE_QS) {
            /* case need to escape char during quoted string */
            mode = MODE_Q;
            continue;
        }
        if (mode == MODE_Q) {
            /* ignore dquote char during quoted string */
            if (str[i] == '"') {
                mode = MODE_N;
            }
            continue;
        }

        /* normal mode below */

        if (str[i] == '"') {
            /* turn into quoted mode */
            mode = MODE_Q;
            continue;
        }
        if (str[i] == '<') {
            /* find < char */
            if (astart != -1) {
                /* ignore if < char exists leftside */
                continue;
            }
            astart = i;
            continue;
        }
        if (str[i] == '>') {
            /* find > char */
            if (astart == -1) {
                /* ignore if < char doesn't exist leftside */
                continue;
            }
            aend = i;
            continue;
        }
        if (str[i] == '(') {
            /* find ( char */
            if (nstart != -1) {
                /* ignore if ( char exists leftside */
                continue;
            }
            nstart = i;
            continue;
        }
        if (str[i] == ')') {
            /* find ) char */
            if (nstart == -1) {
                /* ignore if ( char doesn't exist leftside */
                continue;
            }
            nend = i;
            continue;
        }
    }

    /* return empty string if there is no mail address string */
    if (bstart == -1) {
        addr[0] = '\0';
        return addr;
    }

    /* check escape mode */
    if (mode != MODE_N) {
        /* mode is ASIS: still escape mode */
        amode = ADD_ASIS;
    }

    /* check <> and () pairs at the same line */
    else if (astart != -1 && nstart != -1) {
        /* mode is ASIS: both < and ( chars exists */
        amode = ADD_ASIS;
    }

    /* check <> pair */
    else if (astart != -1 && aend != -1) {
        /* check chars behind > char */
        for (i = aend + 1; i < len; i ++) {
            if (isspace(str[i]) == 0) {
                break;
            }
        }
        if (i != len) {
            /* mode is ASIS: chars exists behind > char */
            amode = ADD_ASIS;
        } else if (astart + 1 == aend) {
            /* return empty string if no mailaddr in <> */
            addr[0] = '\0';
            return addr;
        } else {
            amode = ADD_BRA;
        }
    }

    /* check () pair */
    else if (nstart != -1 && nend != -1) {
        if (nstart == bstart) {
            /* mode is ASIS: ( is at begining of the line */
            amode = ADD_ASIS;
        } else {
            /* check chars behind ) char */
            for (i = nend + 1; i < len; i ++) {
                if (isspace(str[i]) == 0) {
                    break;
                }
            }
            if (i != len) {
                /* mode is ASIS: chars exists behind ) char */
                amode = ADD_ASIS;
            } else {
                amode = ADD_NAME;
            }
        }
    }

    /* determine copy area */
    switch (amode) {
    case ADD_ASIS:
        /* as is: deleted head and tail blanks */
        start = bstart;
        for (i = len - 1; i > bstart; i --) {
            if (isspace(str[i]) == 0) {
                break;
            }
        }
        end = i;
        break;
    case ADD_BRA:
        /* name <address> */
        for (i = astart + 1; i < aend; i ++) {
            if (isspace(str[i]) == 0) {
                break;
            }
        }
        if (i == aend) {
            /* empty address */
            addr[0] = '\0';
            return addr;
        }
        start = i;
        for (i = aend - 1; i > start; i --) {
            if (isspace(str[i]) == 0) {
                break;
            }
        }
        end = i;
        break;
    case ADD_NAME:
        /* address (name) */
        start = bstart;
        for (i = nstart - 1; i > bstart; i --) {
            if (isspace(str[i]) == 0) {
                break;
            }
        }
        end = i;
        break;
    }

    /* copy the string */
    nlen = end - start + 1;
    for (i = 0; i < nlen; i ++) {
        if (translateflg == TRANSLATE) {
            addr[i] = tolower(str[start + i]);
        } else {
            addr[i] = str[start + i];
        }
    }
    addr[i] = '\0';
    return addr;
}

/*
 * get_addrpart
 *
 * 機能
 *	get_addrpart_realを呼び小文字に変換されたメールアドレスを取得。
 *
 * 引数
 *	unsigned char *str	メールアドレス関連ヘッダの値
 *
 * 返り値
 *				メールアドレス文字列
 */
char *
get_addrpart(unsigned char *str)
{
    return get_addrpart_real(str, TRANSLATE);
}

/*
 * get_addrpart_notranslate
 *
 * 機能
 *      get_addrpart_realを呼びメールアドレス部を取得。
 *
 * 引数
 *	unsigned char *str	メールアドレス関連ヘッダの値
 *
 * 返り値
 *				メールアドレス文字列
 */
char *
get_addrpart_notranslate(unsigned char *str)
{
    return get_addrpart_real(str, NOTRANSLATE);
}

/*
 * get_from
 *
 * 機能
 *	Fromヘッダからメールアドレス部を取得する
 *
 * 引数
 *	char  *buftop	メールヘッダの先頭
 *	char **nadr	次のヘッダへのポインタ
 *
 * 返り値
 *	dstr		メールアドレス文字列
 *	NULL		アロケートエラー
 */
char *
get_from(char *buftop, char **nadr)
{
    char   *dstr = NULL;
    char   *rstr = NULL;

    rstr = get_field(buftop, nadr);
    if (rstr == NULL) {
        return NULL;
    }

    dstr = get_addrpart(rstr);
    if (dstr == NULL) {
        free(rstr);
        return NULL;
    }
    free(rstr);
    return dstr;
}

/*
 * encode_mime
 *
 * 機能
 *	EUC文字列をJISに変換した後MIMEエンコードする。
 *
 * 引数
 *	char *str	変換前の文字列
 *	int   len	strの'<メールアドレス>'の直前までの文字数
 *			'<メールアドレス>'がなければstrlen(str)
 * 返り値
 *	ss.ss_str	変換後の文字列
 *	NULL		アロケートエラー
 */
char *
encode_mime(char *str, int len)
{
    char    buf[JIS_STR_MAX_LEN];
    char   *ip;
    char   *op;
    struct strset ss;
    int     ileft;
    size_t  oleft;
    int     ret;
    iconv_t icd;
    int     error;
    int     ptr = 0;
    /* 行単位に分割するための中間バッファ */
    char    str_divide[ENC_STR_DIVIDE_LEN + 2];
    char   *str_divide_tmp;
    size_t  str_divide_len;
    size_t  str_divide_len_tmp;
    int     b64_enc_size;

    strset_init(&ss);

    ip = str;
    if (len < 0) {
        ileft = strlen(str);
    } else {
        ileft = len;
    }

#ifdef SOLARIS
    icd = iconv_open("ISO-2022-JP", "eucJP");
#else
    icd = iconv_open("ISO-2022-JP", "EUC-JP");
#endif
    if (icd == ICONV_ERROR) {
        return (NULL);
    }

    /* 変換済み文字数が変換したい文字数より下ならループ */
    while (ptr < ileft) {
        op = buf;
        oleft = sizeof(buf);

        /* 文字列の分割 */
        str_divide_len = euc_str_divide(ip + ptr, str_divide, ileft - ptr);

        ptr = ptr + str_divide_len;
        str_divide_tmp = str_divide;
        /* 終端の漢字アウト処理のため\0を含む長さに変更 */
        str_divide_len_tmp = str_divide_len + 1;

        /* EUCからJISへ変換 */
        iconv(icd, NULL, NULL, NULL, NULL);
        ret = iconv(icd, &str_divide_tmp, &str_divide_len_tmp, &op, &oleft);

        /* エンコード結果の終端が\0なら1を引く */
        b64_enc_size = sizeof(buf) - oleft;
        if (buf[b64_enc_size - 1] == '\0') {
            b64_enc_size--;
        }

        if (ret == -1) {
            if (errno == E2BIG) {
                /* convert */
                ret = encode_mime_one_line(&ss, buf, b64_enc_size);
                if (ret != 0) {
                    /* memory error */
                    error = errno;
                    strset_free(&ss);
                    iconv_close(icd);
                    errno = error;
                    return (NULL);
                }
                continue;
            } else {
                /* error */
                error = errno;
                strset_free(&ss);
                iconv_close(icd);
                errno = error;
                return (NULL);
            }
        }

        /* convert */
        ret = encode_mime_one_line(&ss, buf, b64_enc_size);
        if (ret != 0) {
            /* error */
            error = errno;
            strset_free(&ss);
            iconv_close(icd);
            errno = error;
            return (NULL);
        }
    }
    iconv_close(icd);

    return (ss.ss_str);
}

/*
 * euc_str_divide
 *
 * 機能
 *	EUCの文字列を分割する関数
 *
 * 引数
 *	char *org_str	コピー元の文字列
 *	char *buf	分割後の文字列
 *	int   rest_len	後何文字変換するかの数
 *
 * 返り値
 *	ptr		コピーした文字数
 */
static int
euc_str_divide(char *org_str, char *buf, int rest_len)
{
    int ptr = 0;

    while (ptr < ENC_STR_DIVIDE_LEN) {

        if (org_str[ptr] == '\0' || rest_len <= ptr) {
            break;
        }

        /* 全角文字ならば */
        if (org_str[ptr] & 0x80) {

            buf[ptr] = org_str[ptr];
            buf[ptr + 1] = org_str[ptr + 1];

            ptr += 2;

        } else {
            /* Ascii文字ならば */
            buf[ptr] = org_str[ptr];
            ptr++;
        }
    }

    buf[ptr] = '\0';

    return (ptr);
}

/*
 * encode_mime_one_line
 *
 * 機能
 *	1行分の文字列をMIMEエンコードする関数
 *
 * 引数
 *	struct strset *ss	MIMEエンコードした文字列を格納
 *	char          *buf	MIMEエンコードする文字列
 *	int            size	MIMEエンコードする文字列の長さ
 *
 * 返り値
 *	-1	アロケートエラー
 *	-2	最大文字数エラー
 *	0	正常
 */
static int
encode_mime_one_line(struct strset *ss, char *buf, int size)
{
    int   ret;
    char *enc_str;

    if (size > B64_MAX_1LINE_SIZE) {
        /* error */
        errno = E2BIG;
        return (-2);
    }

    /* 継続行の場合 */
    if (ss->ss_len > 0) {
        ret = strset_catnstr(ss, "\n\t", 2);
        if (ret < 0) {
            /* memory error */
            return (-1);
        }
    }

    ret = strset_catnstr(ss, MIME_TOPSTR, sizeof(MIME_TOPSTR) - 1);
    if (ret < 0) {
        /* memory error */
        return (-1);
    }

    /* convert */
    enc_str = encode_b64(buf);
    if (enc_str == NULL) {
        /* memory error */
        return (-1);
    }

    ret = strset_catnstr(ss, enc_str, strlen(enc_str));
    free(enc_str);
    if (ret < 0) {
        /* memory error */
        return (-1);
    }

    ret = strset_catnstr(ss, MIME_LASTSTR, sizeof(MIME_LASTSTR) - 1);
    if (ret < 0) {
        /* memory error */
        return (-1);
    }

    return (0);
}

/*
 * get_to
 *
 * 機能
 *	Toヘッダからメールアドレス部を2次元配列に格納する
 *
 * 引数
 *      char   *buftop		フィールドの先頭（To:の次の文字から）
 *      char  **nadr		次のヘッダへのポインタ
 *
 * 返り値:
 *	NULL			アロケートエラー
 *	**addr_array		メールアドレス文字列(二次元配列)(参照変数)
 */
char ** 
get_to(char *buftop, char **nadr)
{
    char   *dstr = NULL;
    char   *rstr = NULL;
    char  **addr_array = NULL;
    int     ret;

    /* 先頭にあるヘッダの値を取得 */
    rstr = get_field(buftop, nadr);
    if (rstr == NULL) {
        return NULL;
    }

    // カンマで分割
    ret = divide_address_list(rstr, &addr_array);
    free(rstr);
    if (ret != 0) {
        return NULL;
    }

    return addr_array;
}

/*
 * divide_address_list
 *
 * 機能
 *	Toヘッダ等の値をカンマで分割
 *
 * 引数
 *	char   *str		フィールドの先頭（To:等の次の文字から）
 *	char ***addr_array	Toヘッダ等の値をカンマで分割後の値
 *				 (二次元配列)(参照変数)
 *
 * 返り値:
 *	-1			アロケートエラー
 *	 0			正常
 */
int
divide_address_list(char *str, char ***addr_array)
{
    char **to_array;
    char **to_array_move;
    char **to_array_addr;
    char **to_array_tmp;
    char **to_array_tmp_move;
    char  *to_start;
    char  *to_ptr;

    int mode;
    int to_array_num;

    // アドレス1個+NULLの分アロケート
    to_array = (char **)malloc(sizeof(char **) * 2);
    if (to_array == NULL) {
        return -1;
    }

    /* カンマがある場合は書式チェック */
    *to_array = NULL;         // 2次元配列にNULLを代入
    *(to_array + 1) = NULL;         // 2次元配列の最後にNULLを代入
    to_array_num = 1;         // 2次元配列の配列の個数
    to_array_addr = to_array; // 2次元配列にaddressを代入する場所を示すポインタ
    mode = MODE_N;            // ノーマルモード("と\と,以外)
    for (to_ptr = to_start = str; *to_ptr != '\0'; to_ptr++) {

        switch (*to_ptr) {
            /* display-nameを示す"の場合 */
            case '"':
            switch (mode) {
                case MODE_N:       // ""内でない場合
                mode = MODE_D;
                break; 

                case MODE_Q:       // ""内でなく直前が\の場合
                mode = MODE_N;
                break; 

                case MODE_D:       // ""内の場合
                mode = MODE_N;
                break;

                default:           // MODE_DQ(""内で直前が\の場合)
                mode = MODE_D;
                break; 
            }
            break;

            /* クォート文字の場合 */
            case '\\':
            switch (mode) {
                case MODE_N:
                mode = MODE_Q;
                break;

                case MODE_Q:
                mode = MODE_N;
                break;

                case MODE_D:
                mode = MODE_DQ;
                break;

                default:           // MODE_DQ
                mode = MODE_D;
                break;
            }
            break;

            /* カンマの場合 */
            case ',':
            switch (mode) {
                case MODE_N:
                /* アドレス格納 */
                *to_ptr = '\0';   // \0で潰す    

                // アドレスのみを抜き出す
                *to_array_addr = get_addrpart(to_start); 
                if (*to_array_addr == NULL) {
                    /* アロケートエラー */
                    // メモリ開放
                    for (to_array_move = to_array; 
                               *to_array_move != NULL; to_array_move++) {
                        free(*to_array_move);
                    }
                    free(to_array);                
                    return -1;
                }

                // カンマ(\0)の次からを開始とする
                to_start = to_ptr + 1;

                // 新配列の作成(次のアドレスとNULLの分までアロケート)
                to_array_tmp = (char **)malloc(sizeof(char **) 
                                                         * (to_array_num + 2));
                if (to_array_tmp == NULL) {
                    /* アロケートエラー */
                    // メモリ開放
                    for (to_array_move = to_array;
                               *to_array_move != NULL; to_array_move++) {
                        free(*to_array_move);
                    }
                    free(to_array);
                    return -1;
                }

                /* 配列の作り直し */
                to_array_move = to_array;          // 旧配列のポインタ
                to_array_tmp_move = to_array_tmp;  // 新配列のポインタ
                while (*to_array_move != NULL) {
                    *to_array_tmp_move = *to_array_move;
                    to_array_move++;
                    to_array_tmp_move++;
                }

                // 旧配列開放
                free(to_array);
    
                // 新配列へ移行
                to_array = to_array_tmp;
                to_array_addr = to_array_tmp_move;

                // 配列の最後にNULLを代入
                *(to_array_addr + 1) = NULL;

                // 配列の数をインクリメント
                to_array_num++;

                // mode変更せず
                break;

                case MODE_Q:
                mode = MODE_N;
                break;

                case MODE_D:
                // mode変更せず
                break;

                default:           // MODE_DQ
                mode = MODE_D;
                break;
            }

            /* 上記以外の場合 */
            default:
            switch (mode) {
                case MODE_N:
                // mode変更せず
                break;

                case MODE_Q:
                mode = MODE_N;
                break;

                case MODE_D:
                // mode変更せず
                break;

                default:           // MODE_DQ
                mode = MODE_D;
                break;
            }            
            break;
        }
    }

    /* 最後尾のアドレス格納 */
    *to_array_addr = get_addrpart(to_start);
    if (*to_array_addr == NULL) {
        /* アロケートエラー */
        // メモリ開放
        for (to_array_move = to_array; *to_array_move != NULL; to_array_move++){
            free(*to_array_move);
        }
        free(to_array);
        return -1;
    }

    // NULLを配列の最後に代入
    to_array_addr++;
    *to_array_addr = NULL;

    // 引数に代入
    *addr_array = to_array;

    return 0;
}
