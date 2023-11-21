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

/*--- static�ؿ���� ---*/

static int euc_str_divide(char *, char *, int);
static int encode_mime_one_line(struct strset *, char *, int);

/*--- �����ѿ� ---*/

/* Basic BASE64 conversion table */
char base64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*--- �ؿ� ---*/

/*
 * get_field
 *
 * ��ǽ
 *	�إå����ͤ��������
 *
 * ����
 *	char  *buftop	�ե�����ɤ���Ƭ
 *	char **nadr	���Υإå��ؤΥݥ���
 *
 * �֤���
 *	NULL		�������ȥ��顼             
 *	rstr		�إå�����
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
 * ��ǽ
 *	�᡼��Υ��֥������Ȥ���Ф�
 *
 * ����
 *	char  *buftop	�ե�����ɤ���Ƭ
 *	char **nadr	���Υإå��ؤΥݥ���
 *	char **rstr	MIME�ǥ����ɤ�������Υ��֥������ȥإå�����
 *
 * �֤���:
 *  NULL		�������ȥ��顼
 *  dstr		MIME�ǥ����ɤ��줿�إå�����
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
 * ��ǽ
 *	MIME�ǥ�����
 *
 * ����
 *	char *sstr	���󥳡��ɤ��줿ʸ����
 *
 * �֤���
 *	NULL		�������ȥ��顼
 *	retbuf_addr	MIME�ǥ����ɤ��줿ʸ����
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
 * ��ǽ
 *	7bitʸ���Υ����å�
 *
 * ����
 *	char *str	�����å�����ʸ����
 *
 * �֤��� 
 *	0		8�ӥåȤ�ʸ����ǤϤʤ�
 *	1		8�ӥåȤ�ʸ����Ǥ���
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
 * ��ǽ
 *	quoted printable�Υǥ�����
 *
 * ����
 *	char  *src_buf	�ǥ����ɤ�����ʸ����
 *	char **ret_buf	�ǥ����ɤ��졢�������Ȥ��줿ʸ����
 *
 * �֤���
 *	 0		����
 *	>0		�ǥ����ɥ��顼
 *	<0		���ꥨ�顼
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
 * ��ǽ
 *	16�ʿ���ʸ���������ͤ��Ѵ���
 *
 * ����
 *	int c	�Ѵ�����16�ʿ�
 *
 * �֤���
 *	-1�ʳ�	�Ѵ����������
 *	-1	���顼
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
 * ��ǽ
 *	Base64�Υǥ�����
 *
 * ����
 *	char  *src_buf	�ǥ����ɤ�����ʸ����
 *	char **ret_buf	�ǥ����ɤ��졢�������Ȥ��줿ʸ����
 *
 * �֤���
 *	 0		����
 *	>0		�ǥ����ɥ��顼
 *	<0		���ꥨ�顼
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
 * ��ǽ
 *	Base64�Υ��󥳡���
 *
 * ����
 *	char  *str	���󥳡��ɤ�����ʸ����
 *
 * �֤���
 *	bstr		���󥳡��ɤ���ʸ����
 *	NULL		�������ȥ��顼
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
 * ��ǽ
 *	Base64���󥳡���ʸ�����ͤ��Ѵ�
 *
 * ����
 *	int c	�Ѵ�������ʸ�� 
 *
 * �֤���
 *	-1�ʳ�	�Ѵ����������
 *	-1	���顼
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
 * ��ǽ
 *	�᡼�륢�ɥ쥹���μ�����
 * 	"name <address>'' �ޤ��� "address (name)'' �ޤ���"address"�η�����
 *
 * ����
 *	unsigned char *str	�᡼�륢�ɥ쥹��Ϣ�إå�����
 *	int translateflg	TRANSLATE:��ʸ�����Ѵ�����
 *				NOTRANSLATE:��ʸ�����Ѵ����ʤ�
 *
 * �֤���
 *	bstr			�᡼�륢�ɥ쥹ʸ����
 *	NULL			�������ȥ��顼
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
 * ��ǽ
 *	get_addrpart_real��ƤӾ�ʸ�����Ѵ����줿�᡼�륢�ɥ쥹�������
 *
 * ����
 *	unsigned char *str	�᡼�륢�ɥ쥹��Ϣ�إå�����
 *
 * �֤���
 *				�᡼�륢�ɥ쥹ʸ����
 */
char *
get_addrpart(unsigned char *str)
{
    return get_addrpart_real(str, TRANSLATE);
}

/*
 * get_addrpart_notranslate
 *
 * ��ǽ
 *      get_addrpart_real��Ƥӥ᡼�륢�ɥ쥹���������
 *
 * ����
 *	unsigned char *str	�᡼�륢�ɥ쥹��Ϣ�إå�����
 *
 * �֤���
 *				�᡼�륢�ɥ쥹ʸ����
 */
char *
get_addrpart_notranslate(unsigned char *str)
{
    return get_addrpart_real(str, NOTRANSLATE);
}

/*
 * get_from
 *
 * ��ǽ
 *	From�إå�����᡼�륢�ɥ쥹�����������
 *
 * ����
 *	char  *buftop	�᡼��إå�����Ƭ
 *	char **nadr	���Υإå��ؤΥݥ���
 *
 * �֤���
 *	dstr		�᡼�륢�ɥ쥹ʸ����
 *	NULL		�������ȥ��顼
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
 * ��ǽ
 *	EUCʸ�����JIS���Ѵ�������MIME���󥳡��ɤ��롣
 *
 * ����
 *	char *str	�Ѵ�����ʸ����
 *	int   len	str��'<�᡼�륢�ɥ쥹>'��ľ���ޤǤ�ʸ����
 *			'<�᡼�륢�ɥ쥹>'���ʤ����strlen(str)
 * �֤���
 *	ss.ss_str	�Ѵ����ʸ����
 *	NULL		�������ȥ��顼
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
    /* ��ñ�̤�ʬ�䤹�뤿�����֥Хåե� */
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

    /* �Ѵ��Ѥ�ʸ�������Ѵ�������ʸ������겼�ʤ�롼�� */
    while (ptr < ileft) {
        op = buf;
        oleft = sizeof(buf);

        /* ʸ�����ʬ�� */
        str_divide_len = euc_str_divide(ip + ptr, str_divide, ileft - ptr);

        ptr = ptr + str_divide_len;
        str_divide_tmp = str_divide;
        /* ��ü�δ��������Ƚ����Τ���\0��ޤ�Ĺ�����ѹ� */
        str_divide_len_tmp = str_divide_len + 1;

        /* EUC����JIS���Ѵ� */
        iconv(icd, NULL, NULL, NULL, NULL);
        ret = iconv(icd, &str_divide_tmp, &str_divide_len_tmp, &op, &oleft);

        /* ���󥳡��ɷ�̤ν�ü��\0�ʤ�1����� */
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
 * ��ǽ
 *	EUC��ʸ�����ʬ�䤹��ؿ�
 *
 * ����
 *	char *org_str	���ԡ�����ʸ����
 *	char *buf	ʬ����ʸ����
 *	int   rest_len	�岿ʸ���Ѵ����뤫�ο�
 *
 * �֤���
 *	ptr		���ԡ�����ʸ����
 */
static int
euc_str_divide(char *org_str, char *buf, int rest_len)
{
    int ptr = 0;

    while (ptr < ENC_STR_DIVIDE_LEN) {

        if (org_str[ptr] == '\0' || rest_len <= ptr) {
            break;
        }

        /* ����ʸ���ʤ�� */
        if (org_str[ptr] & 0x80) {

            buf[ptr] = org_str[ptr];
            buf[ptr + 1] = org_str[ptr + 1];

            ptr += 2;

        } else {
            /* Asciiʸ���ʤ�� */
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
 * ��ǽ
 *	1��ʬ��ʸ�����MIME���󥳡��ɤ���ؿ�
 *
 * ����
 *	struct strset *ss	MIME���󥳡��ɤ���ʸ������Ǽ
 *	char          *buf	MIME���󥳡��ɤ���ʸ����
 *	int            size	MIME���󥳡��ɤ���ʸ�����Ĺ��
 *
 * �֤���
 *	-1	�������ȥ��顼
 *	-2	����ʸ�������顼
 *	0	����
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

    /* ��³�Ԥξ�� */
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
 * ��ǽ
 *	To�إå�����᡼�륢�ɥ쥹����2��������˳�Ǽ����
 *
 * ����
 *      char   *buftop		�ե�����ɤ���Ƭ��To:�μ���ʸ�������
 *      char  **nadr		���Υإå��ؤΥݥ���
 *
 * �֤���:
 *	NULL			�������ȥ��顼
 *	**addr_array		�᡼�륢�ɥ쥹ʸ����(�󼡸�����)(�����ѿ�)
 */
char ** 
get_to(char *buftop, char **nadr)
{
    char   *dstr = NULL;
    char   *rstr = NULL;
    char  **addr_array = NULL;
    int     ret;

    /* ��Ƭ�ˤ���إå����ͤ���� */
    rstr = get_field(buftop, nadr);
    if (rstr == NULL) {
        return NULL;
    }

    // ����ޤ�ʬ��
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
 * ��ǽ
 *	To�إå������ͤ򥫥�ޤ�ʬ��
 *
 * ����
 *	char   *str		�ե�����ɤ���Ƭ��To:���μ���ʸ�������
 *	char ***addr_array	To�إå������ͤ򥫥�ޤ�ʬ������
 *				 (�󼡸�����)(�����ѿ�)
 *
 * �֤���:
 *	-1			�������ȥ��顼
 *	 0			����
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

    // ���ɥ쥹1��+NULL��ʬ��������
    to_array = (char **)malloc(sizeof(char **) * 2);
    if (to_array == NULL) {
        return -1;
    }

    /* ����ޤ�������Ͻ񼰥����å� */
    *to_array = NULL;         // 2���������NULL������
    *(to_array + 1) = NULL;         // 2��������κǸ��NULL������
    to_array_num = 1;         // 2�������������θĿ�
    to_array_addr = to_array; // 2���������address������������򼨤��ݥ���
    mode = MODE_N;            // �Ρ��ޥ�⡼��("��\��,�ʳ�)
    for (to_ptr = to_start = str; *to_ptr != '\0'; to_ptr++) {

        switch (*to_ptr) {
            /* display-name�򼨤�"�ξ�� */
            case '"':
            switch (mode) {
                case MODE_N:       // ""��Ǥʤ����
                mode = MODE_D;
                break; 

                case MODE_Q:       // ""��Ǥʤ�ľ����\�ξ��
                mode = MODE_N;
                break; 

                case MODE_D:       // ""��ξ��
                mode = MODE_N;
                break;

                default:           // MODE_DQ(""���ľ����\�ξ��)
                mode = MODE_D;
                break; 
            }
            break;

            /* ��������ʸ���ξ�� */
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

            /* ����ޤξ�� */
            case ',':
            switch (mode) {
                case MODE_N:
                /* ���ɥ쥹��Ǽ */
                *to_ptr = '\0';   // \0���٤�    

                // ���ɥ쥹�Τߤ�ȴ���Ф�
                *to_array_addr = get_addrpart(to_start); 
                if (*to_array_addr == NULL) {
                    /* �������ȥ��顼 */
                    // ���곫��
                    for (to_array_move = to_array; 
                               *to_array_move != NULL; to_array_move++) {
                        free(*to_array_move);
                    }
                    free(to_array);                
                    return -1;
                }

                // �����(\0)�μ�����򳫻ϤȤ���
                to_start = to_ptr + 1;

                // ������κ���(���Υ��ɥ쥹��NULL��ʬ�ޤǥ�������)
                to_array_tmp = (char **)malloc(sizeof(char **) 
                                                         * (to_array_num + 2));
                if (to_array_tmp == NULL) {
                    /* �������ȥ��顼 */
                    // ���곫��
                    for (to_array_move = to_array;
                               *to_array_move != NULL; to_array_move++) {
                        free(*to_array_move);
                    }
                    free(to_array);
                    return -1;
                }

                /* ����κ��ľ�� */
                to_array_move = to_array;          // ������Υݥ���
                to_array_tmp_move = to_array_tmp;  // ������Υݥ���
                while (*to_array_move != NULL) {
                    *to_array_tmp_move = *to_array_move;
                    to_array_move++;
                    to_array_tmp_move++;
                }

                // ��������
                free(to_array);
    
                // ������ذܹ�
                to_array = to_array_tmp;
                to_array_addr = to_array_tmp_move;

                // ����κǸ��NULL������
                *(to_array_addr + 1) = NULL;

                // ����ο��򥤥󥯥����
                to_array_num++;

                // mode�ѹ�����
                break;

                case MODE_Q:
                mode = MODE_N;
                break;

                case MODE_D:
                // mode�ѹ�����
                break;

                default:           // MODE_DQ
                mode = MODE_D;
                break;
            }

            /* �嵭�ʳ��ξ�� */
            default:
            switch (mode) {
                case MODE_N:
                // mode�ѹ�����
                break;

                case MODE_Q:
                mode = MODE_N;
                break;

                case MODE_D:
                // mode�ѹ�����
                break;

                default:           // MODE_DQ
                mode = MODE_D;
                break;
            }            
            break;
        }
    }

    /* �Ǹ����Υ��ɥ쥹��Ǽ */
    *to_array_addr = get_addrpart(to_start);
    if (*to_array_addr == NULL) {
        /* �������ȥ��顼 */
        // ���곫��
        for (to_array_move = to_array; *to_array_move != NULL; to_array_move++){
            free(*to_array_move);
        }
        free(to_array);
        return -1;
    }

    // NULL������κǸ������
    to_array_addr++;
    *to_array_addr = NULL;

    // ����������
    *addr_array = to_array;

    return 0;
}
