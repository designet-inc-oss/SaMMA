/*
 * String Utility Library
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <iconv.h>
#include <locale.h>

#include "libdgstr.h"

#ifdef HAVE_CONFIGH
#include "../../config.h"
#endif


/*--- 関数 ---*/

/*
 * strset_init
 *
 * 機能
 *	strsetの構造体を初期化する。
 *
 * 引数
 *	struct strset *ss	初期化するstrsetの領域
 *
 * 返り値
 *	なし
 *
 */
void
strset_init(struct strset *ss)
{
    ss->ss_str = NULL;
    ss->ss_len = 0;
}

/*
 * strset_set
 *
 * 機能
 *	strsetの構造体に文字列を設定する。
 *
 * 引数
 *	struct strset *ss	初期化するstrsetの領域
 *	char          *str	設定する文字列
 *
 * 返り値
 *	なし
 *
 */
void
strset_set(struct strset *ss, char *str)
{
    ss->ss_str = str;
    ss->ss_len = strlen(str);
}

/*
 * strset_free
 *
 * 機能
 *	strsetの構造体に割り当てられている文字列を開放する。
 *      strsetの領域そのものは開放しないので、注意が必要です。
 *
 * 引数
 *	struct strset *ss	開放するstrsetの領域
 *
 * 返り値
 *	なし
 *
 */
void
strset_free(struct strset *ss)
{
    if (ss->ss_str != NULL) {
	free(ss->ss_str);
	ss->ss_str = NULL;
    }
    ss->ss_len = 0;
}

/*
 * strset_catstrset
 *
 * 機能
 *	2つのstrsetの構造体に割り当てられている文字列を連結する。
 *      ss1側に連結される。ss2側が開放されることはない。
 *
 * 引数
 *	struct strset *ss1	連結元
 *	struct strset *ss2	連結文字列セット
 *
 * 返り値
 *	正常	0
 *	異常	-1	(連結用の領域が割り当てられない)
 */
int
strset_catstrset(struct strset *ss1, struct strset *ss2)
{
    char   *tmp;

    tmp = realloc(ss1->ss_str, ss1->ss_len + ss2->ss_len + 1);
    if (tmp == NULL) {
	return (-1);
    }

    ss1->ss_str = tmp;
    memcpy(ss1->ss_str + ss1->ss_len, ss2->ss_str, ss2->ss_len);
    ss1->ss_len += ss2->ss_len;
    ss1->ss_str[ss1->ss_len] = '\0';
    return (0);
}

/*
 * strset_catstr
 *
 * 機能
 *	strsetの構造体に割り当てられている文字列に、文字列を連結する。
 *
 * 引数
 *	struct strset *ss1	連結元文字列セット
 *	char          *str	連結する文字列
 *
 * 返り値
 *	正常	0
 *	異常	-1	(連結用の領域が割り当てられない)
 */
int
strset_catstr(struct strset *ss1, char *str)
{
    struct strset ss2;

    strset_set(&ss2, str);

    return (strset_catstrset(ss1, &ss2));
}

/*
 * strset_catnstr
 *
 * 機能
 *	strsetの構造体に割り当てられている文字列に、文字列を連結する。
 *      文字列の中の指定した文字数だけが連結される。
 *
 * 引数
 *	struct strset *ss1	連結元文字列セット
 *	char          *str	連結する文字列
 *      int            len	連結する文字列の長さ
 *
 * 返り値
 *	正常	0
 *	異常	-1	(連結用の領域が割り当てられない)
 */
int
strset_catnstr(struct strset *ss1, char *str, int len)
{
    struct strset ss2;

    ss2.ss_str = str;
    ss2.ss_len = len;

    return (strset_catstrset(ss1, &ss2));
}

#ifndef HAVE_STRNDUP
/*
 * strndup
 *
 * 機能
 *	文字列中の指定した文字数を別の動的領域にコピーする。
 *
 * 引数
 *	char          *str	コピーする文字列
 *      int            len	コピーする文字列の長さ
 *
 * 返り値
 *	正常	0
 *	異常	-1	(コピー用の領域が割り当てられない)
 */
char   *
strndup(char *str, int len)
{
    char   *tmp;

    tmp = malloc(len + 1);
    memcpy(tmp, str, len);

    tmp[len] = '\0';
    return (tmp);
}
#endif

/*
 * str_replace_tag
 *
 * 機能
 *	文字列中のタグを置換し、新たな動的領域に格納する。
 *
 * 引数
 *	char          *str	コピーする文字列
 *	char          *start	タグの開始文字列
 *	char          *end	タグの終了文字列
 *	struct strtag *tag	置換文字列情報の入っている配列
 *	int            num	tagの領域に格納されている配列の個数
 *
 * 返り値
 *	正常	変換後の文字列
 *	異常	NULL	(コピー用の領域が割り当てられない)
 */
char   *
str_replace_tag(char *str, char *start, char *end, struct strtag *tag,
		int num)
{
    char   *ptr;
    char   *nptr;
    char   *p;
    char   *e;
    struct strset ss;
    int     ret;
    int     i;
    int     slen;
    int     elen;
    int     taglen;

    strset_init(&ss);
    slen = strlen(start);
    elen = strlen(end);

    for (ptr = str; *ptr != '\0'; ptr = nptr) {
	if (((p = strstr(ptr, start)) == NULL) ||
	    ((e = strstr(p + slen, end)) == NULL)) {
	    ret = strset_catstr(&ss, ptr);
	    if (ret < 0) {
		/* memory error */
		strset_free(&ss);
		return (NULL);
	    }
	    return (ss.ss_str);
	}

	taglen = e - (p + slen);

	ret = strset_catnstr(&ss, ptr, p - ptr);
	if (ret < 0) {
	    strset_free(&ss);
	    return (NULL);
	}

	for (i = 0; i < num; i++) {
	    if ((tag[i].st_taglen == taglen) &&
		(strncmp(p + slen, tag[i].st_tag, taglen) == 0)) {
		/* found tag */
		ret = strset_catstr(&ss, tag[i].st_str);
		if (ret < 0) {
		    strset_free(&ss);
		    return (NULL);
		}
		break;
	    }
	}

	if (i == num) {
	    /* this is not tag, add a char and go next char */
	    ret = strset_catchar(&ss, start[0]);
	    if (ret < 0) {
		/* memory error */
		strset_free(&ss);
		return (NULL);
	    }
	    nptr = p + 1;
	} else {
	    nptr = e + elen;
	}
    }
    return (ss.ss_str);
}

/*
 * dg_realloc
 *
 * 機能
 *	メモリリークしないrealloc
 *
 * 引数
 *	void  *obuf	アロケートする変数
 *	size_t len	アロケートしたいバイト数
 *
 * 返り値
 *	nbuf		アロケートした変数
 *	NULL		アロケートエラー
 */
void   *
dg_realloc(void *obuf, size_t len)
{
    void   *nbuf;

    nbuf = (void *) realloc(obuf, len);
    if (nbuf == NULL && obuf != NULL) {
        free(obuf);
    }
    return nbuf;
}

/*
 * str2code
 *
 * 概要
 *      inbufで指定した文字列を文字コード from から toへ変換する。
 *
 * 引数
 *      char *from      入力側文字コード
 *      char *inbuf     入力用バッファ
 *
 * 返り値
 *     正常     変換後の文字列
 *     異常     NULL
 *                      errnoに、次の値が設定される
 *                      EINVAL  指定した文字コードが変換できない名前である。
 *                      EILSEQ  文字列中に変換できない文字シーケンスがある。
 *                      ENOMEM  メモリエラー
 */
char *
str2code(char *from, char *to, char *inbuf)
{
    size_t inleft;
    size_t outleft = 0;
    char   *ip;
    char   *op;
    char   *buf = NULL;
    char   *newbuf = NULL;
    int     bufsize = 0;
    int     ret;
    iconv_t icd;
    int     error;
    int     len;
    int     trail = 0;

    len = strlen(inbuf) + 1;

    icd = iconv_open(to, from);
    if (icd == ICONV_ERROR) {
        return NULL;
    }

#ifndef SOLARIS
    /* icdを初期化する */
    iconv(icd, NULL, NULL, NULL, NULL);
#endif

    for (ip = inbuf, inleft = len, op = newbuf, outleft = bufsize;
         inleft > 0 || (inleft == 0 && trail == 1);) {
        newbuf = realloc(buf, bufsize + BUFSIZE);
        if (newbuf == NULL) {
            error = errno;
            if (buf != NULL) {
                free(buf);
            }
            errno = error;
            iconv_close(icd);
            return (NULL);
        }

        buf = newbuf;
        op = newbuf + bufsize - outleft;

        bufsize += BUFSIZE;
        outleft += BUFSIZE;

        ret = iconv(icd, &ip, &inleft, &op, &outleft);
        if (ret == -1) {
            if(errno == E2BIG) {
                if (inleft == 0) {
                    trail = 1;
                }
                continue;
            }
            error = errno;
            free(newbuf);
            iconv_close(icd);
            errno = error;
            return NULL;
        }
        trail = 0;
    }

    /* NULL終端する */
    newbuf[bufsize - outleft] = '\0';

    iconv_close(icd);
    return newbuf;
}



/**
 * str2codeで、機種依存文字が混じっていた時にそれを'?'へ置き換えを試みる
 */
char *
str2code_replace(char *from, char *to, char *inbuf)
{
    size_t inleft;
    size_t outleft = 0;
    char   *ip, *orig;
    char   *op;
    char   *buf = NULL;
    char   *newbuf = NULL;
    int     bufsize = 0;
    int     ret;
    iconv_t icd;
    int     i, error;
    int     len, mbcount;
    int     trail = 0;

    len = strlen(inbuf) + 1;

    orig = ip = strdup(inbuf);
    if (ip == NULL) {
        return NULL;
    }

    setlocale(LC_ALL, "");

    icd = iconv_open(to, from);
    if (icd == ICONV_ERROR) {
        free(orig);
        return NULL;
    }

#ifndef SOLARIS
    /* icdを初期化する */
    iconv(icd, NULL, NULL, NULL, NULL);
#endif

    for (inleft = len, op = newbuf, outleft = bufsize;
         inleft > 0 || (inleft == 0 && trail == 1);) {
        newbuf = realloc(buf, bufsize + BUFSIZE);
        if (newbuf == NULL) {
            error = errno;
            if (buf != NULL) {
                free(buf);
            }
            errno = error;
            iconv_close(icd);
            free(orig);
            return (NULL);
        }

        buf = newbuf;
        op = newbuf + bufsize - outleft;

        bufsize += BUFSIZE;
        outleft += BUFSIZE;

        ret = iconv(icd, &ip, &inleft, &op, &outleft);
        if (ret == -1) {
            switch (errno) {
                case E2BIG:
                    if (inleft == 0) {
                        trail = 1;
                    }
                    continue;

                case EILSEQ:
                    mbcount = mblen(ip, MB_CUR_MAX);
                    if (mbcount < 1) {
                        error = errno;
                        free(newbuf);
                        iconv_close(icd);
                        free(orig);
                        errno = error;
                        return NULL;
                    }

                    for (i = 0; i < mbcount; i++) {
                        ip[i] = LIBDG_PLACEHOLDER;
                    }
                    break;

                default:
                error = errno;
                free(newbuf);
                iconv_close(icd);
                free(orig);
                errno = error;
                return NULL;
            }
        }
        trail = 0;
    }

    /* NULL終端する */
    newbuf[bufsize - outleft] = '\0';

    iconv_close(icd);
    free(orig);
    return newbuf;
}

/*
 * mf_str2euc
 *
 * 概要
 *  入力文字列をtypeからtoに変換する。
 *  typeからの変換に失敗したら、次の順序で変換を試みる
 *   EUC-JP -> EUC-JP
 *   ISO-2022-JP -> EUC-JP
 *   Shift_JIS -> EUC-JP
 *
 * 引数
 *  char *sbuf          変換前の文字列
 *  char **retbuf       変換後の文字列を格納するポインタ
 *  char *type          sbuf のコードと思われる漢字コード
 *
 * 返り値
 *  0   正常
 *  1   デコードに失敗
 *  -1  メモリエラー
 */
int
dg_str2code(char *sbuf, char **retbuf, char *type, char *to)
{
    errno = 0;
    *retbuf = str2code(type, to, sbuf);
    if (*retbuf == NULL) {
        /* 失敗した */
        if (errno == ENOMEM) {
            /* メモリエラー */
            return -1;
        }
        /* 他のコードで変換できるか試してみる */
        /* EUC-JP -> ISO-2022-JP */
#ifdef SOLARIS
        *retbuf = str2code("eucJP", to, sbuf);
#else
        *retbuf = str2code("EUC-JP", to, sbuf);
#endif
        if (*retbuf == NULL) {
            /* 失敗した */
            if (errno == ENOMEM) {
                /* メモリエラー */
                return -1;
            }
            /* ISO-2022-JP -> ISO-2022-JP */
            *retbuf = str2code("ISO-2022-JP", to, sbuf);
            if (*retbuf == NULL) {
                /* 失敗した */
                if (errno == ENOMEM) {
                    /* メモリエラー */
                    return -1;
                }
                /* SJIS -> ISO-2022-JP */
                *retbuf = str2code("SJIS", to, sbuf);
                if (*retbuf == NULL) {
                    /* 失敗した */
                    if (errno == ENOMEM) {
                        /* メモリエラー */
                        return -1;
                    }
                    /* 対応するコードは全滅 */
                    return 1;
                }
            }
        }
    }
    return 0;
}

/**
 * dg_str2codeで、str2code_replaceを使うバージョン
 */
int
dg_str2code_replace(char *sbuf, char **retbuf, char *type, char *to)
{
    errno = 0;
    *retbuf = str2code_replace(type, to, sbuf);
    if (*retbuf == NULL) {
        /* 失敗した */
        if (errno == ENOMEM) {
            /* メモリエラー */
            return -1;
        }
        /* 他のコードで変換できるか試してみる */
        /* EUC-JP -> ISO-2022-JP */
#ifdef SOLARIS
        *retbuf = str2code_replace("eucJP", to, sbuf);
#else
        *retbuf = str2code_replace("EUC-JP", to, sbuf);
#endif
        if (*retbuf == NULL) {
            /* 失敗した */
            if (errno == ENOMEM) {
                /* メモリエラー */
                return -1;
            }
            /* ISO-2022-JP -> ISO-2022-JP */
            *retbuf = str2code_replace("ISO-2022-JP", to, sbuf);
            if (*retbuf == NULL) {
                /* 失敗した */
                if (errno == ENOMEM) {
                    /* メモリエラー */
                    return -1;
                }
                /* SJIS -> ISO-2022-JP */
                *retbuf = str2code_replace("SJIS", to, sbuf);
                if (*retbuf == NULL) {
                    /* 失敗した */
                    if (errno == ENOMEM) {
                        /* メモリエラー */
                        return -1;
                    }
                    /* 対応するコードは全滅 */
                    return 1;
                }
            }
        }
    }
    return 0;
}

/* dg_str2code_replace_validate
 *
 * [Description]
 * dg_str2codeでstr2code_replaceを使い、変換成功したら逆変換して照合する
 *
 * [Arguments]
 *  sbuf           文字コード変換前の文字列
 *  retbuf         文字コード変換後の文字列
 *  type           変換前の文字列の文字コード。UTF-8を想定。
 *  to             変換後の文字コード
 *  lastFromChar   最後に文字コード変換成功したときの、その文字コード名を返す
 *  maxStrCodeSize  "ISO-2022-JP"などの文字列の最大の長さ。13バイト以上を想定
 *
 */
int
dg_str2code_replace_validate(char *sbuf, char **retbuf, char *type, char *to, char **validatebuf, char *lastFromChar, size_t maxStrCodeSize)
{
    char *p = NULL;
    int currentFromCharNum = 0;
    // 0 UTF-8
    // 1 EUC-JP
    // 2 eucjp
    // 3 ISO-2022-JP
    // 4 SJIS
    char codelist[5][16] = {
        "UTF-8",
        "EUC-JP",
        "eucjp",
        "ISO-2022-JP",
        "SJIS"
    };

    errno = 0;
    *retbuf = str2code_replace(type, to, sbuf);
    if (*retbuf == NULL) {
        /* 失敗した */
        if (errno == ENOMEM) {
            /* メモリエラー */
            // メモリエラー時はlastFromCharを返さない
            return -1;
        }
        /* 他のコードで変換できるか試してみる */
        /* EUC-JP -> */
#ifdef SOLARIS
        currentFromCharNum = 2;
        *retbuf = str2code_replace("eucJP", to, sbuf);
#else
        currentFromCharNum = 1;
        *retbuf = str2code_replace("EUC-JP", to, sbuf);
#endif
        if (*retbuf == NULL) {
            /* 失敗した */
            if (errno == ENOMEM) {
                /* メモリエラー */
                // メモリエラー時はlastFromCharを返さない
                return -1;
            }
            /* ISO-2022-JP -> */
            currentFromCharNum = 3;
            *retbuf = str2code_replace("ISO-2022-JP", to, sbuf);
            if (*retbuf == NULL) {
                /* 失敗した */
                if (errno == ENOMEM) {
                    /* メモリエラー */
                    // メモリエラー時はlastFromCharを返さない
                    return -1;
                }
                /* SJIS -> */
                currentFromCharNum = 4;
                *retbuf = str2code_replace("SJIS", to, sbuf);
                if (*retbuf == NULL) {
                    /* 失敗した */
                    if (errno == ENOMEM) {
                        /* メモリエラー */
                        // メモリエラー時はlastFromCharを返さない
                        return -1;
                    }
                    /* 対応するコードは全滅 */
                    return 1;
                }
            }
        }
    }

    // 変換成功時に、最後の変換に使用したFromCharsetをコピーする
    p = strncpy(lastFromChar, codelist[currentFromCharNum], maxStrCodeSize);
    *(p + maxStrCodeSize - 1) = '\0';

    // Validation: Instruct the reverse conversion
    // and compare original strings with converted strings.
    *validatebuf = str2code_replace(to, lastFromChar, *retbuf);
    // null エラー処理
    if (*validatebuf == NULL) {
        /* 失敗した */
        if (errno == ENOMEM) {
            /* メモリエラー */
            return -1;
        }
        /* 逆変換失敗 */
        return 2;
    }
    if (strcmp(*validatebuf, sbuf) != 0) {
        /* 逆変換の検証不一致 */
        return 2;
    }
    return 0;

}
