/*
 * Network Library
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */

#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "libdgstr.h"
#include "libdgnetutil.h"

/*
 * srb_init
 *
 * 機能
 *       ストリームバッファ構造体を初期化する
 *
 * 引数
 *       struct streambuffer *srb       ストリームバッファ構造体
 *       int                  in        読み込み用ファイルデスクリプタ
 *       int                  out       書き込み用ファイルデスクリプタ
 *
 * 返り値
 *       無し
 *
 */
void
srb_init(struct streambuffer *srb, int in, int out)
{
    srb->srb_in     = in;
    srb->srb_out    = out;
    srb->srb_flag   = 0;
    srb->srb_buf    = NULL;
    srb->srb_len    = 0;
    srb->srb_errno  = 0;
}

/*
 * srb_clean
 *
 * 機能
 *       ストリームバッファ構造体の確保された領域を開放する
 *
 * 引数
 *       struct streambuffer *srb      ストリームバッファ構造体
 *
 * 返り値
 *       無し
 *
 */
void
srb_clean(struct streambuffer *srb)
{
    if (srb->srb_buf != NULL) {
	free(srb->srb_buf);
	srb->srb_buf = NULL;
    }
    srb->srb_len    = 0;
    srb->srb_errno  = 0;
}

/*
 * srb_write
 *
 * 機能
 *       ストリームバッファに書き込む
 *       書き込み用FDに書き込む
 *       接続先からデータが送られているときには書き込みは実施しない
 *       buffer は復帰時に開放されない。
 *
 * 引数
 *       struct streambuffer *srb      ストリームバッファ構造体
 *       char                *buffer   書き込むバッファ
 *       int                  len      書き込む長さ
 *
 * 返り値
 *  SRB_OK              正常
 *  SRB_ERROR_IO        IOエラー
 *  SRB_ERROR_TIMEOUT   タイムアウト
 *
 */
int
srb_write(struct streambuffer *srb, char *buffer, int len)
{
    int ret;
    int oft = 0;

    while(oft < len) {
	int wlen = len - oft;

	ret = write(srb->srb_out, buffer + oft, wlen);
	if(ret < 0) {
	    if (errno == EINTR) {
		/* 割り込みからの復帰 */
		continue;
	    } else if(errno == EWOULDBLOCK) {
		/* タイムアウト発生 */
		srb->srb_errno = errno;
		srb->srb_flag |= SRB_FLAG_TIMEOUT;
		return SRB_ERROR_TIMEOUT;
	    } else {
		/* その他のエラー発生 */
		srb->srb_errno = errno;
		srb->srb_flag |= SRB_FLAG_ERROR;
		return SRB_ERROR_IO;
	    }
	}
	oft += ret;
    }
    return SRB_OK;
}

/*
 * srb_read_buf
 *
 * 機能
 *      バッファを最大でsizeだけ読む
 *
 * 引数
 *      struct streambuffer *srb         ストリームバッファ構造体
 *      int                  size        読むサイズ
 *
 * 返り値
 *  SRB_OK              正常
 *  SRB_ERROR_IO        IOエラー
 *  SRB_ERROR_MEM       メモリエラー
 *  SRB_ERROR_TIMEOUT   タイムアウト
 *
 */
static int
srb_read_buf(struct streambuffer *srb, int size)
{
    int len;

    if (size <= 0) {
	/* 読む必要がないのでそのまま返す */
	return SRB_OK;
    }

    srb->srb_buf = dg_realloc(srb->srb_buf, srb->srb_len + size + 1);
    if (srb->srb_buf == NULL) {
        /* メモリエラー */
        srb->srb_errno = errno;
        srb->srb_flag |= SRB_FLAG_MEMERROR;
        return SRB_ERROR_MEM;
    }

    len = read(srb->srb_in, srb->srb_buf + srb->srb_len, size);
    if(len > 0) {
	srb->srb_len += len;
	srb->srb_buf[srb->srb_len] = '\0';
    } else if (len == 0) {
	/* EOFに達した */
	srb->srb_flag |= SRB_FLAG_EOF;
	return SRB_OK;
    } else {
	/* len < 0 */
	if (errno == EINTR) {
	    /* 割り込みが入ったのでエラーにはしない */
	    return SRB_OK;
	} else if(errno == EWOULDBLOCK) {
	    /* タイムアウト発生 */
	    srb->srb_errno = errno;
	    srb->srb_flag |= SRB_FLAG_TIMEOUT;
	    return SRB_ERROR_TIMEOUT;
	} else {
	    /* IOエラー発生 */
	    srb->srb_errno = errno;
	    srb->srb_flag |= SRB_FLAG_ERROR;
	    return SRB_ERROR_IO;
	}
    }
    return SRB_OK;
}

/*
 * replace_buffer
 *
 * 機能
 *       バッファを先頭になるポインタのものに置き換える
 *
 * 引数
 *       struct streambuffer *srb         ストリームバッファ構造体
 *       char                *nextdata    次の先頭になるポインタ
 *       int                 *size        サイズ
 *
 * 返り値
 *       ret_str	置き換えられたバッファ
 *       NULL		メモリエラー
 *
 */
static char *
replace_buffer(struct streambuffer *srb, char *nextdata, int *size)
{
    char *ret_str = NULL;

    if (*size == srb->srb_len + 1) {
	/* *sizeが'\0'を含めたバッファサイズと同じ場合 */
	ret_str = srb->srb_buf;
	srb->srb_buf = NULL;
	srb->srb_len = 0;
    } else {
	ret_str = srb->srb_buf;
	srb->srb_len -= nextdata - srb->srb_buf;

	srb->srb_buf = (char *) malloc(srb->srb_len + 1);
        if (srb->srb_buf == NULL) {
            /* メモリエラー */
            srb->srb_errno = errno;
            srb->srb_flag |= SRB_FLAG_MEMERROR;
            return NULL;
        }

	memcpy(srb->srb_buf, nextdata, srb->srb_len);
	srb->srb_buf[srb->srb_len] = '\0';
	*(ret_str + *size - 1) = '\0';
        ret_str = (char *) dg_realloc(ret_str, *size);
        if (ret_str == NULL) {
            /* メモリエラー */
            srb->srb_errno = errno;
            srb->srb_flag |= SRB_FLAG_MEMERROR;
            return NULL;
        }
    }
    return ret_str;
}

/*
 * srb_read_len
 *
 * 機能
 *      ストリームバッファからサイズ指定で読み込む
 *
 * 引数
 *      struct streambuffer *srb       ストリームバッファ構造体
 *      int                 *size      読まれたサイズ
 *      int                  rlen      読み込むサイズ
 *
 * 返り値
 *      ret_str                        読み込んだバッファ
 *      NULL                           エラー
 *
 */
char *
srb_read_len(struct streambuffer *srb, int *size, int rlen)
{
    char *ret_str;
    char *endcmd = NULL;
    char *nextdata = NULL;
    int ret;

    if (rlen == 0) {
        *size = 0;
        return NULL;
    }

    /*
     * データを読む必要があればsrbから読む
     */
    if (rlen > srb->srb_len) {
	while (srb->srb_len < rlen) {
	    ret = srb_read_buf(srb, rlen - srb->srb_len);
	    if (srb->srb_flag & SRB_FLAG_ERRORS) {
		/* エラー発生 */
		*size = 0;
		return NULL;
	    }
	    if (srb->srb_flag & SRB_FLAG_EOF) {
		/* EOFに達しているので抜ける */
		break;
	    }
	}
    }

    /* バッファが空ならNULLを返す */
    if (srb->srb_len == 0) {
	*size = 0;
	return NULL;
    }

    /* rlenに達したかチェック */
    if (srb->srb_len >= rlen) {
	endcmd = srb->srb_buf + rlen;
	nextdata = srb->srb_buf + rlen;
    } else if (srb->srb_flag & SRB_FLAG_EOF) {
	/* EOFに達している */
	endcmd = srb->srb_buf + srb->srb_len;
	nextdata = srb->srb_buf + srb->srb_len;
    }

    *size = endcmd - srb->srb_buf + 1; /* '\0'を含めたサイズ */
    ret_str = replace_buffer(srb, nextdata, size);
    if (srb->srb_flag & SRB_FLAG_ERRORS) {
	*size = 0;
	return NULL;
    }
    *size -= 1;
    return ret_str;
}

/*
 * srb_read_tostr
 *
 * 機能
 *     ストリームバッファから検索文字列までを取得する
 *     検索文字列があったら文字列を返す
 *
 * 引数
 *      struct streambuffer *srb         ストリームバッファ構造体
 *      int                 *size        読まれたサイズ
 *      const char          *needle      検索文字列
 *
 * 返り値
 *      ret_str                   検索文字列までの文字列
 *      NULL                      エラー
 *
 */
char *
srb_read_tostr(struct streambuffer *srb, int *size, const char *needle)
{
    char *p = NULL;
    char *ret_str;
    char *endcmd;
    int ret;
    int needlesize;

    needlesize = strlen(needle);

    while (((srb->srb_buf == NULL) || (srb->srb_len < needlesize) || 
		((p = strstr(srb->srb_buf, needle)) == NULL))
					&& !(srb->srb_flag & SRB_FLAG_EOF)) {
	/* srb からデータを読む */
	ret = srb_read_buf(srb, SRB_BUFSIZE);
	if (srb->srb_flag & SRB_FLAG_ERRORS) {
	    /* エラー発生 */
	    *size = 0;
	    return NULL;
	}
    }
    if ((srb->srb_len == 0) && (srb->srb_flag & SRB_FLAG_EOF)) {
	/* 空だったら領域を開放する */
	if (srb->srb_buf != NULL) {
	    free(srb->srb_buf);
	    srb->srb_buf = NULL;
	}
	*size = 0;
	return NULL;
    }

    /* 行の最後かチェック */
    if (p != NULL) {
	endcmd = p + needlesize;
    } else {
	/* 改行はないがEOFに達している */
	endcmd = srb->srb_buf + srb->srb_len;
    }

    *size = endcmd - srb->srb_buf + 1; /* '\0'を含めたサイズ */
    ret_str = replace_buffer(srb, endcmd, size);
    if (srb->srb_flag & SRB_FLAG_ERRORS) {
	*size = 0;
	return NULL;
    }
    *size -= 1;
    return ret_str;
}

/*
 * srb_rollback
 *
 * 機能
 *      backを読まなかったことにする
 *      backをストリームバッファの先頭に挿入する
 *
 * 引数
 *      struct streambuffer *srb          ストリームバッファ構造体
 *      char                *back         ロールバックするバッファ
 *      int                  size         backのサイズ
 *
 * 返り値
 *  SRB_OK              正常
 *  SRB_ERROR_MEM       メモリエラー
 *
 */
int
srb_rollback(struct streambuffer *srb, char *back, int size)
{
    char *newbuf;

    if (back == NULL) {
	return SRB_OK;
    }
    newbuf = back;
    if (srb->srb_buf == NULL) {

	newbuf = dg_realloc(newbuf, size + 1);
        if (newbuf == NULL) {
            /* メモリエラー */
            srb->srb_errno = errno;
            srb->srb_flag |= SRB_FLAG_MEMERROR;
            return SRB_ERROR_MEM;
        }

	srb->srb_len = size;
	srb->srb_buf = newbuf;
	*(srb->srb_buf + srb->srb_len) = '\0';
	return SRB_OK;

    } else {

	newbuf = dg_realloc(newbuf, size + srb->srb_len + 1);
        if (newbuf == NULL) {
            /* メモリエラー */
            srb->srb_errno = errno;
            srb->srb_flag |= SRB_FLAG_MEMERROR;
            return SRB_ERROR_MEM;
        }

	memcpy(newbuf + size, srb->srb_buf, srb->srb_len);
	srb->srb_len += size;
	free(srb->srb_buf);
	srb->srb_buf = newbuf;
	*(srb->srb_buf + srb->srb_len) = '\0';
	return SRB_OK;
    }
}
