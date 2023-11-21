/*
 * Network Library
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */

#ifndef _LIBDGNETUTIL_H_
#define _LIBDGNETUTIL_H_

/*--- 構造体 ---*/

/* ストリームバッファ構造体 */
struct streambuffer {
    int   srb_in;	/* 入力のためのファイルディスクリプタ */
    int   srb_out;	/* 出力のためのファイルディスクリプタ */
    int   srb_flag;     /* フラグ */
    char *srb_buf;	/* 読み込んだバッファ */
    int   srb_len;	/* 読み込んだバッファの長さ */
    int   srb_errno;	/* エラーナンバーを格納 */
};


/*--- マクロ ---*/

/* ストリームバッファ構造体のメンバsrb_flagに代入するフラグ */
#define SRB_FLAG_EOF	 	0x01
#define SRB_FLAG_ERROR		0x10
#define SRB_FLAG_MEMERROR	0x20
#define SRB_FLAG_TIMEOUT	0x40

#define SRB_BUFSIZE 1024             // バッファサイズ

/* 関数の返り値 */
#define SRB_ERROR_TIMEOUT    -3      // タイムアウト
#define SRB_ERROR_MEM        -2      // メモリエラー
#define SRB_ERROR_IO         -1      // IOエラー
#define SRB_OK                0      // 正常


/*--- 関数マクロ ---*/

#define SRB_FLAG_ERRORS		((SRB_FLAG_ERROR) | \
                                 (SRB_FLAG_MEMERROR) | \
                                 (SRB_FLAG_TIMEOUT))

/* 改行までを読み込む */
#define srb_read_line(x, y)	srb_read_tostr(x, y, "\r\n")


/*--- プロトタイプ宣言 ---*/

extern void  srb_init(struct streambuffer *, int, int);
extern void  srb_clean(struct streambuffer *);
extern char *srb_read_tostr(struct streambuffer *, int *, const char *);
extern char *srb_read(struct streambuffer *, int *);
extern char *srb_read_len(struct streambuffer *, int *, int);
extern int   srb_write(struct streambuffer *, char *, int);
extern int   srb_rollback(struct streambuffer *, char *, int);


#endif	/* _LIBDGNETUTIL_H_ */
