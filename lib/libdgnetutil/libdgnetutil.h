/*
 * Network Library
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */

#ifndef _LIBDGNETUTIL_H_
#define _LIBDGNETUTIL_H_

/*--- ��¤�� ---*/

/* ���ȥ꡼��Хåե���¤�� */
struct streambuffer {
    int   srb_in;	/* ���ϤΤ���Υե�����ǥ�������ץ� */
    int   srb_out;	/* ���ϤΤ���Υե�����ǥ�������ץ� */
    int   srb_flag;     /* �ե饰 */
    char *srb_buf;	/* �ɤ߹�����Хåե� */
    int   srb_len;	/* �ɤ߹�����Хåե���Ĺ�� */
    int   srb_errno;	/* ���顼�ʥ�С����Ǽ */
};


/*--- �ޥ��� ---*/

/* ���ȥ꡼��Хåե���¤�ΤΥ���srb_flag����������ե饰 */
#define SRB_FLAG_EOF	 	0x01
#define SRB_FLAG_ERROR		0x10
#define SRB_FLAG_MEMERROR	0x20
#define SRB_FLAG_TIMEOUT	0x40

#define SRB_BUFSIZE 1024             // �Хåե�������

/* �ؿ����֤��� */
#define SRB_ERROR_TIMEOUT    -3      // �����ॢ����
#define SRB_ERROR_MEM        -2      // ���ꥨ�顼
#define SRB_ERROR_IO         -1      // IO���顼
#define SRB_OK                0      // ����


/*--- �ؿ��ޥ��� ---*/

#define SRB_FLAG_ERRORS		((SRB_FLAG_ERROR) | \
                                 (SRB_FLAG_MEMERROR) | \
                                 (SRB_FLAG_TIMEOUT))

/* ���ԤޤǤ��ɤ߹��� */
#define srb_read_line(x, y)	srb_read_tostr(x, y, "\r\n")


/*--- �ץ�ȥ�������� ---*/

extern void  srb_init(struct streambuffer *, int, int);
extern void  srb_clean(struct streambuffer *);
extern char *srb_read_tostr(struct streambuffer *, int *, const char *);
extern char *srb_read(struct streambuffer *, int *);
extern char *srb_read_len(struct streambuffer *, int *, int);
extern int   srb_write(struct streambuffer *, char *, int);
extern int   srb_rollback(struct streambuffer *, char *, int);


#endif	/* _LIBDGNETUTIL_H_ */
