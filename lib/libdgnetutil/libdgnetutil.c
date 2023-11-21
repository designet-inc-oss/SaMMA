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
 * ��ǽ
 *       ���ȥ꡼��Хåե���¤�Τ���������
 *
 * ����
 *       struct streambuffer *srb       ���ȥ꡼��Хåե���¤��
 *       int                  in        �ɤ߹����ѥե�����ǥ�����ץ�
 *       int                  out       �񤭹����ѥե�����ǥ�����ץ�
 *
 * �֤���
 *       ̵��
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
 * ��ǽ
 *       ���ȥ꡼��Хåե���¤�Τγ��ݤ��줿�ΰ��������
 *
 * ����
 *       struct streambuffer *srb      ���ȥ꡼��Хåե���¤��
 *
 * �֤���
 *       ̵��
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
 * ��ǽ
 *       ���ȥ꡼��Хåե��˽񤭹���
 *       �񤭹�����FD�˽񤭹���
 *       ��³�褫��ǡ����������Ƥ���Ȥ��ˤϽ񤭹��ߤϼ»ܤ��ʤ�
 *       buffer ���������˳�������ʤ���
 *
 * ����
 *       struct streambuffer *srb      ���ȥ꡼��Хåե���¤��
 *       char                *buffer   �񤭹���Хåե�
 *       int                  len      �񤭹���Ĺ��
 *
 * �֤���
 *  SRB_OK              ����
 *  SRB_ERROR_IO        IO���顼
 *  SRB_ERROR_TIMEOUT   �����ॢ����
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
		/* �����ߤ�������� */
		continue;
	    } else if(errno == EWOULDBLOCK) {
		/* �����ॢ����ȯ�� */
		srb->srb_errno = errno;
		srb->srb_flag |= SRB_FLAG_TIMEOUT;
		return SRB_ERROR_TIMEOUT;
	    } else {
		/* ����¾�Υ��顼ȯ�� */
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
 * ��ǽ
 *      �Хåե�������size�����ɤ�
 *
 * ����
 *      struct streambuffer *srb         ���ȥ꡼��Хåե���¤��
 *      int                  size        �ɤॵ����
 *
 * �֤���
 *  SRB_OK              ����
 *  SRB_ERROR_IO        IO���顼
 *  SRB_ERROR_MEM       ���ꥨ�顼
 *  SRB_ERROR_TIMEOUT   �����ॢ����
 *
 */
static int
srb_read_buf(struct streambuffer *srb, int size)
{
    int len;

    if (size <= 0) {
	/* �ɤ�ɬ�פ��ʤ��ΤǤ��Τޤ��֤� */
	return SRB_OK;
    }

    srb->srb_buf = dg_realloc(srb->srb_buf, srb->srb_len + size + 1);
    if (srb->srb_buf == NULL) {
        /* ���ꥨ�顼 */
        srb->srb_errno = errno;
        srb->srb_flag |= SRB_FLAG_MEMERROR;
        return SRB_ERROR_MEM;
    }

    len = read(srb->srb_in, srb->srb_buf + srb->srb_len, size);
    if(len > 0) {
	srb->srb_len += len;
	srb->srb_buf[srb->srb_len] = '\0';
    } else if (len == 0) {
	/* EOF��ã���� */
	srb->srb_flag |= SRB_FLAG_EOF;
	return SRB_OK;
    } else {
	/* len < 0 */
	if (errno == EINTR) {
	    /* �����ߤ����ä��Τǥ��顼�ˤϤ��ʤ� */
	    return SRB_OK;
	} else if(errno == EWOULDBLOCK) {
	    /* �����ॢ����ȯ�� */
	    srb->srb_errno = errno;
	    srb->srb_flag |= SRB_FLAG_TIMEOUT;
	    return SRB_ERROR_TIMEOUT;
	} else {
	    /* IO���顼ȯ�� */
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
 * ��ǽ
 *       �Хåե�����Ƭ�ˤʤ�ݥ��󥿤Τ�Τ��֤�������
 *
 * ����
 *       struct streambuffer *srb         ���ȥ꡼��Хåե���¤��
 *       char                *nextdata    ������Ƭ�ˤʤ�ݥ���
 *       int                 *size        ������
 *
 * �֤���
 *       ret_str	�֤�������줿�Хåե�
 *       NULL		���ꥨ�顼
 *
 */
static char *
replace_buffer(struct streambuffer *srb, char *nextdata, int *size)
{
    char *ret_str = NULL;

    if (*size == srb->srb_len + 1) {
	/* *size��'\0'��ޤ᤿�Хåե���������Ʊ����� */
	ret_str = srb->srb_buf;
	srb->srb_buf = NULL;
	srb->srb_len = 0;
    } else {
	ret_str = srb->srb_buf;
	srb->srb_len -= nextdata - srb->srb_buf;

	srb->srb_buf = (char *) malloc(srb->srb_len + 1);
        if (srb->srb_buf == NULL) {
            /* ���ꥨ�顼 */
            srb->srb_errno = errno;
            srb->srb_flag |= SRB_FLAG_MEMERROR;
            return NULL;
        }

	memcpy(srb->srb_buf, nextdata, srb->srb_len);
	srb->srb_buf[srb->srb_len] = '\0';
	*(ret_str + *size - 1) = '\0';
        ret_str = (char *) dg_realloc(ret_str, *size);
        if (ret_str == NULL) {
            /* ���ꥨ�顼 */
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
 * ��ǽ
 *      ���ȥ꡼��Хåե����饵����������ɤ߹���
 *
 * ����
 *      struct streambuffer *srb       ���ȥ꡼��Хåե���¤��
 *      int                 *size      �ɤޤ줿������
 *      int                  rlen      �ɤ߹��ॵ����
 *
 * �֤���
 *      ret_str                        �ɤ߹�����Хåե�
 *      NULL                           ���顼
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
     * �ǡ������ɤ�ɬ�פ������srb�����ɤ�
     */
    if (rlen > srb->srb_len) {
	while (srb->srb_len < rlen) {
	    ret = srb_read_buf(srb, rlen - srb->srb_len);
	    if (srb->srb_flag & SRB_FLAG_ERRORS) {
		/* ���顼ȯ�� */
		*size = 0;
		return NULL;
	    }
	    if (srb->srb_flag & SRB_FLAG_EOF) {
		/* EOF��ã���Ƥ���Τ�ȴ���� */
		break;
	    }
	}
    }

    /* �Хåե������ʤ�NULL���֤� */
    if (srb->srb_len == 0) {
	*size = 0;
	return NULL;
    }

    /* rlen��ã�����������å� */
    if (srb->srb_len >= rlen) {
	endcmd = srb->srb_buf + rlen;
	nextdata = srb->srb_buf + rlen;
    } else if (srb->srb_flag & SRB_FLAG_EOF) {
	/* EOF��ã���Ƥ��� */
	endcmd = srb->srb_buf + srb->srb_len;
	nextdata = srb->srb_buf + srb->srb_len;
    }

    *size = endcmd - srb->srb_buf + 1; /* '\0'��ޤ᤿������ */
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
 * ��ǽ
 *     ���ȥ꡼��Хåե����鸡��ʸ����ޤǤ��������
 *     ����ʸ���󤬤��ä���ʸ������֤�
 *
 * ����
 *      struct streambuffer *srb         ���ȥ꡼��Хåե���¤��
 *      int                 *size        �ɤޤ줿������
 *      const char          *needle      ����ʸ����
 *
 * �֤���
 *      ret_str                   ����ʸ����ޤǤ�ʸ����
 *      NULL                      ���顼
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
	/* srb ����ǡ������ɤ� */
	ret = srb_read_buf(srb, SRB_BUFSIZE);
	if (srb->srb_flag & SRB_FLAG_ERRORS) {
	    /* ���顼ȯ�� */
	    *size = 0;
	    return NULL;
	}
    }
    if ((srb->srb_len == 0) && (srb->srb_flag & SRB_FLAG_EOF)) {
	/* �����ä����ΰ�������� */
	if (srb->srb_buf != NULL) {
	    free(srb->srb_buf);
	    srb->srb_buf = NULL;
	}
	*size = 0;
	return NULL;
    }

    /* �ԤκǸ夫�����å� */
    if (p != NULL) {
	endcmd = p + needlesize;
    } else {
	/* ���ԤϤʤ���EOF��ã���Ƥ��� */
	endcmd = srb->srb_buf + srb->srb_len;
    }

    *size = endcmd - srb->srb_buf + 1; /* '\0'��ޤ᤿������ */
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
 * ��ǽ
 *      back���ɤޤʤ��ä����Ȥˤ���
 *      back�򥹥ȥ꡼��Хåե�����Ƭ����������
 *
 * ����
 *      struct streambuffer *srb          ���ȥ꡼��Хåե���¤��
 *      char                *back         ����Хå�����Хåե�
 *      int                  size         back�Υ�����
 *
 * �֤���
 *  SRB_OK              ����
 *  SRB_ERROR_MEM       ���ꥨ�顼
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
            /* ���ꥨ�顼 */
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
            /* ���ꥨ�顼 */
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
