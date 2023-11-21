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


/*--- �ؿ� ---*/

/*
 * strset_init
 *
 * ��ǽ
 *	strset�ι�¤�Τ��������롣
 *
 * ����
 *	struct strset *ss	���������strset���ΰ�
 *
 * �֤���
 *	�ʤ�
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
 * ��ǽ
 *	strset�ι�¤�Τ�ʸ��������ꤹ�롣
 *
 * ����
 *	struct strset *ss	���������strset���ΰ�
 *	char          *str	���ꤹ��ʸ����
 *
 * �֤���
 *	�ʤ�
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
 * ��ǽ
 *	strset�ι�¤�Τ˳�����Ƥ��Ƥ���ʸ����������롣
 *      strset���ΰ褽�Τ�Τϳ������ʤ��Τǡ���դ�ɬ�פǤ���
 *
 * ����
 *	struct strset *ss	��������strset���ΰ�
 *
 * �֤���
 *	�ʤ�
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
 * ��ǽ
 *	2�Ĥ�strset�ι�¤�Τ˳�����Ƥ��Ƥ���ʸ�����Ϣ�뤹�롣
 *      ss1¦��Ϣ�뤵��롣ss2¦����������뤳�ȤϤʤ���
 *
 * ����
 *	struct strset *ss1	Ϣ�븵
 *	struct strset *ss2	Ϣ��ʸ���󥻥å�
 *
 * �֤���
 *	����	0
 *	�۾�	-1	(Ϣ���Ѥ��ΰ褬������Ƥ��ʤ�)
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
 * ��ǽ
 *	strset�ι�¤�Τ˳�����Ƥ��Ƥ���ʸ����ˡ�ʸ�����Ϣ�뤹�롣
 *
 * ����
 *	struct strset *ss1	Ϣ�븵ʸ���󥻥å�
 *	char          *str	Ϣ�뤹��ʸ����
 *
 * �֤���
 *	����	0
 *	�۾�	-1	(Ϣ���Ѥ��ΰ褬������Ƥ��ʤ�)
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
 * ��ǽ
 *	strset�ι�¤�Τ˳�����Ƥ��Ƥ���ʸ����ˡ�ʸ�����Ϣ�뤹�롣
 *      ʸ�������λ��ꤷ��ʸ����������Ϣ�뤵��롣
 *
 * ����
 *	struct strset *ss1	Ϣ�븵ʸ���󥻥å�
 *	char          *str	Ϣ�뤹��ʸ����
 *      int            len	Ϣ�뤹��ʸ�����Ĺ��
 *
 * �֤���
 *	����	0
 *	�۾�	-1	(Ϣ���Ѥ��ΰ褬������Ƥ��ʤ�)
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
 * ��ǽ
 *	ʸ������λ��ꤷ��ʸ�������̤�ưŪ�ΰ�˥��ԡ����롣
 *
 * ����
 *	char          *str	���ԡ�����ʸ����
 *      int            len	���ԡ�����ʸ�����Ĺ��
 *
 * �֤���
 *	����	0
 *	�۾�	-1	(���ԡ��Ѥ��ΰ褬������Ƥ��ʤ�)
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
 * ��ǽ
 *	ʸ������Υ������ִ�����������ưŪ�ΰ�˳�Ǽ���롣
 *
 * ����
 *	char          *str	���ԡ�����ʸ����
 *	char          *start	�����γ���ʸ����
 *	char          *end	�����ν�λʸ����
 *	struct strtag *tag	�ִ�ʸ�����������äƤ�������
 *	int            num	tag���ΰ�˳�Ǽ����Ƥ�������θĿ�
 *
 * �֤���
 *	����	�Ѵ����ʸ����
 *	�۾�	NULL	(���ԡ��Ѥ��ΰ褬������Ƥ��ʤ�)
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
 * ��ǽ
 *	����꡼�����ʤ�realloc
 *
 * ����
 *	void  *obuf	�������Ȥ����ѿ�
 *	size_t len	�������Ȥ������Х��ȿ�
 *
 * �֤���
 *	nbuf		�������Ȥ����ѿ�
 *	NULL		�������ȥ��顼
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
 * ����
 *      inbuf�ǻ��ꤷ��ʸ�����ʸ�������� from ���� to���Ѵ����롣
 *
 * ����
 *      char *from      ����¦ʸ��������
 *      char *inbuf     �����ѥХåե�
 *
 * �֤���
 *     ����     �Ѵ����ʸ����
 *     �۾�     NULL
 *                      errno�ˡ������ͤ����ꤵ���
 *                      EINVAL  ���ꤷ��ʸ�������ɤ��Ѵ��Ǥ��ʤ�̾���Ǥ��롣
 *                      EILSEQ  ʸ��������Ѵ��Ǥ��ʤ�ʸ���������󥹤����롣
 *                      ENOMEM  ���ꥨ�顼
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
    /* icd���������� */
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

    /* NULL��ü���� */
    newbuf[bufsize - outleft] = '\0';

    iconv_close(icd);
    return newbuf;
}



/**
 * str2code�ǡ������¸ʸ���������äƤ������ˤ����'?'���֤��������ߤ�
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
    /* icd���������� */
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

    /* NULL��ü���� */
    newbuf[bufsize - outleft] = '\0';

    iconv_close(icd);
    free(orig);
    return newbuf;
}

/*
 * mf_str2euc
 *
 * ����
 *  ����ʸ�����type����to���Ѵ����롣
 *  type������Ѵ��˼��Ԥ����顢���ν�����Ѵ����ߤ�
 *   EUC-JP -> EUC-JP
 *   ISO-2022-JP -> EUC-JP
 *   Shift_JIS -> EUC-JP
 *
 * ����
 *  char *sbuf          �Ѵ�����ʸ����
 *  char **retbuf       �Ѵ����ʸ������Ǽ����ݥ���
 *  char *type          sbuf �Υ����ɤȻפ������������
 *
 * �֤���
 *  0   ����
 *  1   �ǥ����ɤ˼���
 *  -1  ���ꥨ�顼
 */
int
dg_str2code(char *sbuf, char **retbuf, char *type, char *to)
{
    errno = 0;
    *retbuf = str2code(type, to, sbuf);
    if (*retbuf == NULL) {
        /* ���Ԥ��� */
        if (errno == ENOMEM) {
            /* ���ꥨ�顼 */
            return -1;
        }
        /* ¾�Υ����ɤ��Ѵ��Ǥ��뤫��Ƥߤ� */
        /* EUC-JP -> ISO-2022-JP */
#ifdef SOLARIS
        *retbuf = str2code("eucJP", to, sbuf);
#else
        *retbuf = str2code("EUC-JP", to, sbuf);
#endif
        if (*retbuf == NULL) {
            /* ���Ԥ��� */
            if (errno == ENOMEM) {
                /* ���ꥨ�顼 */
                return -1;
            }
            /* ISO-2022-JP -> ISO-2022-JP */
            *retbuf = str2code("ISO-2022-JP", to, sbuf);
            if (*retbuf == NULL) {
                /* ���Ԥ��� */
                if (errno == ENOMEM) {
                    /* ���ꥨ�顼 */
                    return -1;
                }
                /* SJIS -> ISO-2022-JP */
                *retbuf = str2code("SJIS", to, sbuf);
                if (*retbuf == NULL) {
                    /* ���Ԥ��� */
                    if (errno == ENOMEM) {
                        /* ���ꥨ�顼 */
                        return -1;
                    }
                    /* �б����륳���ɤ����� */
                    return 1;
                }
            }
        }
    }
    return 0;
}

/**
 * dg_str2code�ǡ�str2code_replace��Ȥ��С������
 */
int
dg_str2code_replace(char *sbuf, char **retbuf, char *type, char *to)
{
    errno = 0;
    *retbuf = str2code_replace(type, to, sbuf);
    if (*retbuf == NULL) {
        /* ���Ԥ��� */
        if (errno == ENOMEM) {
            /* ���ꥨ�顼 */
            return -1;
        }
        /* ¾�Υ����ɤ��Ѵ��Ǥ��뤫��Ƥߤ� */
        /* EUC-JP -> ISO-2022-JP */
#ifdef SOLARIS
        *retbuf = str2code_replace("eucJP", to, sbuf);
#else
        *retbuf = str2code_replace("EUC-JP", to, sbuf);
#endif
        if (*retbuf == NULL) {
            /* ���Ԥ��� */
            if (errno == ENOMEM) {
                /* ���ꥨ�顼 */
                return -1;
            }
            /* ISO-2022-JP -> ISO-2022-JP */
            *retbuf = str2code_replace("ISO-2022-JP", to, sbuf);
            if (*retbuf == NULL) {
                /* ���Ԥ��� */
                if (errno == ENOMEM) {
                    /* ���ꥨ�顼 */
                    return -1;
                }
                /* SJIS -> ISO-2022-JP */
                *retbuf = str2code_replace("SJIS", to, sbuf);
                if (*retbuf == NULL) {
                    /* ���Ԥ��� */
                    if (errno == ENOMEM) {
                        /* ���ꥨ�顼 */
                        return -1;
                    }
                    /* �б����륳���ɤ����� */
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
 * dg_str2code��str2code_replace��Ȥ����Ѵ�������������Ѵ����ƾȹ礹��
 *
 * [Arguments]
 *  sbuf           ʸ���������Ѵ�����ʸ����
 *  retbuf         ʸ���������Ѵ����ʸ����
 *  type           �Ѵ�����ʸ�����ʸ�������ɡ�UTF-8�����ꡣ
 *  to             �Ѵ����ʸ��������
 *  lastFromChar   �Ǹ��ʸ���������Ѵ����������Ȥ��Ρ�����ʸ��������̾���֤�
 *  maxStrCodeSize  "ISO-2022-JP"�ʤɤ�ʸ����κ����Ĺ����13�Х��Ȱʾ������
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
        /* ���Ԥ��� */
        if (errno == ENOMEM) {
            /* ���ꥨ�顼 */
            // ���ꥨ�顼����lastFromChar���֤��ʤ�
            return -1;
        }
        /* ¾�Υ����ɤ��Ѵ��Ǥ��뤫��Ƥߤ� */
        /* EUC-JP -> */
#ifdef SOLARIS
        currentFromCharNum = 2;
        *retbuf = str2code_replace("eucJP", to, sbuf);
#else
        currentFromCharNum = 1;
        *retbuf = str2code_replace("EUC-JP", to, sbuf);
#endif
        if (*retbuf == NULL) {
            /* ���Ԥ��� */
            if (errno == ENOMEM) {
                /* ���ꥨ�顼 */
                // ���ꥨ�顼����lastFromChar���֤��ʤ�
                return -1;
            }
            /* ISO-2022-JP -> */
            currentFromCharNum = 3;
            *retbuf = str2code_replace("ISO-2022-JP", to, sbuf);
            if (*retbuf == NULL) {
                /* ���Ԥ��� */
                if (errno == ENOMEM) {
                    /* ���ꥨ�顼 */
                    // ���ꥨ�顼����lastFromChar���֤��ʤ�
                    return -1;
                }
                /* SJIS -> */
                currentFromCharNum = 4;
                *retbuf = str2code_replace("SJIS", to, sbuf);
                if (*retbuf == NULL) {
                    /* ���Ԥ��� */
                    if (errno == ENOMEM) {
                        /* ���ꥨ�顼 */
                        // ���ꥨ�顼����lastFromChar���֤��ʤ�
                        return -1;
                    }
                    /* �б����륳���ɤ����� */
                    return 1;
                }
            }
        }
    }

    // �Ѵ��������ˡ��Ǹ���Ѵ��˻��Ѥ���FromCharset�򥳥ԡ�����
    p = strncpy(lastFromChar, codelist[currentFromCharNum], maxStrCodeSize);
    *(p + maxStrCodeSize - 1) = '\0';

    // Validation: Instruct the reverse conversion
    // and compare original strings with converted strings.
    *validatebuf = str2code_replace(to, lastFromChar, *retbuf);
    // null ���顼����
    if (*validatebuf == NULL) {
        /* ���Ԥ��� */
        if (errno == ENOMEM) {
            /* ���ꥨ�顼 */
            return -1;
        }
        /* ���Ѵ����� */
        return 2;
    }
    if (strcmp(*validatebuf, sbuf) != 0) {
        /* ���Ѵ��θ����԰��� */
        return 2;
    }
    return 0;

}
