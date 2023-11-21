/*
 * String Utility Library
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */

#ifdef HAVE_CONFIGH
#include "../../config.h"
#endif

#ifndef _LIBDGSTR_H_
#define _LIBDGSTR_H_

/*--- ��¤�� ---*/

struct strset {
    char   *ss_str;
    int     ss_len;
};

struct strtag {
    char   *st_tag;
    int     st_taglen;
    char   *st_str;
};


/*--- �ޥ��� ---*/

#define strset_catchar(ss, c) strset_catnstr(ss, &c, 1)
#define ICONV_ERROR           ((iconv_t)-1)
#define BUFSIZE               1024

// �����¸ʸ���ʤɡ�iconv���Ѵ�����ʤ��ä�ʸ�����֤�������
#define LIBDG_PLACEHOLDER '?'


/*--- �ץ�ȥ�������� ---*/

extern void strset_init(struct strset *);
extern void strset_set(struct strset *, char *str);
extern void strset_free(struct strset *);
extern int  strset_catstrset(struct strset *, struct strset *);
extern int  strset_catstr(struct strset *, char *);
extern int  strset_catnstr(struct strset *, char *, int);

#ifndef HAVE_STRNDUP
extern char *strndup(char *, int);
#endif

extern char *str_replace_tag(char *, char *, char *, struct strtag *, int);
extern char *sql_rep(char *, int);
extern int   iseuc(unsigned char);
extern void *dg_realloc(void *, size_t);
extern char *str2code(char *, char *, char *);
extern int   dg_str2code(char *, char **, char *, char *);
// �����¸ʸ�����֤������褦�Ȥ���С������
extern char *str2code_replace(char *, char *, char *);
extern int   dg_str2code_replace(char *, char **, char *, char *);
// �����¸ʸ�����֤������褦�Ȥ���С������+���Ѵ�����
extern int   dg_str2code_replace_validate(char *, char **, char *, char *, char **, char *, size_t);

#endif  /* _LIBDGSTR_H_ */
