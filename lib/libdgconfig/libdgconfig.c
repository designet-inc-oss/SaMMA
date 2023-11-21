/*
 * Config, Log Library
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include "libdgconfig.h"

#ifdef SOLARIS

/* solaris�ξ�� */

typedef struct _code {
        char    *c_name;
        int     c_val;
} CODE;

CODE facilitynames[] =
  {
    { "auth", LOG_AUTH },
    { "cron", LOG_CRON },
    { "daemon", LOG_DAEMON },
    { "kern", LOG_KERN },
    { "lpr", LOG_LPR },
    { "mail", LOG_MAIL },
    { "news", LOG_NEWS },
    { "syslog", LOG_SYSLOG },
    { "user", LOG_USER },
    { "uucp", LOG_UUCP },
    { "local0", LOG_LOCAL0 },
    { "local1", LOG_LOCAL1 },
    { "local2", LOG_LOCAL2 },
    { "local3", LOG_LOCAL3 },
    { "local4", LOG_LOCAL4 },
    { "local5", LOG_LOCAL5 },
    { "local6", LOG_LOCAL6 },
    { "local7", LOG_LOCAL7 },
    { NULL, -1 }
  };

#endif /* SOLARIS */


/*--- �ץ�ȥ�������� ---*/

static int LOG(int, const char *, ...);
int dgconfig_loglevel;
int (*dgconfig_log) (int, const char *, ...) = (void *) syslog;


/*--- ����Ϣ�ؿ� ---*/

/*
 * syslog_facility
 *
 * ��ǽ
 *      syslog�ե�����ƥ��Υ����å���
 *      ����������syslog�ե�����ƥ��������ͤ��֤���
 *
 * ����
 *      char *str      �����å�ʸ����
 *
 * �֤���
 *      facilitynames[i].c_val     �����Х��ѿ��Ǥ���facilitynames��¤�Τ�
 *                                 ���ꤷ��syslog�ե�����ƥ���������
 *      -1                         �����Х��ѿ��Ǥ���facilitynames��¤�Τ�
 *                                 ���ꤷ��syslog�ե�����ƥ��˰��פ��ʤ��ä�
 *
 */
int
syslog_facility(char *str)
{
    int     i;

    for (i = 0; facilitynames[i].c_name != NULL; i++) {
	if (strcasecmp(str, facilitynames[i].c_name) == 0) {
	    return (facilitynames[i].c_val);
	}
    }
    return (-1);
}

/*
 * is_syslog_facility
 *
 * ��ǽ
 *      ��������Υ����å���
 *
 * ����
 *      char *str      �����å�ʸ����
 *
 * �֤���
 *      NULL                            ����
 *      ERR_CONF_SYSLOGFACILITY         ���顼��å�����
 *
 */
char *
is_syslog_facility(char *str)
{
    if (strcasecmp(str, FACILITY_STDERR) == 0) {
	return (NULL);
    }
    if (strcasecmp(str, FACILITY_NONE) == 0) {
	return (NULL);
    }

    if (syslog_facility(str) < 0) {
	return (ERR_CONF_SYSLOGFACILITY);
    }
    return (NULL);
}

/*
 * dgloginit
 *
 * ��ǽ
 *      ��������ν����(ɸ�२�顼���Ϥˤ���)��
 *
 * ����
 *      ̵��
 *
 * �֤���
 *      ̵��
 *
 */
void
dgloginit()
{
    dgconfig_log = LOG;
}

/*
 * LOG
 *
 * ��ǽ
 *      ɸ�२�顼����(stderr)�ؤν񤭹��ߡ�
 *
 * ����
 *      int         type         �������碌
 *      const char *fmt          ���ϥե����ޥå�
 *      ����                     ���ϥե����ޥåȤΰ���
 *
 * �֤���
 *      0                        ����
 *
 */
static int
LOG(int type, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    return (0);
}

/*
 * NoLOG
 *
 * ��ǽ
 *      �����Ϥʤ�(none)�μ��Ρ�
 *
 * ����
 *      int         type         �������碌
 *      const char *fmt          ���ϥե����ޥå�
 *      ����                     ���ϥե����ޥåȤΰ���
 *
 * �֤���
 *      0                        ����
 *
 */
static int
NoLOG(int type, const char *fmt, ...)
{
    return (0);
}

/*
 * dglogchange
 *
 * ��ǽ
 *      �������������(*log������) syslog�ξ���openlog��Ԥ���
 *
 * ����
 *      char *name              �ץ����̾��openlog�ؿ�����������
 *      char *facility_name     ��������⤷����syslog�ե�����ƥ�
 *
 * �֤���
 *      ̵��
 *
 */
void
dglogchange(char *name, char *facility_name)
{
    int     facility;

    if (strcasecmp(facility_name, FACILITY_STDERR) == 0) {
	dgconfig_log = LOG;
	return;
    }
    if (strcasecmp(facility_name, FACILITY_NONE) == 0) {
	dgconfig_log = NoLOG;
	return;
    }

    closelog();

    facility = syslog_facility(facility_name);

    openlog(name, LOG_PID, facility);

    dgconfig_log = (void *) syslog;
}


/*--- ����ե������Ϣ�ؿ� ---*/

/*
 * read_config
 *
 * ��ǽ
 *      �ե������open��������ե�������ɤ߹���
 *      ���顼��SYSLOG(�ޥ���)�˽��Ϥ��롣
 *
 * ����
 *      char           *file      �ե�����̾
 *      struct cfentry *fmt       ������ܤι�¤��
 *      int             count     �����ͤ��Ǽ���빽¤�ΤΥ�����
 *                                 (sizeof([������ܤι�¤��̾]) / 
 *                                                      sizeof(struct cfentry))
 *      void           *data      �����ͤ��Ǽ���빽¤��
 *
 * �֤���
 *      -1             �ɹ���̵����fopen���ԡ��������ȥ��顼��
 *       1             ����ե������1�Ԥ�Ĺ�������
 *      error          0�����顼�ʤ�
 *                     1�ʾ塧�����ʹԤ�����
 *
 */
int
read_config(char *file, struct cfentry *cfe, int count, void *data)
{
    int     i;
    int     len;
    char    line[MAX_CONFIG_LINE + 1];
    FILE   *fp;
    char   *p;
    int     nline;
    int     error = 0;
    char   *str;
    int    *check;

    if ((p = is_readable_file(file)) != NULL) {
        SYSLOG(LOG_WARNING, p);
        return (-1);
    }

    fp = fopen(file, "r");
    if (fp == NULL) {
        SYSLOG(LOG_WARNING, ERR_CONF_OPEN, file, strerror(errno));
        return (-1);
    }
    check = (int *) malloc((sizeof(int)) * count);
    if (check == NULL) {
        SYSLOG(LOG_WARNING, ERR_CONF_ALLOCATE, strerror(errno));
        fclose(fp);
        return (-1);
    }

    memset(check, 0, sizeof(int) * count);

    for (nline = 1; fgets(line, MAX_CONFIG_LINE + 1, fp) != NULL; nline++) {

        p = strchr(line, '\n');
        if (p == NULL) {
            SYSLOG(LOG_WARNING, ERR_CONF_TOOLONGLINE, file, nline);
            fclose(fp);
            free(check);
            return (-2);
        }
        *p = '\0';

        if ((line[0] == '#') || (line[0] == '\0')) {
            /* comment or null line */
            continue;
        }

        for (i = 0; i < count; i++) {
            len = strlen(cfe[i].cf_name);

            if ((strncasecmp(line, cfe[i].cf_name, len) == 0) &&
                (line[len] == '=') && !isspace((int) line[len + 1])) {
                /* keyword match */

                str = &line[len + 1];

                check[i] = CONFIG_TRUE;

                switch (cfe[i].cf_type) {
                case CF_INTEGER:
                case CF_INT_PLUS:
                    {
                        unsigned int value;
                        char   *tmp;

                        value = strtol(str, &tmp, 10);

                        /* skip trailing blank, if *tmp is blank space */
                        while (isblank(*tmp)) {
                            tmp++;
                        };

                        if (*tmp != '\0') {
                            SYSLOG(LOG_WARNING, ERR_CONF_SYNTAXERR,
                                                file, nline);
                            error++;
                            break;
                        } else {
                            if ((value == UINT_MAX) && (errno == ERANGE)) {
                                SYSLOG(LOG_WARNING, ERR_CONF_TOOBIGNUM,
                                       file, nline);
                                error++;
                                break;
                            }
                            if ((cfe[i].cf_type == CF_INT_PLUS) &&
                                (value > UINT_MAX)) {
                                SYSLOG(LOG_WARNING, ERR_CONF_MUSTPLUS,
                                       file, nline, cfe[i].cf_name, value);
                                error++;
                                break;
                            }

                            if (cfe[i].cf_check != NULL) {
                                char   *estr;

                                estr = (*cfe[i].cf_check) (value);
                                if (estr != NULL) {
                                    SYSLOG(LOG_WARNING, ERR_CONF_CHECKFUNC,
                                           file, nline, estr);
                                    error++;
                                    break;
                                }
                            }
                        }

                        *((unsigned int *) (data + cfe[i].cf_dataoffset)) =
                            value;
                        break;
                    }
                case CF_STRING:
                    {
                        char   *estr;
                        int     j;

                        if (cfe[i].cf_check != NULL) {
                            estr = (*cfe[i].cf_check) (str);
                            if (estr != NULL) {
                                SYSLOG(LOG_WARNING, ERR_CONF_CHECKFUNC,
                                       file, nline, estr);
                                error++;
                                break;
                            }
                        }

                        for (j = len + 1; line[j] != '\0'; j++) {
                            if (!isspace((int) line[j])) {
                                break;
                            }
                        }

                        if (line[j] == '\0') {
                            /* ignore because all charactors are space */
                            break;
                        }

                        estr = strdup(str);
                        if (estr == NULL) {
                            SYSLOG(LOG_WARNING, ERR_CONF_ALLOCATE,
                                   strerror(errno));
                            error++;
                        } else {
                            *((char **) (data + cfe[i].cf_dataoffset)) =
                                estr;
                        }
                        break;
                    }
                case CF_FUNCTION:
                    {
                        char *estr;

                        estr = (*cfe[i].cf_check)(
                            str,
                            (data + cfe[i].cf_dataoffset)
                        );
                        if (estr != NULL) {
                            SYSLOG(LOG_WARNING, ERR_CONF_CHECKFUNC,
                                   file, nline, estr);
                            error++;
                            break;
                        }

                        break;
                    }
                default:
                    SYSLOG(LOG_WARNING, ERR_CONF_NOTYPE, cfe[i].cf_type);
                    error++;
                    break;
                }
                break;
            }
        }

        if (i == count) {
            /* illegal line */
            SYSLOG(LOG_WARNING, ERR_CONF_SYNTAXERR, file, nline);
            error++;
        }
    }

    fclose(fp);

    for (i = 0; i < count; i++) {
        if (check[i] != CONFIG_TRUE) {
            /* if allow, convert default */
            if (cfe[i].cf_default) {
                switch (cfe[i].cf_type) {
                case CF_INTEGER:
                case CF_INT_PLUS:
                    *((unsigned int *) (data + cfe[i].cf_dataoffset)) =
                        atoi(cfe[i].cf_default);
                    break;
                case CF_STRING:
                    str = strdup(cfe[i].cf_default);
                    if (str == NULL) {
                        SYSLOG(LOG_WARNING, ERR_CONF_ALLOCATE, strerror(errno));
                        error++;
                    } else {
                        *((char **) (data + cfe[i].cf_dataoffset)) = str;
                    }
                    break;
                }
                continue;
            } else {
                SYSLOG(LOG_WARNING, ERR_CONF_MUSTSET, file, cfe[i].cf_name);
                error++;
            }
        }
    }

    free(check);
    return (error);
}

/*
 * is_writable_directory
 *
 * ��ǽ
 *      �ǥ��쥯�ȥ�ν񤭹��߸������å���
 *
 * ����
 *      char *str      �����å�ʸ����
 *
 * �֤���
 *      NULL           ����
 *      errbuf         ���顼��å�����
 *
 */
char *
is_writable_directory(char *str)
{
    static char errbuf[MAX_CONFIG_LINE];
    struct stat st;

    if (stat(str, &st) < 0) {
        sprintf(errbuf, ERR_CONF_FILEDIR, str, strerror(errno));
        return (errbuf);
    }

    if (!S_ISDIR(st.st_mode)) {
        errno = ENOTDIR;
        sprintf(errbuf, ERR_CONF_FILEDIR, str, strerror(errno));
        return (errbuf);
    }

    if (access(str, W_OK) != 0) {
        sprintf(errbuf, ERR_CONF_FILEDIR, str, strerror(errno));
        return (errbuf);
    }
    return (NULL);
}

/*
 * is_readable_file
 *
 * ��ǽ
 *      �ե�������ɤ߹��߸������å���
 *
 * ����
 *      char *str      �����å�ʸ����
 *
 * �֤���
 *      NULL           ����
 *      errbuf         ���顼��å�����
 *
 */
char *
is_readable_file(char *str)
{
    static char errbuf[MAX_CONFIG_LINE];
    struct stat st;

    if (stat(str, &st) < 0) {
        sprintf(errbuf, ERR_CONF_FILEDIR, str, strerror(errno));
        return (errbuf);
    }

    if (S_ISDIR(st.st_mode)) {
        errno = EISDIR;
        sprintf(errbuf, ERR_CONF_FILEDIR, str, strerror(errno));
        return (errbuf);
    }

    if (access(str, R_OK) != 0) {
        sprintf(errbuf, ERR_CONF_FILEDIR, str, strerror(errno));
        return (errbuf);
    }
    return (NULL);
}

/*
 * is_inetaddr
 *
 * ��ǽ
 *      IP���ɥ쥹�񼰥����å���
 *      (inet_aton�ؿ�������[1,1.1,1.1.1���Υ���ब­��ʤ����Ǥ�������֤�])
 *
 * ����
 *      char *str      �����å�ʸ����
 *
 * �֤���
 *      NULL                    ����
 *      ERR_CONF_IPADDR         ���顼��å�����
 *
 */
char *
is_inetaddr(char *str)
{
    struct in_addr in;

    if (inet_aton(str, &in) == 0) {
        return (ERR_CONF_IPADDR);
    }
    return (NULL);
}

/*
 * is_ipaddr
 *
 * ��ǽ
 *      IP���ɥ쥹�񼰥����å���
 *      (1,1.1,1.1.1���Υ���ब­��ʤ����ˤ⥨�顼�Ȥ�����])
 *
 * ����
 *      char *str      �����å�ʸ����
 *
 * �֤���
 *      NULL                    ����
 *      ERR_CONF_IPADDR         ���顼��å�����
 *
 */
char *
is_ipaddr(char *str)
{
    struct in_addr in;
    int            count;
    char          *po1;

    if (inet_aton(str, &in) == 0) {
        return (ERR_CONF_IPADDR);
    }

    // �����ο���Ĵ�٤�
    po1 = str;
    count = 0;
    while ((po1 = strchr(po1, '.')) != NULL) {
        count++;
        po1++;
    }

    // �ԥꥪ�ɤ�3�ĤǤʤ����ϥ��顼
    if (count != 3) {
        return (ERR_CONF_IPADDR);
    }

    return (NULL);
}

/*
 * is_plus
 *
 * ��ǽ
 *      �ݡ����ֹ�Υ����å���0��65535�ˡ�
 *
 * ����
 *      int value      �����å�����
 *
 * �֤���
 *      NULL                  ����
 *      ERR_CONF_PLUS         ���顼��å�����
 *
 */
char *
is_plus(int value)
{
    if (value <= 0) {
        return (ERR_CONF_PLUS);
    }

    return (NULL);
}

/*
 * is_port
 *
 * ��ǽ
 *      �ݡ����ֹ�Υ����å���0��65535�ˡ�
 *
 * ����
 *      int value      �����å�����
 *
 * �֤���
 *      NULL                  ����
 *      ERR_CONF_PORT         ���顼��å�����
 *
 */
char *
is_port(int value)
{
    if (value < 0 || value > USHRT_MAX) {
        return (ERR_CONF_PORT);
    }
    return (NULL);
}

/*
 * is_boolean
 *
 * ��ǽ
 *      0,1�Υ����å���
 *
 * ����
 *      int value      �����å�����
 *
 * �֤���
 *      NULL                  ����
 *      ERR_CONF_BOOL         ���顼��å�����
 *
 */
char *
is_boolean(int value)
{
    if (value != 0 && value != 1) {
        return (ERR_CONF_BOOL);
    }
    return (NULL);
}

/*
 * is_mailaddr
 *
 * ��ǽ
 *      �᡼�륢�ɥ쥹�Υ����å���
 *      (@���ޤޤ�Ƥ��ꡢ����.���ޤޤ�Ƥ��뤫������å�)
 *
 * ����
 *      char *str                  �����å�ʸ����
 *
 * �֤���
 *      NULL                       ����
 *      ERR_CONF_MAILADDR          ���顼��å�����
 *
 */
char *
is_mailaddr(char *str)
{
    if ((strchr(str, '@') == NULL) || (strchr(str, '.') == NULL)) {
        return (ERR_CONF_MAILADDR);
    }
    return (NULL);
}

/*
 * is_ldapversion
 *
 * ��ǽ
 *      LDAP�ΥС����������å�(2, 3)��
 *
 * ����
 *      int value      �����å�����
 *
 * �֤���
 *      NULL                     ����
 *      ERR_CONF_LDAPVER         ���顼��å�����
 *
 */
char *
is_ldapversion(int value)
{
    if (value < LDAP_VERSION_MIN || value > LDAP_VERSION_MAX) {
        return (ERR_CONF_LDAPVER);
    }
    return (NULL);
}

/*
 * is_ldapscope
 *
 * ��ǽ
 *      LDAP�������פΥ����å�("onelevel", "subtree")��
 *
 * ����
 *      char *str      �����å�ʸ����
 *
 * �֤���
 *      NULL                       ����
 *      ERR_CONF_LDAPSCAPE         ���顼��å�����
 *
 */
char *
is_ldapscope(char *str)
{
    if (strcmp(str, LDAP_SCOPE_ONELEVEL) && strcmp(str, LDAP_SCOPE_SUBTREE)) {
        return (ERR_CONF_LDAPSCAPE);
    }
    return NULL;
}

/*
 * is_oneattr
 *
 * ��ǽ
 *     �ͤ�Ⱦ�Ѷ��򤬴ޤޤ�Ƥ��ʤ����Ȥ�����å���
 *
 * ����
 *      char *str      �����å�ʸ����
 *
 * �֤���
 *      NULL                     ����
 *      ERR_CONF_ONEATTR         ���顼��å�����
 *
 */
char *
is_oneattr(char *str)
{
    if (strchr(str, ' ') != NULL) {
        return (ERR_CONF_ONEATTR);
    }
    return (NULL);
}

#ifdef SOLARIS

int
_inet_aton(const char *s, struct in_addr *in)
{
     char *p1;
     char *p2;
     unsigned int ret1;
     unsigned int ret2;
     unsigned int ret3;
     unsigned int ret4;
     int   addr;

     p1 = (char *)s;
     ret1 = strtoul(p1, &p2, 10);
     if((ret1 > 255) || (p1 == p2) || (*p2 != '.')) {
          return(0);
     }

     p1 = p2 + 1;
     ret2 = strtoul(p1, &p2, 10);
     if((ret2 > 255) || (p1 == p2) || (*p2 != '.')) {
          return(0);
     }

     p1 = p2 + 1;
     ret3 = strtoul(p1, &p2, 10);
     if((ret3 > 255) || (p1 == p2) || (*p2 != '.')) {
          return(0);
     }

     p1 = p2 + 1;
     ret4 = strtoul(p1, &p2, 10);
     if((ret4 > 255) || (p1 == p2) || (*p2 != '\0')) {
          return(0);
     }

     p1 = (char *)&addr;

     p1[0] = ret1;
     p1[1] = ret2;
     p1[2] = ret3;
     p1[3] = ret4;

     in->s_addr = addr;

     return(1);
}

#endif
