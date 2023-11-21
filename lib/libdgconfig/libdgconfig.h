/*
 * Config, Log Library
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */

#ifndef _LIBDGCONFIG_H_
#define _LIBDGCONFIG_H_

#include <stdio.h>

#ifdef SOLARIS

/* solarisの場合 */
#include <syslog.h>

#else /* SOLARIS */

/* solaris以外の場合 */
#define SYSLOG_NAMES
#include <syslog.h>

#endif /* SOLARIS */

/*--- 構造体 ---*/

/* 設定ファイル項目情報格納構造体 */
struct cfentry {
    char   *cf_name;
    unsigned int cf_type;
    char   *cf_default;         /* NULL if needed */
    int     cf_dataoffset;
    char   *(*cf_check) ();
};


/*--- グローバル変数 ---*/

extern int dgconfig_loglevel;


/*--- マクロ ---*/

/* 特別なファシリティ */
#define FACILITY_STDERR "stderr"
#define FACILITY_NONE   "none"

/* ログレベル */
#define LOGLVL_INFO     2
#define LOGLVL_WARNING  1
#define LOGLVL_ERROR    0

#define MAX_CONFIG_LINE      1024

/* 設定ファイルの設定値の型情報を示すフラグ */
#define CF_INTEGER      1
#define CF_INT_PLUS     2
#define CF_STRING       3
#define CF_FUNCTION     4

/* LDAPチェック関数 */
#define LDAP_VERSION_MIN     2
#define LDAP_VERSION_MAX     3
#define LDAP_SCOPE_ONELEVEL     "onelevel"
#define LDAP_SCOPE_SUBTREE      "subtree"

#define CONFIG_TRUE    1


/*--- 関数マクロ ---*/

/* syslogを呼び出す際に使用するマクロ */
#define SYSLOG (*dgconfig_log)

#define SYSLOGINFO(logcontent...) \
if (dgconfig_loglevel >= LOGLVL_INFO) { \
    SYSLOG(LOG_INFO, logcontent); \
}
#define SYSLOGWARNING(logcontent...) \
if (dgconfig_loglevel >= LOGLVL_WARNING) { \
    SYSLOG(LOG_WARNING, logcontent); \
}
#define SYSLOGERROR(logcontent...) \
if (dgconfig_loglevel >= LOGLVL_ERROR) { \
    SYSLOG(LOG_ERR, logcontent); \
}

/* 設定ファイル項目情報格納構造体で使用 */
#define OFFSET(x, y) ((size_t)&(((x *)NULL)->y))


/*--- エラーメッセージ ---*/

#define ERR_CONF_SYSLOGFACILITY "unknown syslog facility string"
#define ERR_CONF_OPEN           "Cannot open config file: %s :%s"
#define ERR_CONF_ALLOCATE       "Cannot allocate memory: %s"
#define ERR_CONF_TOOLONGLINE    "%s (line: %d) too long line"
#define ERR_CONF_SYNTAXERR      "%s (line: %d) syntax error"
#define ERR_CONF_TOOBIGNUM      "%s (line: %d) too large"
#define ERR_CONF_MUSTPLUS       "%s (line: %d) \"%s\" must be plus %d"
#define ERR_CONF_CHECKFUNC      "%s (line: %d) %s" 
#define ERR_CONF_NOTYPE         "Unknown data type %d"
#define ERR_CONF_MUSTSET        "%s: parameter \"%s\" must be set"
#define ERR_CONF_FILEDIR        "%s: %s"
#define ERR_CONF_PLUS           "invalid number"
#define ERR_CONF_IPADDR         "invalid ip address"
#define ERR_CONF_PORT           "invalid port number"
#define ERR_CONF_BOOL           "invalid number"
#define ERR_CONF_MAILADDR       "invalid mail address"
#define ERR_CONF_LDAPVER        "invalid LDAP database version"
#define ERR_CONF_LDAPSCAPE      "invalid LDAP database scope"
#define ERR_CONF_ONEATTR        "invalid attribute" 


/*--- プロトタイプ宣言 ---*/

extern int (*dgconfig_log) (int, const char *, ...);

extern int   syslog_facility(char *);
extern char *is_syslog_facility(char *);
extern void  dgloginit();
extern void  dglogchange(char *, char *);
extern int   read_config(char *, struct cfentry *, int, void *);
extern char *is_writable_directory(char *);
extern char *is_readable_file(char *);
extern char *is_inetaddr(char *);
extern char *is_ipaddr(char *);
extern char *is_plus(int);
extern char *is_port(int);
extern char *is_boolean(int);
extern char *is_mailaddr(char *);
extern char *is_ldapversion(int);
extern char *is_ldapscope(char *);
extern char *is_oneattr(char *);

#ifdef SOLARIS

/* solarisの場合 */
#define inet_aton(s, in)        _inet_aton(s, in)
extern int _inet_aton(const char *, struct in_addr *);

#endif


#endif  /* _LIBDGCONFIG_H_ */
