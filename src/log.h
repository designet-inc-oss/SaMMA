/*
 * samma
 *
 * Copyright (C) 2006,2007,2008,2011 DesigNET, INC.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/*
 * $RCSfile: log.h,v $
 * $Revision: 1.17 $
 * $Date: 2013/09/19 01:30:56 $
 */
#ifndef _SAMMA_LOG_H
#define _SAMMA_LOG_H

#include <errno.h>
#include <string.h>

#define SYSLOG_IDENT "samma"

#define ERR_CONFIG_NULL			"%s: Config is null."
#define ERR_CONFIG_ENCRYPTION_NULL	"%s: EncryptionTmpDir is not set."
#define ERR_CONFIG_ZIPCOMMAND_NULL	"%s: ZipCommand is not set."
#define ERR_CONFIG_READ			"%s: Cannot reload samma config.(%s)"
#define STDERR_CONFIG_READ		"Cannot load samma config.(%s)"
#define ERR_CONFIG_RELOADING		"%s: Cannot reload config(%s): (still refered)"
#define CONFIG_RELOADING		"%s: reload config(%s)"
#define ERR_TEMPLATE_READ		"%s: Template file is empty.(%s)"
#define ERR_TEMPLATE_RELOADING		"%s: Cannot reload template(%s): (still refered)"
#define TEMPLATE_RELOADING		"%s: reload template(%s)"
#ifdef __CUSTOMIZE2018
#define ADDMSG_RELOADING		"%s: reload add message templates"
#define ERR_ADDMSG_RELOADING		"%s: Cannot reload add message templates: (still refered)"
#endif	// __CUSTOMIZE2018


/* ADD(20150316)*/
#define ERR_WHITELIST_RELOADING		"%s: Cannot reload whitelist(%s): (still refered)"
#define ERR_WHITELIST_INVALID_IP	"%s: IP address (%s) is invalid."
#define ERR_WHITELIST_IP_INVALID	"%s: IP address (%s) is invalid (Line: %d)"
#define ERR_WHITELIST_MASK_NOT_NUM	"%s: Netmask(%s) is not number (Line: %d)"
#define ERR_WHITELIST_MASK_RANGEV4      "%s: Netmask(%d) from 1 to 32 (Line: %d)"
#define ERR_WHITELIST_MASK_RANGEV6      "%s: Netmask(%d) from 1 to 128 (Line: %d)"

#define WHITELIST_RELOADING		        "%s: reload whitelist(%s)"
#define WHITELIST_NOT_ENCRYPTION            "%s: Skip encrypt file at ip address(%s)"




#define ERR_CONFIG_FILE_OPEN	"%s: Cannot open config file.(%s): (%s)"
#define ERR_CONFIG_LINE_LONG	"%s: %s (line: %d) is too long."
#define ERR_CONFIG_DUPLICATED	"%s: %s (line: %d) is duplicated. (%s)"
#define ERR_CONFIG_SYNTAX	"%s: %s (line: %d) syntax error. (%s)"
#define ERR_CONFIG_OUT_OF_RANGE	"%s: %s (line: %d) is too large. (%s)"
#define ERR_CONFIG_VALUE_MINUS	"%s: %s (line: %d) must be plus. (%s)"
#define ERR_CONFIG_UNKNOWN_NAME	"%s: %s (line: %d) is unknown data type."
#define ERR_CONFIG_MUST_BE_SET	"%s: Parameter \"%s\" must be set. (%s)"

#define ERR_SOCKET_READ			"%s: Cannot read from socket.: (%s)"
#define ERR_SOCKET_CONNECT		"%s: Cannot connect socket.: (%s)"
#define ERR_SOCKET_CLOSE		"%s: Cannot close socket.: (%s)"
#define ERR_SOCKET_CREATE		"%s: Cannot create socket.: (%s)"
#define ERR_SOCKET_SET_OPTION		"%s: Cannot set socket option.: (%s)"
#define ERR_SOCKET_BIND			"%s: Cannot bind socket.: (%s)"
#define ERR_SOCKET_LISTEN		"%s: Cannot listen socket.: (%s)"
#define ERR_SOCKET_ACCEPT		"%s: Cannot accept socket.: (%s)"

#define ERR_MILTER_SET_SOCKET		"Cannot set milter socket.: (%s)"
#define ERR_MILTER_SET_TIMEOUT		"Cannot set milter timeout.: (%s)"
#define ERR_MILTER_REGISTER		"Cannot set milter register.: (%s)"
#define ERR_MILTER_START		"Cannot start milter.: (%s)"

#define ERR_MAIL_FORMAT			"%s: Mailformat error.: (%s)"
#define ERR_MAIL_FIND_ADDRESS		"%s: Not found mail address."
#define ERR_MAIL_SEND			"%s: Cannot mail send."

#define ERR_FILE_RENAME		"%s: Cannot rename.(%s): (%s)"
#define ERR_FILE_OPEN		"%s: Cannot open file.(%s)"
#define ERR_FILE_REMOVE		"%s: Cannot remove file.(%s)"
#define ERR_FILE_GET_INFO	"%s: Cannot get file information.(%s)"
#define ERR_FILE_CREATE_TMPFILE	"%s: Cannot create tmpfile.(%s): (%s)"
#define ERR_FILE_WRITE		"%s: Cannot write file."
#define ERR_FILE_GET_NAME	"%s: Cannot get file name."

#define ERR_DIRECTORY_MAKE		"%s: Cannot make directory.(%s): (%s)"
#define ERR_DIRECTORY_SEARCH		"%s: Cannot search directory.(%s): (%s)"
#define ERR_DIRECTORY_REMOVE		"%s: Cannot remove directory.(%s)"
#define ERR_DIRECTORY_CHANGE		"%s: Change directory failed.(%s)"
#define ERR_DIRECTORY_NOT_DIRECTORY	"%s: Not directory.(%s)"

#define ERR_IO_READ			"%s: Cannot read."
#define ERR_IO_WRITE			"%s: Cannot write.: (%s)"
#define ERR_IO_DELETE			"%s: Cannot delete.: (%s)"

#define ERR_THREAD_CREATE	"%s: Cannot create thread.(%s): (%s)"
#define ERR_THREAD_DETACH	"%s: Cannot detach thread.(%s): (%s)"

#define ERR_MEMORY_ALLOCATE	"%s: Cannot allocate memory.(variable=%s): (%s)"
#define STDERR_MEMORY_ALLOCATE	"Cannot allocate memory.(variable=%s): (%s)"

#define ERR_ENCODE_MEMORY_ALLOCATE	"%s: Cannot allocate memory for encoding.: (%s)"

#define ERR_MAILADDR_UNKNOWN_TYPE	"%s: Non-ascii characters are included in mail address.: (%s)"

#define ERR_DB                     "%s: DB error.(%s)"

#define ERR_GMIME		"%s: GMime error.(%s)"

#define ERR_PIPE_CREATE		"%s: Cannot create pipe.(%s)"
#define	ERR_WAIT_CHILD		"%s: Cannot wait child process.(%s)"
#define ERR_FORK_CREATE		"%s: Cannot create fork process.(%s)"
#define ERR_FD_CREATE		"%s: Cannot create file descriptor.(%s)"
#define ERR_FP_CREATE		"%s: Cannot create file pointer.(%s)"
#define ERR_EXEC_FILE		"%s: Cannot execute file.(%s): (%s)"

#define ERR_MAILSAVE_WRITE	"%s: Cannot write mail data.(%s)"

#define ERR_PASS_MUST_BE_SET	"%s: Password must be set."

#define ERR_INVALID_COMMAND     "%s: Cannot analysis command.(variable=%s): (value=%d)"
#define ERR_DELETE_ADDRESS	"%s: Cannot delete rcpt address.(%s)"
#define ERR_SET_ENV		"%s: Cannot set environment variable.(%s)"
#define ERR_GET_PRIV		"%s: Cannot get private data pointer."
#define ERR_RELOAD_SERVER	"%s: Cannot start reload server."
#define ERR_ZIP_CONVERT		"%s: Cannot zip convert.(%s)"
#define ERR_CHARCODE_CONVERT	"%s: Cannot convert character code."
#define ERR_CONVERT_VALIDATION	"Failed to validate charset conversion: (Attachfilename[base64]: original: %s, converted: %s, validation: %s, FromChar: %s, ToChar: %s)."
#define DEBUG_CONVERT_VALIDATION "Validation for charset conversion: (Attachfilename[base64]: original: %s, converted: %s, validation: %s, FromChar: %s, ToChar: %s)."
#define MAX_STRCODE_LEN	        16

#define ERR_NULL_FILE_NAME      "%s: samma atlist is NULL."
#define ERR_STR_CODE		"Invalid str code."
#define ERR_NULL_VALUE		"Invalid value."
#define ERR_DEFALT_ENCRYPTION	"Invalid default encryption strings."
#define ERR_LDAP_FILTER		"Invalid LDAP filter strings."
#define ERR_SET_PNOTICE         "Invalid passwordnotice value."

#define ERR_LDAP_SEARCH	        "%s: Cannot search ldap.(%s):"
#define ERR_LDAP_ENTRIE 	"%s: Cannot get first ldap entry .(variable=%s):"
#define ERR_LDAP_COUNT          "%s: Cannot count ldap.(variable=%s):"
#define ERR_LDAP_GET_DN         "%s: Cannot get ldap dn.(variable=%s):"
#define ERR_LDAP_INIT           "%s: Cannot ldap init.(%s):"
#define ERR_LDAP_SET            "%s: Cannot ldap set.(%s):"
#define ERR_LDAP_BIND           "%s: Cannot ldap bind.(%s):"
#define ERR_LDAP_VALUE	        "%s: Cannot get value from entry.(%s):"

#define ERR_YESNO		"Invalid strings."
#define ERR_LDAP		"%s: Ldap error.(variable=%s):"
#define ERR_MAKE_FILTER		"%s: Cannot make filter(variable=%s)"

#define ERR_LDAP_CONFIG		"%s must be set.(because UserPolicy is YES)"

#define ERR_AUTOBCC_OPTION	"%s can not set.(because UserPolicy is NO)"
#define ERR_AUTOBCC_PARAM	"%s must be set.(because AutoBccOption is YES)"
#define ERR_REGEX		"%s: Regex error.(%s)"
#define ERR_AUTOBCC		"%s: Cannot add RcptTo.(%s):"

/* ADD(20170119)*/
#define INVALID_CHAR	"%s: Invalid character in mail address."

/* ADD(20170123)*/
#define ERR_ERRTMPL_READ	"%s: Cannot read error message template file.(%s)"
#define ERR_ERRTMPL_OPEN	"%s: Cannot open error message template file.(%s)"
#define ERR_ERRTMPL_STAT	"%s: Cannot fstat error message template file.(%s)"
#define ERRTMPL_NOSTRING	"%s: No strings in error message template file.(%s)"
#define INVALID_CHAR_EXTENSION "WARNING: %s: Invalid character in extension. (%s)"
#define INVALID_LEN_EXTENSION  "WARNING: %s: Invalid length in extension. (%s)"
#define ERR_SEARCH_EXT         "%s: Cannot get extension. (%s)"

/* ADD(20170130)*/
#define ERR_REPEAT_EXTENSION	"Same extension command is repeated. (MIME type: %s)"

/* harmless */
#define LOG_HARMLESS            "harmless: source=%s, message-id=%s, sender=%s, recipients=%s"

int syslog_facility(char *str);
void init_log();
void switch_log(char *);
void errorlog(char *, ...);
void systemlog(char *, ...);
extern int (*logfunc)(const char *, ...);

#define log (*logfunc)

#endif		/* _SAMMA_LOG_H */
