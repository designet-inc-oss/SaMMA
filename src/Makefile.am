bin_PROGRAMS = samma
samma_SOURCES = client_side.c client_side.h global.h log.c log.h maildrop.c maildrop.h mailsave.c mailsave.h mailzip.c mailzip.h mailzip_config.c mailzip_config.h mailzip_db.c mailzip_db.h mailzip_tmpl.c mailzip_tmpl.h sendmail.c sendmail.h zipconv.c zipconv.h samma_policy.c samma_policy.h samma_autobcc.c samma_autobcc.h netlist.c netlist.h sender_check_record.c sender_check_record.h sender_check.c sender_check.h msg_convert.c msg_convert.h msg_delete.c msg_delete.h msg_encrypt.c msg_encrypt.h harmless.c harmless.h exec_command.c exec_command.h
AM_LDFLAGS = @DGCONFIG_LD@ @DGSTR_LD@ @DGMAIL_LD@ @DGNETUTIL_LD@ @PTHREAD_LD@ @MILTER_LD@ @DB_LD@ @LDAP_LD@ @LBER_LD@ @GMIME_LD@ @ICONV_LD@ @RPATH@
sysconf_DATA = samma.conf.enc.default samma.conf.del.default samma.conf.harmless.default samma.tmpl.default rcpt.default sender.default harmless.conf.default errmsg.tmpl.default
AM_CFLAGS = -Wall -lresolv @DGCONFIG_CFLAGS@ @DGSTR_CFLAGS@ @DGMAIL_CFLAGS@ @DGNETUTIL_CFLAGS@ @PTHREAD_CFLAGS@ @MILTER_CFLAGS@ @DB_CFLAGS@ @LDAP_CFLAGS@ @GLIB_CFLAGS@ @GMIME_CFLAGS@ @NOTICE_PASS_CFLAGS@ @SUBJECTSW_CFLAGS@
DEFS = @DEFS@ -DDEFAULT_CONFDIR=\"$(sysconfdir)\" -DHAVE_STRNDUP

install-exec-am: install-binPROGRAMS install-sysconfDATA install-dbMakefile
install-dbMakefile:
	cp Makefile.db $(sysconfdir)/Makefile
