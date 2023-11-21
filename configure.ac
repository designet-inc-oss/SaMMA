#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(samma, 1.00, thayashi@designet.co.jp)
AC_CONFIG_AUX_DIR(./shtool)
AM_INIT_AUTOMAKE
dnl AC_CONFIG_SRCDIR([lib/libdgconfig/libdgconfig.c])
AC_CONFIG_SRCDIR([src/mailzip_tmpl.c])
AC_CONFIG_HEADER([config.h])

AC_SUBST(HAVE_LIBDG,"yes")

# enable/disable function: notice_passwd
AC_ARG_ENABLE(notice_passwd,
  AS_HELP_STRING(
    [--enable-notice_passwd],
    [,(no support) default: no]),
    [case "${enableval}" in
      yes) AC_SUBST(NOTICE_PASS_CFLAGS, "-D__NOTICE_PASSWD") ;;
      no)  AC_SUBST(NOTICE_PASS_CFLAGS, "");;
      *)   AC_MSG_ERROR([bad value ${enableval} for --enable-notice_passwd]) ;;
    esac],
    [AC_SUBST(NOTICE_PASS_CFLAGS, "")])

# enable/disable function  subjectsw(CUSTOMIZE2018)
AC_ARG_ENABLE(subjectsw,
  AS_HELP_STRING(
    [--enable-subjectsw],
    [,(no support) default: no]),
    [case "${enableval}" in
      yes) AC_SUBST(SUBJECTSW_CFLAGS, "-D__CUSTOMIZE2018") ;;
      no)  AC_SUBST(SUBJECTSW_CFLAGS, "");;
      *)   AC_MSG_ERROR([bad value ${enableval} for --enable-subjectsw]) ;;
    esac],
    [AC_SUBST(SUBJECTSW_CFLAGS, "")])

if test "$prefix" = 'NONE'; then
    prefix="/usr/local"
fi

if test "$sysconfdir" = '${prefix}/etc'; then
    sysconfdir="${prefix}/etc"
fi
sysconfdir="${sysconfdir}/samma"

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL
AC_PROG_MAKE_SET
AC_PROG_RANLIB

if test "$HAVE_LIBDG" = 'yes'; then
    $SHELL ./makelibdg
fi

# check arch
echo "int i;" >> archtest.c
$CC -c archtest.c >/dev/null 2>&1
case `/usr/bin/file archtest.o` in
  *32-bit*)
    LIBSUF=''
    ;;
  *64-bit*)
    LIBSUF='64'
    ;;
esac
rm -f archtest*

AC_ARG_WITH([zip],
            [AC_HELP_STRING([--with-zip=PATH],
                            [path to zip command])],
            [AC_CHECK_FILE([$withval], ZIP=$withval, ZIP=no)],
            [AC_PATH_PROG(ZIP, [zip], no)])

AS_IF(test x${ZIP} = xno,
      [AC_MSG_ERROR([zip command is not found.])])
AC_SUBST(ZIP)

AC_ARG_WITH([sendmail],
            [AC_HELP_STRING([--with-sendmail=PATH],
                            [path to sendmail command])],
            [AC_CHECK_FILE([$withval], SENDMAIL=$withval, SENDMAIL=no)],
            [AC_PATH_PROG(SENDMAIL, [sendmail], no, [$PATH:/usr/sbin])])

AS_IF(test x${SENDMAIL} = xno,
      [AC_MSG_ERROR([sendmail command is not found.])])
AC_SUBST(SENDMAIL)

AC_ARG_WITH([python3],
            [AC_HELP_STRING([--with-python3=PATH],
                            [path to python3 command])],
            [AC_CHECK_FILE([$withval], PYTHON3=$withval, PYTHON3=no)],
            [AC_PATH_PROG(PYTHON3, [python3], no, [$PATH:/usr/bin])])

AS_IF(test x${PYTHON3} = xno,
      [AC_MSG_ERROR([python3 command is not found.])])
AC_SUBST(PYTHON3)

# Checks for libraries.
SAVED_CFLAGS=$CFLAGS
SAVED_LDFLAGS=$LDFLAGS

AC_SUBST(LIBDG_PREFIX, ${prefix})

AC_ARG_WITH([dgconfig],
            [AC_HELP_STRING([--with-dgconfig=DIR],
                            [dgconfig library in DIR])],
            [DGCONFIG_TOPPATH=$withval
             AC_MSG_CHECKING([for libdgconfig])
             if test -r "$DGCONFIG_TOPPATH/include/libdgconfig.h"; then
               DGCONFIG_INCDIR="$DGCONFIG_TOPPATH/include"
             fi
             if test -r "$DGCONFIG_TOPPATH/lib/libdgconfig.so"; then
               DGCONFIG_LIBDIR="$DGCONFIG_TOPPATH/lib"
             fi
             if test -z "$DGCONFIG_INCDIR" || test -z "$DGCONFIG_LIBDIR"; then
               AC_MSG_RESULT([no])
               AC_MSG_ERROR(libdgconfig is not found.)
             fi
             DGCONFIG_CFLAGS="-I$DGCONFIG_INCDIR"
             DGCONFIG_LD="$DGCONFIG_LIBDIR/libdgconfig.so"
             RPATH="$RPATH -R $DGCONFIG_LIBDIR"
             AC_MSG_RESULT([yes])
            ],
            [
             CFLAGS=-I../lib/libdgconfig
             LDFLAGS="-L../lib/libdgconfig -ldgconfig -lspf2"

             AC_CHECK_LIB([dgconfig], [read_config],
                          [DGCONFIG_CFLAGS=$CFLAGS
                           DGCONFIG_LD=$LDFLAGS
                           AC_SUBST(LIBDGCONFIG, "libdgconfig")],
                          [AS_IF(test x${HAVE_LIBDG} = xno,
                                 [AC_MSG_ERROR(libdgconfig is not found.)])
                           AC_SUBST(LIBDGCONFIG, "libdgconfig")
                           DGCONFIG_CFLAGS=$CFLAGS
                           DGCONFIG_LD=$LDFLAGS])
            ])

AC_SUBST(DGCONFIG_CFLAGS)
AC_SUBST(DGCONFIG_LD)
CFLAGS=$SAVED_CFLAGS
LDFLAGS=$SAVED_LDFLAGS

AC_ARG_WITH([dgstr],
            [AC_HELP_STRING([--with-dgstr=DIR],
                            [dgstr library in DIR])],
            [DGSTR_TOPPATH=$withval
             AC_MSG_CHECKING([for libdgstr])
             if test -r "$DGSTR_TOPPATH/include/libdgstr.h"; then
               DGSTR_INCDIR="$DGSTR_TOPPATH/include"
             fi
             if test -r "$DGSTR_TOPPATH/lib/libdgstr.so"; then
               DGSTR_LIBDIR="$DGSTR_TOPPATH/lib"
             fi
             if test -z "$DGSTR_INCDIR" || test -z "$DGSTR_LIBDIR"; then
               AC_MSG_RESULT([no])
               AC_MSG_ERROR(libdgstr is not found.)
             fi
             DGSTR_CFLAGS="-I$DGSTR_INCDIR"
             DGSTR_LD="$DGSTR_LIBDIR/libdgstr.so"
             RPATH="$RPATH -R $DGSTR_LIBDIR"
             AC_MSG_RESULT([yes])
            ],
            [
             CFLAGS=-I../lib/libdgstr
             LDFLAGS="-L../lib/libdgstr -ldgstr"

             AC_CHECK_LIB([dgstr], [str_replace_tag],
                          [DGSTR_CFLAGS=$CFLAGS
                           DGSTR_LD=$LDFLAGS
                           AC_SUBST(LIBDGSTR, "libdgstr")],
                          [AS_IF(test x${HAVE_LIBDG} = xno,
                                 [AC_MSG_ERROR(libdgstr is not found.)])
                           AC_SUBST(LIBDGSTR, "libdgstr")
                           DGSTR_CFLAGS=$CFLAGS
                           DGSTR_LD=$LDFLAGS])
            ])

AC_SUBST(DGSTR_CFLAGS)
AC_SUBST(DGSTR_LD)
CFLAGS=$SAVED_CFLAGS
LDFLAGS=$SAVED_LDFLAGS

AC_ARG_WITH([dgmail],
            [AC_HELP_STRING([--with-dgmail=DIR],
                            [dgmail library in DIR])],
            [DGMAIL_TOPPATH=$withval
             AC_MSG_CHECKING([for libdgmail])
             if test -r "$DGMAIL_TOPPATH/include/libdgmail.h"; then
               DGMAIL_INCDIR="$DGMAIL_TOPPATH/include"
             fi
             if test -r "$DGMAIL_TOPPATH/lib/libdgmail.so"; then
               DGMAIL_LIBDIR="$DGMAIL_TOPPATH/lib"
             fi
             if test -z "$DGMAIL_INCDIR" || test -z "$DGMAIL_LIBDIR"; then
               AC_MSG_RESULT([no])
               AC_MSG_ERROR(libdgmail is not found.)
             fi
# 20110927 start #
             if test -z "${DGSTR_LIBDIR}"; then
               CHECK_LIBDGMAIL_STRPATH="./lib/libdgstr/"
             else
               CHECK_LIBDGMAIL_STRPATH=${DGSTR_LIBDIR}
             fi

             sh ./shtool/check_libdgmail.sh ${DGMAIL_LIBDIR} ${CHECK_LIBDGMAIL_STRPATH}
             check_libdgmail_version=$?

             if test $check_libdgmail_version -ne 0; then
               AC_MSG_RESULT([no])
               AC_MSG_ERROR(please reinstall new version libdgmail.)
             fi
# 20110927 end #

             DGMAIL_CFLAGS="-I$DGMAIL_INCDIR"
             DGMAIL_LD="$DGMAIL_LIBDIR/libdgmail.so"
             RPATH="$RPATH -R $DGMAIL_LIBDIR"
             AC_MSG_RESULT([yes])
            ],
            [
             CFLAGS=-I../lib/libdgmail
             LDFLAGS="-L../lib/libdgmail -ldgmail"

             AC_CHECK_LIB([dgmail], [get_from],
                          [DGMAIL_CFLAGS=$CFLAGS
                           DGMAIL_LD=$LDFLAGS
                           AC_SUBST(LIBDGMAIL, "libdgmail")],
                          [AS_IF(test x${HAVE_LIBDG} = xno,
                                 [AC_MSG_ERROR(libdgmail is not found.)])
                           AC_SUBST(LIBDGMAIL, "libdgmail")
                           DGMAIL_CFLAGS=$CFLAGS
                           DGMAIL_LD=$LDFLAGS],
                          [-ldgstr])
            ])

AC_SUBST(DGMAIL_CFLAGS)
AC_SUBST(DGMAIL_LD)
CFLAGS=$SAVED_CFLAGS
LDFLAGS=$SAVED_LDFLAGS

AC_ARG_WITH([dgnetutil],
            [AC_HELP_STRING([--with-dgnetutil=DIR],
                            [dgnetutil library in DIR])],
            [DGNETUTIL_TOPPATH=$withval
             AC_MSG_CHECKING([for libdgnetutil])
             if test -r "$DGNETUTIL_TOPPATH/include/libdgnetutil.h"; then
               DGNETUTIL_INCDIR="$DGNETUTIL_TOPPATH/include"
             fi
             if test -r "$DGNETUTIL_TOPPATH/lib/libdgnetutil.so"; then
               DGNETUTIL_LIBDIR="$DGNETUTIL_TOPPATH/lib"
             fi
             if test -z "$DGNETUTIL_INCDIR" || test -z "$DGNETUTIL_LIBDIR"; then
               AC_MSG_RESULT([no])
               AC_MSG_ERROR(libdgnetutil is not found.)
             fi
             DGNETUTIL_CFLAGS="-I$DGNETUTIL_INCDIR"
             DGNETUTIL_LD="$DGNETUTIL_LIBDIR/libdgnetutil.so"
             RPATH="$RPATH -R $DGNETUTIL_LIBDIR"
             AC_MSG_RESULT([yes])
            ],
            [
             CFLAGS=-I../lib/libdgnetutil
             LDFLAGS="-L../lib/libdgnetutil -ldgnetutil"

             AC_CHECK_LIB([dgnetutil], [srb_init],
                          [DGNETUTIL_CFLAGS=$CFLAGS
                           DGNETUTIL_LD=$LDFLAGS
                           AC_SUBST(LIBDGNETUTIL, "libdgnetutil")],
                          [AS_IF(test x${HAVE_LIBDG} = xno,
                                 [AC_MSG_ERROR(libdgnetutil is not found.)])
                           AC_SUBST(LIBDGNETUTIL, "libdgnetutil")
                           DGNETUTIL_CFLAGS=$CFLAGS
                           DGNETUTIL_LD=$LDFLAGS],
                          [-ldgstr])
            ])

AC_SUBST(DGNETUTIL_CFLAGS)
AC_SUBST(DGNETUTIL_LD)
CFLAGS=$SAVED_CFLAGS
LDFLAGS=$SAVED_LDFLAGS

AC_ARG_WITH([pthread],
            [AC_HELP_STRING([--with-pthread=DIR],
                            [pthread library in DIR])],
            [PTHREAD_TOPPATH=$withval
             AC_MSG_CHECKING([for pthread])
             if test -r "$PTHREAD_TOPPATH/include/pthread.h"; then
               PTHREAD_INCDIR="$PTHREAD_TOPPATH/include"
             fi
             if test -r "$PTHREAD_TOPPATH/lib/libpthread.so"; then
               PTHREAD_LIBDIR="$PTHREAD_TOPPATH/lib"
             fi
             if test -z "$PTHREAD_INCDIR" || test -z "$PTHREAD_LIBDIR"; then
               AC_MSG_RESULT([no])
               AC_MSG_ERROR(pthread is not found.)
             fi
             PTHREAD_CFLAGS="-I$PTHREAD_INCDIR"
             PTHREAD_LD="$PTHREAD_LIBDIR/libpthread.so"
             RPATH="$RPATH -R $PTHREAD_LIBDIR"
             AC_MSG_RESULT([yes])
            ],
            [
             CFLAGS=""
             LDFLAGS=-lpthread

             AC_CHECK_LIB([pthread], [pthread_mutex_lock],
                          [PTHREAD_CFLAGS=$CFLAGS
                           PTHREAD_LD=$LDFLAGS],
                          [AC_MSG_ERROR(libpthread is not found.)])
            ])

AC_SUBST(PTHREAD_CFLAGS)
AC_SUBST(PTHREAD_LD)
CFLAGS=$SAVED_CFLAGS
LDFLAGS=$SAVED_LDFLAGS

AC_ARG_WITH([iconv],
            [AC_HELP_STRING([--with-iconv=DIR],
                            [iconv library in DIR])],
            [ICONV_TOPPATH=$withval
             AC_MSG_CHECKING([for iconv])
             if test -r "$ICONV_TOPPATH/include/iconv.h"; then
               ICONV_INCDIR="$ICONV_TOPPATH/include"
             fi
             if test -r "$ICONV_TOPPATH/lib/libiconv.so"; then
               ICONV_LIBDIR="$ICONV_TOPPATH/lib"
             fi
             if test -z "$ICONV_INCDIR" || test -z "$ICONV_LIBDIR"; then
               AC_MSG_RESULT([no])
               AC_MSG_ERROR(iconv is not found.)
             fi
             ICONV_CFLAGS="-I$ICONV_INCDIR"
             ICONV_LD="$ICONV_LIBDIR/libiconv.so"
             RPATH="$RPATH -R $ICONV_LIBDIR"
             AC_MSG_RESULT([yes])
            ],
            [
             CFLAGS=""
             LDFLAGS=""
             AC_SEARCH_LIBS([iconv], [c],
                            [ICONV_CFLAGS=$CFLAGS
                             ICONV_LD=$LDFLAGS],
                            [AC_MSG_ERROR(iconv is not found.)])])

AC_SUBST(ICONV_CFLAGS)
AC_SUBST(ICONV_LD)
CFLAGS=$SAVED_CFLAGS
LDFLAGS=$SAVED_LDFLAGS

AC_ARG_WITH([milter],
            [AC_HELP_STRING([--with-milter=DIR],
                            [milter library in DIR])],
            [MILTER_TOPPATH=$withval
             AC_MSG_CHECKING([for milter])
             if test -r "$MILTER_TOPPATH/include/libmilter/mfapi.h"; then
               MILTER_INCDIR="$MILTER_TOPPATH/include/libmilter"
             fi
             if test -r "$MILTER_TOPPATH/lib64/libmilter.so"; then
               MILTER_LIBDIR="$MILTER_TOPPATH/lib64"
               MILTER_LIB="libmilter.so"
             elif test -r "$MILTER_TOPPATH/lib64/libmilter.a"; then
               MILTER_LIBDIR="$MILTER_TOPPATH/lib64"
               MILTER_LIB="libmilter.a"
             elif test -r "$MILTER_TOPPATH/lib/libmilter.so"; then
               MILTER_LIBDIR="$MILTER_TOPPATH/lib"
               MILTER_LIB="libmilter.so"
             elif test -r "$MILTER_TOPPATH/lib/libmilter.a"; then
               MILTER_LIBDIR="$MILTER_TOPPATH/lib"
               MILTER_LIB="libmilter.a"
             fi
             if test -z "$MILTER_INCDIR" || test -z "$MILTER_LIBDIR"; then
               AC_MSG_RESULT([no])
               AC_MSG_ERROR(milter is not found.)
             fi
             MILTER_CFLAGS="-I$MILTER_INCDIR"
             MILTER_LD="$MILTER_LIBDIR/$MILTER_LIB"
             RPATH="$RPATH -R $MILTER_LIBDIR"
             AC_MSG_RESULT([yes])
            ],
            [
	     if test -r "/usr/lib64/libmilter.so";then
                AC_CHECK_FILE([/usr/lib64/libmilter.so], ,
                              [AC_MSG_ERROR(libmilter is not found.)])
	     elif test -r "/usr/lib64/libmilter.a";then
                AC_CHECK_FILE([/usr/lib64/libmilter.a], ,
                              [AC_MSG_ERROR(libmilter is not found.)])
	     elif test -r "/usr/lib/libmilter.so";then
                AC_CHECK_FILE([/usr/lib/libmilter.so], ,
                              [AC_MSG_ERROR(libmilter is not found.)])
	     elif test -r "/usr/lib/libmilter.a";then
                AC_CHECK_FILE([/usr/lib/libmilter.a], ,
                              [AC_MSG_ERROR(libmilter is not found.)])
             elif test -r "/usr/lib/x86_64-linux-gnu/libmilter.so";then
                AC_CHECK_FILE([/usr/lib/x86_64-linux-gnu/libmilter.so], ,
                              [AC_MSG_ERROR(libmilter is not found.)])		
             elif test -r "/usr/lib/x86_64-linux-gnu/libmilter.a";then
                AC_CHECK_FILE([/usr/lib/x86_64-linux-gnu/libmilter.a], ,
                              [AC_MSG_ERROR(libmilter is not found.)])			      
	     else
                AC_MSG_ERROR(libmilter is not found.)
	     fi

             CFLAGS=""
             LDFLAGS=-lmilter

             AC_CHECK_LIB([milter], [main],
                          [MILTER_CFLAGS=$CFLAGS
                           MILTER_LD=$LDFLAGS],
                          [AC_MSG_ERROR(libmilter is not found.)])
            ])

AC_SUBST(MILTER_CFLAGS)
AC_SUBST(MILTER_LD)
CFLAGS=$SAVED_CFLAGS
LDFLAGS=$SAVED_LDFLAGS

AC_ARG_WITH([bdb],
            [AC_HELP_STRING([--with-bdb=DIR],
                            [BerkeyDB library in DIR])],
            [BDB_TOPPATH=$withval
             AC_MSG_CHECKING([for bdb])
             if test -r "$BDB_TOPPATH/include/db.h"; then
               BDB_INCDIR="$BDB_TOPPATH/include"
             fi
             if test -r "$BDB_TOPPATH/lib/libdb.so"; then
               BDB_LIBDIR="$BDB_TOPPATH/lib"
             elif test -r "$BDB_TOPPATH/lib64/libdb.so"; then
               BDB_LIBDIR="$BDB_TOPPATH/lib64"
             fi
             if test -z "$BDB_INCDIR" || test -z "$BDB_LIBDIR"; then
               AC_MSG_RESULT([no])
               AC_MSG_ERROR(bdb is not found.)
             fi
             DB_CFLAGS="-I$BDB_INCIDR"
             DB_LD="$BDB_LIBDIR/libdb.so"
             RPATH="$RPATH -R $BDB_LIBDIR"
             AC_MSG_RESULT([yes])
            ],
            [
             if test -r "/usr/lib/libdb.so";then
                 AC_CHECK_FILE([/usr/lib/libdb.so], ,
                               [AC_MSG_ERROR(libdb is not found.)])
             elif test -r "/usr/lib64/libdb.so";then
                 AC_CHECK_FILE([/usr/lib64/libdb.so], ,
                               [AC_MSG_ERROR(libdb is not found.)])
             elif test -r "/usr/lib/x86_64-linux-gnu/libdb.so";then
                 AC_CHECK_FILE([/usr/lib/x86_64-linux-gnu/libdb.so], ,
                               [AC_MSG_ERROR(libdb is not found.)])		 
             else
                 AC_MSG_ERROR(libdb is not found.)
             fi

             CFLAGS=""
             LDFLAGS=-ldb

             AC_CHECK_LIB([db], [main],
                          [DB_CFLAGS=$CFLAGS
                           DB_LD=$LDFLAGS],
                          [AC_MSG_ERROR(libdb is not found.)])
            ])

AC_SUBST(DB_CFLAGS)
AC_SUBST(DB_LD)
CFLAGS=$SAVED_CFLAGS
LDFLAGS=$SAVED_LDFLAGS

AC_ARG_WITH([ldap],
            [AC_HELP_STRING([--with-ldap=DIR],
                            [LDAP library in DIR])],
            [LDAP_TOPPATH=$withval
             AC_MSG_CHECKING([for ldap])
             if test -r "$LDAP_TOPPATH/include/ldap.h"; then
               LDAP_INCDIR="$LDAP_TOPPATH/include"
             fi
             if test -r "$LDAP_TOPPATH/lib/libldap.so"; then
               BDB_LIBDIR="$LDAP_TOPPATH/lib"
             elif test -r "$LDAP_TOPPATH/lib64/libldap.so"; then
               BDB_LIBDIR="$LDAP_TOPPATH/lib64"
             fi
             if test -z "$LDAP_INCDIR" || test -z "$LDAP_LIBDIR"; then
               AC_MSG_RESULT([no])
               AC_MSG_ERROR(ldap is not found.)
             fi
             LDAP_CFLAGS="-I$LDAP_INCIDR"
             LDAP_LD="$LDAP_LIBDIR/libldap.so"
             RPATH="$RPATH -R $LDAP_LIBDIR"
             AC_MSG_RESULT([yes])
            ],
            [
             if test -r "/usr/lib/libldap.so";then
                 AC_CHECK_FILE([/usr/lib/libldap.so], ,
                               [AC_MSG_ERROR(libldap is not found.)])
             elif test -r "/usr/lib64/libldap.so";then
                 AC_CHECK_FILE([/usr/lib64/libldap.so], ,
                               [AC_MSG_ERROR(libldap is not found.)])
             elif test -r "/usr/lib/x86_64-linux-gnu/libldap.so";then
                 AC_CHECK_FILE([/usr/lib/x86_64-linux-gnu/libldap.so], ,
                               [AC_MSG_ERROR(libldap is not found.)])
             else
                 AC_MSG_ERROR(libldap is not found.)
             fi

             CFLAGS=""
             LDFLAGS="-lldap"

             AC_CHECK_LIB([ldap], [ldap_initialize],
                          [LDAP_CFLAGS=$CFLAGS
                           LDAP_LD=$LDFLAGS],
                          [AC_MSG_ERROR(libldap is not found.)])

	     LBER_LD="-llber"
            ])

AC_SUBST(LDAP_CFLAGS)
AC_SUBST(LDAP_LD)
AC_SUBST(LBER_LD)
CFLAGS=$SAVED_CFLAGS
LDFLAGS=$SAVED_LDFLAGS

AC_ARG_WITH([glib],
            [AC_HELP_STRING([--with-glib=DIR],
                            [GLib library in DIR])],
            [GLIB_TOPPATH=$withval
             CFLAGS="-I$GLIB_TOPPATH/include/glib-2.0"
             CFLAGS="$CFLAGS  -I$GLIB_TOPPATH/lib/glib-2.0/include"
	     LDFLAGS="$LDFLAGS  -L$GLIB_TOPPATH/lib"
            ],
            [
             CFLAGS="-I/usr/include/glib-2.0 -I/usr/lib${LIBSUF}/glib-2.0/include -I /usr/lib/x86_64-linux-gnu/glib-2.0/include"
             ])

AC_CHECK_LIB([glib-2.0], [main],
             [AC_SUBST(GLIB_CFLAGS, $CFLAGS)],
             [AC_MSG_ERROR(libglib is not found.)])
CFLAGS=$SAVED_CFLAGS
LDFLAGS=$SAVED_LDFLAGS

AC_ARG_WITH([gmime],
            [AC_HELP_STRING([--with-gmime=DIR],
                            [GMime library in DIR])],
            [GMIME_TOPPATH=$withval
             AC_MSG_CHECKING([for gmime])
             if test -r "$GMIME_TOPPATH/include/gmime-2.0/gmime/gmime.h"; then
               GMIME_INCDIR="$GMIME_TOPPATH/include/gmime-2.0"
             elif test -r "$GMIME_TOPPATH/include/gmime-2.6/gmime/gmime.h"; then
               GMIME_INCDIR="$GMIME_TOPPATH/include/gmime-2.6"
             fi
             if test -r "$GMIME_TOPPATH/lib/libgmime-2.0.so"; then
               GMIME_LIBDIR="$GMIME_TOPPATH/lib"
               GMIME_CFLAGS="-I$GMIME_INCDIR"
               GMIME_LD="$GMIME_LIBDIR/libgmime-2.0.so"
             elif test -r "$GMIME_TOPPATH/lib64/libgmime-2.0.so"; then
               GMIME_LIBDIR="$GMIME_TOPPATH/lib64"
               GMIME_CFLAGS="-I$GMIME_INCDIR"
               GMIME_LD="$GMIME_LIBDIR/libgmime-2.0.so"
             elif test -r "$GMIME_TOPPATH/lib/libgmime-2.6.so"; then
               GMIME_LIBDIR="$GMIME_TOPPATH/lib"
               GMIME_CFLAGS="-I$GMIME_INCDIR -DGMIME24 -DGMIME26"
               GMIME_LD="$GMIME_LIBDIR/libgmime-2.6.so -lgobject-2.0 -lglib-2.0"  
             elif test -r "$GMIME_TOPPATH/lib64/libgmime-2.6.so"; then
               GMIME_LIBDIR="$GMIME_TOPPATH/lib64"
               GMIME_CFLAGS="-I$GMIME_INCDIR -DGMIME24 -DGMIME26"
               GMIME_LD="$GMIME_LIBDIR/libgmime-2.6.so -lgobject-2.0 -lglib-2.0"  
             elif test -r "/usr/lib/x86_64-linux-gnu/libgmime-2.6.so"; then
               GMIME_LIBDIR="/usr/lib/x86_64-linux-gnu"
               GMIME_VERS=2.6
               CFLAGS="-I$GMIME_INCDIR -DGMIME24 -DGMIME26"
               LDFLAGS="-L$GMIME_LIBDIR -lgmime-2.6 -lgobject-2.0 -lglib-2.0"
             fi
             if test -z "$GMIME_INCDIR" || test -z "$GMIME_LIBDIR"; then
               AC_MSG_RESULT([no])
               AC_MSG_ERROR(gmime is not found 1.)
             fi
             RPATH="$RPATH -R $GMIME_LIBDIR"
             AC_MSG_RESULT([yes])
            ],
            [
             AC_MSG_CHECKING([for gmime])
             if test -r "/usr/include/gmime-2.0/gmime/gmime.h"; then
               GMIME_INCDIR="/usr/include/gmime-2.0"
             elif test -r "/usr/include/gmime-2.6/gmime/gmime.h"; then
               GMIME_INCDIR="/usr/include/gmime-2.6"
             fi

             if test -r "/usr/lib/libgmime-2.0.so"; then
               GMIME_LIBDIR="/usr/lib"
               GMIME_VERS=2.0
               CFLAGS="-I$GMIME_INCDIR"
               LDFLAGS="$GMIME_LIBDIR/libgmime-2.0.so"

             elif test -r "/usr/lib/libgmime-2.6.so"; then
               GMIME_LIBDIR="/usr/lib"
               GMIME_VERS=2.6
               CFLAGS="-I$GMIME_INCDIR -DGMIME24 -DGMIME26"
               LDFLAGS="$GMIME_LIBDIR/libgmime-2.6.so -lgobject-2.0 -lglib-2.0"

             elif test -r "/usr/lib64/libgmime-2.0.so"; then 
               GMIME_LIBDIR="/usr/lib64"
               GMIME_VERS=2.0
               CFLAGS="-I$GMIME_INCDIR"
               LDFLAGS="$GMIME_LIBDIR/libgmime-2.0.so"

             elif test -r "/usr/lib64/libgmime-2.6.so"; then
               GMIME_LIBDIR="/usr/lib64"
               GMIME_VERS=2.6
               CFLAGS="-I$GMIME_INCDIR -DGMIME24 -DGMIME26"
               LDFLAGS="$GMIME_LIBDIR/libgmime-2.6.so -lgobject-2.0 -lglib-2.0"
             elif test -r "/usr/lib/x86_64-linux-gnu/libgmime-2.6.so"; then
               GMIME_LIBDIR="/usr/lib/x86_64-linux-gnu"
               GMIME_VERS=2.6
               CFLAGS="-I$GMIME_INCDIR -DGMIME24 -DGMIME26"
               LDFLAGS="-L$GMIME_LIBDIR -lgmime-2.6 -lgobject-2.0 -lglib-2.0"	       
             fi
             if test -z "$GMIME_INCDIR" || test -z "$GMIME_LIBDIR"; then
               AC_MSG_RESULT([no])
               AC_MSG_ERROR(gmime is not found 2.)
             fi
             RPATH="$RPATH -R $GMIME_LIBDIR"
             AC_MSG_RESULT([yes])
             if test "$GMIME_VERS" = "2.0"; then
               AC_CHECK_LIB([gmime-2.0], [g_mime_part_new],
                            [GMIME_CFLAGS=$CFLAGS
                             GMIME_LD=$LDFLAGS],
                            [AC_MSG_ERROR(libgmime is not found.)])

             elif test "$GMIME_VERS" = "2.6"; then
               AC_CHECK_LIB([gmime-2.6], [g_mime_part_new],
                            [GMIME_CFLAGS=$CFLAGS
                             GMIME_LD=$LDFLAGS],
                            [AC_MSG_ERROR(libgmime is not found.)])
             fi
            ])

AC_SUBST(GMIME_CFLAGS)
AC_SUBST(GMIME_LD)
CFLAGS=$SAVED_CFLAGS
LDFLAGS=$SAVED_LDFLAGS

AC_SUBST(RPATH)

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netdb.h netinet/in.h stdlib.h string.h strings.h sys/param.h sys/socket.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_STRUCT_TM

# Checks for library functions.
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_TYPE_SIGNAL
AC_FUNC_STAT
AC_FUNC_STRFTIME
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([isascii memset rmdir setenv socket strcasecmp strchr strdup strerror strncasecmp strndup strrchr strstr strtol strtoul])

AC_CONFIG_FILES([Makefile
                 lib/Makefile
                 lib/libdgconfig/Makefile
                 lib/libdgstr/Makefile
                 lib/libdgmail/Makefile
                 lib/libdgnetutil/Makefile
                 src/Makefile
                 src/mailzip_config.h
                 src/mailzip_config.c
                 src/samma.conf.enc.default
                 src/samma.conf.del.default
                 src/samma.conf.harmless.default
                 src/harmless.conf.default
                 os_uploader/Makefile])
AC_OUTPUT

