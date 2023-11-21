%define libname SaMMA
Summary: SAfety Mail gateway with Milter Api
Name: %{libname}
%define version _VER_
Version: %{version}
Group : System Enviroment/Daemons
License: GPLv2
Packager: Kimiyoshi Ohno <ohno@designet.co.jp>

Release: _REL_.dg%{?dist}

BuildRequires: sendmail-devel
BuildRequires: gmime-devel >= 2.6
BuildRequires: libdgstr
BuildRequires: libdgstr-devel
BuildRequires: libdgconfig
BuildRequires: libdgconfig-devel
BuildRequires: libdgmail
BuildRequires: libdgmail-devel
BuildRequires: libdgnetutil
BuildRequires: libdgnetutil-devel
BuildRequires: libspf2-devel
BuildRequires: libtool
BuildRequires: automake
BuildRequires: autoconf

Requires:      libblkid
Requires:      libcom_err
Requires:      libdb
Requires:      libffi
Requires:      libgcc
Requires:      libgpg-error
Requires:      libmount
Requires:      libselinux
Requires:      libtasn1
Requires:      libunistring
Requires:      libuuid
Requires:      p11-kit
Requires:      pcre
Requires:      pcre2
Requires:      sendmail-milter

%if %{rhel} > 7
Requires:      libidn2
Requires:      libxcrypt
%endif

Requires:      libdgstr
Requires:      libdgconfig
Requires:      libdgmail
Requires:      libdgnetutil
Requires:      libspf2
Requires:      gmime >= 2.6
Requires:      samma-iconv

BuildRoot: %{_tmppath}/%{name}-root

Source0: %{libname}-%{version}.tar.gz
Source1: samma-encrypt.service
Source2: samma-delete.service
Source3: samma-harmless.service
Source4: samma.sysconfig
Source5: samma.ldif
Source6: samma.schema
Source7: message_BOTH.tmpl.default
Source8: message_EN.tmpl.default
Source9: message_JP.tmpl.default
Source10: samma-389ds.ldif

%description
%{libname} is a software that automatically converts the attached file of mail into encryption ZIP with MTA. 

%package os_uploader
Summary: upload attachment files to NextCloud instead of zip command
Group : System Enviroment/Commands
Buildarch: noarch
Requires: SaMMA = %{version}
Requires: python3

%if %{rhel} > 7
Requires: python3-urllib3
Requires: python3-requests
%else
Requires: python36-urllib3
Requires: python36-requests
%endif

%description os_uploader
upload attachment files to NextCloud instead of zip command

%prep
rm -rf $RPM_BUILD_ROOT

#%setup -n SaMMA
%setup

%build

autoheader
libtoolize
aclocal
automake --add-missing --copy
autoconf
./configure --prefix=/usr --sysconfdir=/etc --enable-notice_passwd=yes --enable-subjectsw=yes
make #"CFLAGS=-DDEBUG"

%install
mkdir -p $RPM_BUILD_ROOT/usr/sbin
mkdir -p $RPM_BUILD_ROOT/etc
mkdir -p $RPM_BUILD_ROOT/etc/samma
mkdir -p $RPM_BUILD_ROOT/usr/lib/systemd/system
mkdir -p $RPM_BUILD_ROOT/etc/sysconfig

cp -f src/samma $RPM_BUILD_ROOT/usr/sbin/samma
cp -f src/samma.conf.del.default $RPM_BUILD_ROOT/etc/samma/samma.conf.del.default
cp -f src/samma.conf.enc.default $RPM_BUILD_ROOT/etc/samma/samma.conf.enc.default
cp -f src/samma.conf.harmless.default $RPM_BUILD_ROOT/etc/samma/samma.conf.harmless.default
cp -f src/harmless.conf.default $RPM_BUILD_ROOT/etc/samma/harmless.conf.default
cp -f src/samma.tmpl.default $RPM_BUILD_ROOT/etc/samma/samma.tmpl.default
cp -f src/samma-rcpt.tmpl.default $RPM_BUILD_ROOT/etc/samma/samma-rcpt.tmpl.default
cp -f src/errmsg.tmpl.default $RPM_BUILD_ROOT/etc/samma/errmsg.tmpl.default
cp -f src/sender.default  $RPM_BUILD_ROOT/etc/samma/sender.default
cp -f src/rcpt.default $RPM_BUILD_ROOT/etc/samma/rcpt.default
cp -f src/whitelist.default $RPM_BUILD_ROOT/etc/samma/whitelist.default
cp -f src/extension.default $RPM_BUILD_ROOT/etc/samma/extension.default
cp -f src/Makefile.db $RPM_BUILD_ROOT/etc/samma/Makefile
cp %{SOURCE1} $RPM_BUILD_ROOT/usr/lib/systemd/system/
cp %{SOURCE2} $RPM_BUILD_ROOT/usr/lib/systemd/system/
cp %{SOURCE3} $RPM_BUILD_ROOT/usr/lib/systemd/system/
cp %{SOURCE4} $RPM_BUILD_ROOT/etc/sysconfig/samma
cp %{SOURCE5} $RPM_BUILD_ROOT/etc/samma/
cp %{SOURCE6} $RPM_BUILD_ROOT/etc/samma/
cp %{SOURCE7} $RPM_BUILD_ROOT/etc/samma/
cp %{SOURCE8} $RPM_BUILD_ROOT/etc/samma/
cp %{SOURCE9} $RPM_BUILD_ROOT/etc/samma/
cp %{SOURCE10} $RPM_BUILD_ROOT/etc/samma/

mkdir -p $RPM_BUILD_ROOT/usr/bin
mkdir -p $RPM_BUILD_ROOT/etc/samma
cp os_uploader/bin/os_uploader $RPM_BUILD_ROOT/usr/bin/
cp os_uploader/etc/os_uploader.conf.default $RPM_BUILD_ROOT/etc/samma/
cp os_uploader/etc/os_uploader.tmpl.default $RPM_BUILD_ROOT/etc/samma/


%clean
rm -rf $RPM_BUILD_ROOT

%files
%attr(0755, root, root) /usr/sbin/samma
%attr(0644, root, root) /etc/samma/samma.conf.del.default
%attr(0644, root, root) /etc/samma/samma.conf.enc.default
%attr(0644, root, root) /etc/samma/samma.conf.harmless.default
%attr(0644, root, root) /etc/samma/harmless.conf.default
%attr(0644, root, root) /etc/samma/samma.tmpl.default
%attr(0644, root, root) /etc/samma/samma-rcpt.tmpl.default
%attr(0644, root, root) /etc/samma/errmsg.tmpl.default
%attr(0644, root, root) /etc/samma/sender.default
%attr(0644, root, root) /etc/samma/rcpt.default
%attr(0644, root, root) /etc/samma/Makefile
%attr(0644, root, root) /usr/lib/systemd/system/samma-encrypt.service
%attr(0644, root, root) /usr/lib/systemd/system/samma-delete.service
%attr(0644, root, root) /usr/lib/systemd/system/samma-harmless.service
%attr(0644, root, root) /etc/sysconfig/samma
%attr(0644, root, root) /etc/samma/samma.ldif
%attr(0644, root, root) /etc/samma/samma-389ds.ldif
%attr(0644, root, root) /etc/samma/samma.schema
%attr(0644, root, root) /etc/samma/whitelist.default
%attr(0644, root, root) /etc/samma/extension.default
%attr(0644, root, root) /etc/samma/message_BOTH.tmpl.default
%attr(0644, root, root) /etc/samma/message_EN.tmpl.default
%attr(0644, root, root) /etc/samma/message_JP.tmpl.default

%files os_uploader
%attr(0644, root, root) /etc/samma/os_uploader.conf.default
%attr(0644, root, root) /etc/samma/os_uploader.tmpl.default
%attr(0755, root, root) /usr/bin/os_uploader

%changelog
* Tue Jun 15 2021 DesigNET <dgspt-prod@designet.co.jp> - 5.0.0
- New feature: add online storage (NextCloud) uploader

* Fri Nov 27 2020 Phan Tien Dung <dung@designet.co.jp> - 4.1.19
- Fix bug segfault when UseAddMessageHeader=yes and
- Content-Type header of Emails which charset is not set.

* Mon Oct 19 2020 Phan Tien Dung <dung@designet.co.jp> - 4.1.18
- Initial packaging for RHEL8/CentOS8.
