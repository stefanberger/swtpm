#
# configure.ac
#
#       The Initial Developer of the Original Code is International
#       Business Machines Corporation. Portions created by IBM
#       Corporation are Copyright (C) 2014 International Business
#       Machines Corporation. All Rights Reserved.
#
#       This program is free software; you can redistribute it and/or modify
#       it under the terms of the Common Public License as published by
#       IBM Corporation; either version 1 of the License, or (at your option)
#       any later version.
#
#       This program is distributed in the hope that it will be useful,
#       but WITHOUT ANY WARRANTY; without even the implied warranty of
#       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#       Common Public License for more details.
#
#       You should have received a copy of the Common Public License
#       along with this program; if not, a copy can be viewed at
#       http://www.opensource.org/licenses/cpl1.0.php.
#
#       This file is derived from tpm-tool's configure.in.
#

AC_INIT([swtpm],[0.7.0])
AC_PREREQ([2.69])
AC_CONFIG_SRCDIR(Makefile.am)
AC_CONFIG_HEADERS([config.h])

SWTPM_VER_MAJOR=`echo $PACKAGE_VERSION | cut -d "." -f1`
SWTPM_VER_MINOR=`echo $PACKAGE_VERSION | cut -d "." -f2`
SWTPM_VER_MICRO=`echo $PACKAGE_VERSION | cut -d "." -f3`

AC_SUBST([SWTPM_VER_MAJOR])
AC_SUBST([SWTPM_VER_MINOR])
AC_SUBST([SWTPM_VER_MICRO])

dnl Check for programs
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
LT_INIT

AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_TARGET
AC_CANONICAL_HOST
AM_INIT_AUTOMAKE([foreign 1.6])
AM_SILENT_RULES([yes])

DEBUG=""
AC_MSG_CHECKING([for debug-enabled build])
AC_ARG_ENABLE(debug, AS_HELP_STRING([--enable-debug],[create a debug build]),
  [if test "$enableval" = "yes"; then
     DEBUG="yes"
     AC_MSG_RESULT([yes])
   else
     DEBUG="no"
     AC_MSG_RESULT([no])
   fi],
  [DEBUG="no",
   AC_MSG_RESULT([no])])

# If the user has not set CFLAGS, do something appropriate
test_CFLAGS=${CFLAGS+set}
if test "$test_CFLAGS" != set; then
	if test "$DEBUG" = "yes"; then
		CFLAGS="-O0 -g -DDEBUG"
	else
		CFLAGS="-g -O2"
	fi
elif test "$DEBUG" = "yes"; then
	CFLAGS="$CFLAGS -O0 -g -DDEBUG"
fi

AC_C_CONST
AC_C_INLINE

AC_TYPE_SIZE_T

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MKDIR_P

AC_ARG_WITH([selinux],
   AS_HELP_STRING([--with-selinux],
      [add SELinux policy extensions @<:@default=check@:>@]))
m4_divert_text([DEFAULTS], [with_selinux=check])

dnl Check for SELinux policy support

if test "$with_selinux" != "no"; then
    if test "$with_selinux" = "check" || test "$with_selinux" = "yes"; then
        if ! test -f /usr/share/selinux/devel/Makefile; then
            if test "$with_selinux" = "yes"; then
                AC_MSG_ERROR("Is selinux-policy-devel installed?")
            else
                with_selinux="no"
            fi
        fi
        AC_PATH_PROG([SEMODULE], semodule)
        if test "x$SEMODULE" = "x"; then
            if test "$with_selinux" = "yes"; then
	        AC_MSG_ERROR("Is selinux-policy-devel installed?")
	    else
	        with_selinux="no"
	    fi
        fi
        if test "$with_selinux" = "check"; then
            with_selinux="yes"
        fi
    fi
fi
AM_CONDITIONAL([WITH_SELINUX], [test "x$with_selinux" = "xyes"])

if test "$prefix" = "/usr" && test "$sysconfdir" = '${prefix}/etc'; then
	sysconfdir="/etc"
fi
if test "$prefix" = "" && test "$datarootdir" = '${prefix}/share'; then
	datarootdir="/usr/share"
fi
if test "$prefix" = "/usr" && test "$localstatedir" = '${prefix}/var'; then
	localstatedir="/var"
fi
if test "x$prefix" = "xNONE"; then
	prefix="/usr/local"
fi
if test "x$exec_prefix" = "xNONE"; then
	exec_prefix=$prefix
fi
SYSCONFDIR=`eval echo $sysconfdir`
DATAROOTDIR=`eval echo $datarootdir`
LOCALSTATEDIR=`eval echo $localstatedir`
BINDIR=`eval echo $bindir`
AC_SUBST([SYSCONFDIR])
AC_SUBST([DATAROOTDIR])
AC_SUBST([LOCALSTATEDIR])
AC_SUBST([BINDIR])

cryptolib=openssl

AC_ARG_WITH([openssl],
            [AS_HELP_STRING([--with-openssl],
                           [build with openssl library])],
            [],
            [])

case "$cryptolib" in
openssl)
	AC_CHECK_LIB(crypto,
		      [AES_set_encrypt_key],
		      [true],
		      AC_MSG_ERROR(Faulty openssl crypto library))
	AC_CHECK_HEADERS([openssl/aes.h],[],
			 AC_MSG_ERROR(Is openssl-devel/libssl-dev installed?))
	AC_MSG_RESULT([Building with openssl crypto library])
	LIBCRYPTO_LIBS=$(pkg-config --libs libcrypto)
	AC_SUBST([LIBCRYPTO_LIBS])
	;;
esac

LIBTASN1_LIBS=$(pkg-config --libs libtasn1)
if test $? -ne 0; then
	AC_MSG_ERROR("Is libtasn1-devel installed? -- could not get libs for libtasn1")
fi
AC_SUBST([LIBTASN1_LIBS])

PKG_CHECK_MODULES(
	[LIBTPMS],
	[libtpms],
	,
	AC_MSG_ERROR("no libtpms.pc found; please set PKG_CONFIG_PATH to the directory where libtpms.pc is located")
)
LDFLAGS="$LDFLAGS $LIBTPMS_LIBS"
CFLAGS="$CFLAGS $LIBTPMS_CFLAGS"
AC_CHECK_LIB(tpms,
             TPMLIB_ChooseTPMVersion,[true],
             AC_MSG_ERROR("libtpms 0.6 or later is required")
)
AC_SUBST([LIBTPMS_LIBS])

AC_CHECK_LIB(c, clock_gettime, LIBRT_LIBS="", LIBRT_LIBS="-lrt")
AC_SUBST([LIBRT_LIBS])

AC_PATH_PROG([TCSD], tcsd)
if test "x$TCSD" = "x"; then
    have_tcsd=no
    AC_MSG_WARN([tcsd could not be found; typically need it for tss user account and tests])
else
    have_tcsd=yes
fi
AM_CONDITIONAL([HAVE_TCSD], test "$have_tcsd" != "no")

dnl We either need netstat (more common across systems) or 'ss' for test cases
AC_PATH_PROG([NETSTAT], [netstat])
if test "x$NETSTAT" = "x"; then
	AC_PATH_PROG([SS], [ss])
	if test "x$SS" = "x"; then
		AC_MSG_ERROR(['netstat' and 'ss' tools are missing for tests: net-tools OR iproute/iproute2 package])
	fi
fi

AC_MSG_CHECKING([for whether to build with CUSE interface])
AC_ARG_WITH([cuse],
            AS_HELP_STRING([--with-cuse],[build with CUSE interface]),
            [],
            [with_cuse=check]
)

if test "$with_cuse" != "no"; then
    LIBFUSE_CFLAGS=$(pkg-config fuse --cflags 2>/dev/null)
    if test $? -ne 0; then
        if test "$with_cuse" = "yes"; then
            AC_MSG_ERROR("Is fuse-devel installed? -- could not get cflags for libfuse")
        else
            with_cuse=no
        fi
    else
        with_cuse=yes
    fi
fi

JSON_GLIB_CFLAGS=$(pkg-config --cflags json-glib-1.0)
if test $? -ne 0; then
   AC_MSG_ERROR("Is libjson-glib-dev/json-glib-devel installed? -- could not get cflags")
fi
AC_SUBST([JSON_GLIB_CFLAGS])

JSON_GLIB_LIBS=$(pkg-config --libs json-glib-1.0)
if test $? -ne 0; then
   AC_MSG_ERROR("Is libjson-glib-dev/json-glib-devel installed? -- could not get libs")
fi
AC_SUBST([JSON_GLIB_LIBS])

GLIB_CFLAGS=$(pkg-config --cflags glib-2.0)
if test $? -ne 0; then
   AC_MSG_ERROR("Is libglib-2.0-dev/glib2-devel installed? -- could not get cflags")
fi
AC_SUBST([GLIB_CFLAGS])

GLIB_LIBS=$(pkg-config --libs glib-2.0)
if test $? -ne 0; then
   AC_MSG_ERROR("Is libglib-2.0-dev/glib2-devel installed? -- could not get libs")
fi
AC_SUBST([GLIB_LIBS])

dnl with_cuse is now yes or no
if test "$with_cuse" != "no"; then
    LIBFUSE_LIBS=$(pkg-config fuse --libs)
    if test $? -ne 0; then
        AC_MSG_ERROR("Is fuse-devel installed? -- could not get libs for libfuse")
    fi
    AC_SUBST([LIBFUSE_CFLAGS])
    AC_SUBST([LIBFUSE_LIBS])
    AC_DEFINE_UNQUOTED([WITH_CUSE], 1,
                       [whether to build with CUSE interface])

    GTHREAD_LIBS=$(pkg-config --libs gthread-2.0)
    if test $? -ne 0; then
        AC_MSG_ERROR("Is glib-2.0 installed? -- could not get libs for gthread-2.0")
    fi
    AC_SUBST([GTHREAD_LIBS])
fi
AM_CONDITIONAL([WITH_CUSE],[test "$with_cuse" = "yes"])
AC_MSG_RESULT($with_cuse)

AC_MSG_CHECKING([for whether to build with chardev interface])
case $host_os in
linux-*)
    with_chardev=yes
    AC_DEFINE_UNQUOTED([WITH_CHARDEV], 1,
                       [whether to build with chardev interface])
    ;;
*)
    with_chardev=no
esac
AM_CONDITIONAL([WITH_CHARDEV],[test "$with_chardev" = "yes"])
AC_MSG_RESULT($with_cuse)

AC_ARG_WITH([gnutls],
            AS_HELP_STRING([--with-gnutls],[build with gnutls library]),
            [],
            [with_gnutls=check]
)

if test "x$with_gnutls" != "xno"; then
    GNUTLS_LDFLAGS=$(pkg-config --libs gnutls)
    if test $? -ne 0; then
        if test "x$with_gnutls" = "xyes"; then
            AC_MSG_ERROR("Is gnutls installed? -- could not get libs for gnutls")
        else
            with_gnutls=no
        fi
    fi
fi

if test "x$with_gnutls" != "xno"; then
    AC_PATH_PROG([GNUTLS_CERTTOOL], certtool)
    if test "x$GNUTLS_CERTTOOL" = "x"; then
        if test "x$with_gnutls" = "xyes"; then
            AC_MSG_ERROR("Could not find certtool. Is gnutls-utils/gnutls-bin installed?")
        else
            with_gnutls=no
        fi
    fi
    dnl certtool changed how it takes private key passwords
    dnl 3.3.29 is too old (RHEL 7); we need at least gnutls 3.4.0
    AC_MSG_CHECKING([for gnutls 3.4.0 or later])
    $(pkg-config gnutls --atleast-version=3.4.0)
    if test $? -ne 0; then
        AC_MSG_ERROR([gnutls 3.4.0 is required])
    fi
    AC_MSG_RESULT([yes])
fi

if test "x$with_gnutls" != "xno"; then
    ORIG_CFLAGS="$CFLAGS"
    GNUTLS_CFLAGS=$(pkg-config gnutls --cflags)
    CFLAGS="$CFLAGS $GNUTLS_CFLAGS $GNUTLS_LDFLAGS"
    AC_CHECK_LIB([gnutls], [gnutls_load_file], [
                 GNUTLS_LIBS=-lgnutls
             ],
             [if test "x$with_gnutls" = "xyes"; then
                 AC_MSG_ERROR([GNUTLS >= 3.1.0 library not found: libgnutls.so])
              else
                 with_gnutls="no"
              fi])
    CFLAGS="$ORIG_CFLAGS"
fi

if test "x$with_gnutls" != "xno"; then
    ORIG_CFLAGS="$CFLAGS"
    CFLAGS="$CFLAGS $GNUTLS_CFLAGS"
    AC_CHECK_HEADER(gnutls/abstract.h, [], \
             [if test "x$with_gnutls" = "xyes"; then
                 AC_MSG_ERROR([GNUTLS >= 3.1.0 library header not found: gnutls/abstract.h])
              else
                 with_gnutls="no"
              fi])
    CFLAGS="$ORIG_CFLAGS"
fi

if test "x$with_gnutls" != "xno"; then
    with_gnutls="yes"
fi
AM_CONDITIONAL([WITH_GNUTLS], [test "x$with_gnutls" = "xyes"])
AC_SUBST([GNUTLS_LIBS])

AC_PATH_PROG([EXPECT], expect)
if test "x$EXPECT" = "x"; then
	AC_MSG_ERROR([expect is required: expect package])
fi

AC_PATH_PROG([GAWK], gawk)
if test "x$GAWK" = "x"; then
	AC_MSG_ERROR([gawk is required: gawk package])
fi

AC_PATH_PROG([SOCAT], socat)
if test "x$SOCAT" = "x"; then
	AC_MSG_ERROR([socat is required: socat package])
fi

AC_PATH_PROG([BASE64], base64)
if test "x$BASE64" = "x"; then
	AC_MSG_ERROR([base64 is required: base64 package])
fi

AC_PATH_PROG([CP], cp)
if test "x$CP" = "x"; then
	AC_MSG_ERROR([cp is required])
fi

AM_PATH_PYTHON([3.3])

AC_ARG_ENABLE([hardening],
  AS_HELP_STRING([--disable-hardening], [Disable hardening flags]))

if test "x$enable_hardening" != "xno"; then
	TMP="$($CC -fstack-protector-strong $srcdir/include/swtpm/tpm_ioctl.h 2>&1)"
	if echo $TMP | $GREP 'unrecognized command line option' >/dev/null; then
		HARDENING_CFLAGS="-fstack-protector -Wstack-protector"
	else
		HARDENING_CFLAGS="-fstack-protector-strong -Wstack-protector"
	fi

	dnl Must not have -O0 but must have a -O for -D_FORTIFY_SOURCE=2
	TMP1="$(echo $CFLAGS | sed -n 's/.*\(-O0\).*/\1/p')"
	TMP2="$(echo $CFLAGS | sed -n 's/.*\(-O\).*/\1/p')"
	if test -z "$TMP1" && test -n "$TMP2"; then
		HARDENING_CFLAGS="$HARDENING_CFLAGS -D_FORTIFY_SOURCE=2"
	fi
	dnl Check linker for 'relro' and 'now'
	save_CFLAGS="$CFLAGS"
	CFLAGS="-Wl,-z,relro -Werror"
	AC_MSG_CHECKING([whether linker supports -Wl,-z,relro])
	AC_LINK_IFELSE(
		[AC_LANG_SOURCE([[int main() { return 0; }]])],
		[HARDENING_LDFLAGS="$HARDENING_LDFLAGS -Wl,-z,relro"
		 AC_MSG_RESULT(yes)],
		[AC_MSG_RESULT(no)]
	)
	CFLAGS="-Wl,-z,now -Werror"
	AC_MSG_CHECKING([whether linker supports -Wl,-z,now])
	AC_LINK_IFELSE(
		[AC_LANG_SOURCE([[int main() { return 0; }]])],
		[HARDENING_LDFLAGS="$HARDENING_LDFLAGS -Wl,-z,now"
		 AC_MSG_RESULT(yes)],
		[AC_MSG_RESULT(no)]
	)
	CFLAGS="$save_CFLAGS"
	AC_SUBST([HARDENING_CFLAGS])
	AC_SUBST([HARDENING_LDFLAGS])
fi

AC_ARG_ENABLE([test-coverage],
  AS_HELP_STRING([--enable-test-coverage], [Enable test coverage flags]))

if test "x$enable_test_coverage" = "xyes"; then
	COVERAGE_CFLAGS="-fprofile-arcs -ftest-coverage"
	COVERAGE_LDFLAGS="-fprofile-arcs"
fi

AC_ARG_ENABLE([sanitizers],
  AS_HELP_STRING([--enable-sanitizers], [Enable address/undefined sanitizers]))

if test "x$enable_sanitizers" = "xyes"; then
	save_CFLAGS="$CFLAGS"
	CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"
	AC_MSG_CHECKING([whether linker supports sanitizer])
	AC_LINK_IFELSE(
		[AC_LANG_SOURCE([[int main() { return 0; }]])],
		[SANITIZER_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"
		 SANITIZER_LDFLAGS="-fsanitize=address,undefined"
		 AC_MSG_RESULT(yes)],
		[AC_MSG_RESULT(no)]
	)
	CFLAGS="$save_CFLAGS"
fi

AC_ARG_WITH([tss-user],
            AS_HELP_STRING([--with-tss-user=TSS_USER],[The tss user to use]),
            [TSS_USER="$withval"],
            [TSS_USER="tss"]
)

AC_ARG_WITH([tss-group],
            AS_HELP_STRING([--with-tss-group=TSS_GROUP],[The tss group to use]),
            [TSS_GROUP="$withval"],
            [TSS_GROUP="tss"]
)

case $have_tcsd in
yes)
	AC_MSG_CHECKING([whether TSS_USER $TSS_USER is available])
	if ! test $(id -u $TSS_USER); then
		AC_MSG_ERROR(["$TSS_USER is not available"])
	else
		AC_MSG_RESULT([yes])
	fi
	AC_MSG_CHECKING([whether TSS_GROUP $TSS_GROUP is available])
	if ! test $(id -g $TSS_GROUP); then
		AC_MSG_ERROR(["$TSS_GROUP is not available"])
	else
		AC_MSG_RESULT([yes])
	fi
	;;
esac

AC_SUBST([TSS_USER])
AC_SUBST([TSS_GROUP])

CFLAGS="$CFLAGS -Wreturn-type -Wsign-compare -Wswitch-enum"
CFLAGS="$CFLAGS -Wmissing-prototypes -Wall -Werror"
CFLAGS="$CFLAGS -Wformat -Wformat-security"
CFLAGS="$CFLAGS $GNUTLS_CFLAGS $COVERAGE_CFLAGS $SANITIZER_CFLAGS"

LDFLAGS="$LDFLAGS $COVERAGE_LDFLAGS $SANITIZER_LDFLAGS"

dnl Simulate the following for systems with pkg-config < 0.28:
dnl PKG_CHECK_VAR([libtpms_cryptolib], [libtpms], [cryptolib],
dnl  [], AC_MSG_ERROR([Could not determine libtpms crypto library.]))
PKG_PROG_PKG_CONFIG

AC_MSG_CHECKING([Checking the crypto library libtpms is linked to])
libtpms_cryptolib=`$PKG_CONFIG --variable cryptolib libtpms`
if test "x$libtpms_cryptolib" = "x"; then
  AC_MSG_WARN([Could not determine the crypto library libtpms is using, assuming ${cryptolib}])
  libtpms_cryptolib=${cryptolib}
fi
AC_MSG_RESULT($libtpms_cryptolib)

if test "$libtpms_cryptolib" != "$cryptolib"; then
  echo "libtpms is using $libtpms_cryptolib; we have to use the same"
  if test "$cryptolib" = "openssl"; then
    AC_MSG_ERROR([do not use --with-openssl])
  else
    AC_MSG_ERROR([use --with-openssl])
  fi
fi

with_vtpm_proxy=no
case $host_os in
linux-*)
  with_vtpm_proxy=yes
  AC_DEFINE_UNQUOTED([WITH_VTPM_PROXY], 1,
                     [whether to build in vTPM proxy support (Linux only)])
esac

case $host_os in
cygwin)
  CFLAGS="$CFLAGS -D__USE_LINUX_IOCTL_DEFS"
esac

dnl Seccomp profile using -lseccomp (Linux only)
case $host_os in
linux-*)
  with_seccomp_default=yes
  ;;
*)
  with_seccomp_default=no
  ;;
esac

AC_MSG_CHECKING([for whether to build with seccomp profile])
AC_ARG_WITH([seccomp],
  AS_HELP_STRING([--with-seccomp],[build with seccomp profile]),
  AC_MSG_RESULT([$with_seccomp]),
  [with_seccomp=$with_seccomp_default]
  AC_MSG_RESULT([$with_seccomp])
)

if test "$with_seccomp" != "no"; then
  LIBSECCOMP_CFLAGS=$(pkg-config libseccomp --cflags 2>/dev/null)
  if test $? -ne 0; then
    AC_MSG_ERROR("Is libseccomp-devel installed? -- could not get cflags for libseccomp")
  else
    with_libseccomp=yes
  fi
  LIBSECCOMP_LIBS=$(pkg-config --libs libseccomp)
  AC_SUBST([LIBSECCOMP_LIBS])
  AC_SUBST([LIBSECCOMP_CFLAGS])
  AC_DEFINE_UNQUOTED([WITH_SECCOMP], 1,
                     [whether to build in seccomp profile (Linux only)])
fi

MY_CFLAGS="$CFLAGS"
MY_LDFLAGS="$LDFLAGS"
AC_SUBST([MY_CFLAGS])
AC_SUBST([MY_LDFLAGS])

AC_CONFIG_FILES([Makefile                   \
		debian/swtpm-tools.postinst \
		swtpm.spec                  \
		samples/Makefile            \
		samples/swtpm-localca.conf  \
		samples/swtpm-create-user-config-files \
		samples/swtpm_setup.conf    \
		include/Makefile            \
		include/swtpm/Makefile      \
		include/swtpm.h             \
		src/Makefile                \
		src/selinux/Makefile        \
		src/swtpm/Makefile          \
		src/swtpm_bios/Makefile     \
		src/swtpm_cert/Makefile     \
		src/swtpm_ioctl/Makefile    \
		src/swtpm_localca/Makefile  \
		src/swtpm_localca/swtpm_localca_conf.h \
		src/swtpm_setup/Makefile    \
		src/swtpm_setup/swtpm_setup_conf.h \
		src/utils/Makefile          \
		man/Makefile                \
		man/man3/Makefile           \
		man/man8/Makefile           \
		tests/Makefile              \
		tests/test_config           \
		])
AC_CONFIG_FILES([samples/swtpm-localca],
                [chmod 755 samples/swtpm-localca])
AC_OUTPUT

echo
printf "with_gnutls     : %5s  (no = swtpm_cert will NOT be built)\n" $with_gnutls
printf "with_selinux    : %5s  (no = SELinux policy extensions will NOT be built)\n" $with_selinux
printf "with_cuse       : %5s  (no = no CUSE interface)\n" $with_cuse
printf "with_chardev    : %5s  (no = no chardev interface)\n" $with_chardev
printf "with_vtpm_proxy : %5s  (no = no vtpm proxy support; Linux only)\n" $with_vtpm_proxy
printf "with_seccomp    : %5s  (no = no seccomp profile; Linux only)\n" $with_seccomp
echo
echo "Version to build  : $PACKAGE_VERSION"
echo "Crypto library    : $cryptolib"
echo
echo "        MY_CFLAGS = $MY_CFLAGS"
echo " HARDENING_CFLAGS = $HARDENING_CFLAGS"
echo "HARDENING_LDFLAGS = $HARDENING_LDFLAGS"
echo "       MY_LDFLAGS = $MY_LDFLAGS"
echo "  LIBSECCOMP_LIBS = $LIBSECCOMP_LIBS"
echo " JSON_GLIB_CFLAGS = $JSON_GLIB_CFLAGS"
echo "   JSON_GLIB_LIBS = $JSON_GLIB_LIBS"
echo "      GLIB_CFLAGS = $GLIB_CFLAGS"
echo "        GLIB_LIBS = $GLIB_LIBS"
echo
echo "TSS_USER=$TSS_USER"
echo "TSS_GROUP=$TSS_GROUP"
echo
