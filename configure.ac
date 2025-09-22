dnl
dnl configure.ac
dnl
dnl       The Initial Developer of the Original Code is International
dnl       Business Machines Corporation. Portions created by IBM
dnl       Corporation are Copyright (C) 2014 International Business
dnl       Machines Corporation. All Rights Reserved.
dnl
dnl       This program is free software; you can redistribute it and/or modify
dnl       it under the terms of the Common Public License as published by
dnl       IBM Corporation; either version 1 of the License, or (at your option)
dnl       any later version.
dnl
dnl       This program is distributed in the hope that it will be useful,
dnl       but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl       Common Public License for more details.
dnl
dnl       You should have received a copy of the Common Public License
dnl       along with this program; if not, a copy can be viewed at
dnl       http://www.opensource.org/licenses/cpl1.0.php.
dnl
dnl       This file is derived from tpm-tool's configure.in.
dnl

AC_INIT([swtpm],[0.11.0])
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

dnl Allow 64-bit file API on 32-bit systems. Without the change even small
dnl files will fail to stat any files on filesystems with 64-bit inodes.
AC_SYS_LARGEFILE

AC_C_CONST
AC_C_INLINE

AC_TYPE_SIZE_T

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MKDIR_P

AC_ARG_WITH([selinux],
    [AS_HELP_STRING([--with-selinux],
       [add SELinux policy extensions @<:@default=check@:>@])],
    [],
    [with_selinux="check"]
)

dnl Check for SELinux policy support

AS_IF([test "x$with_selinux" != "xno"],
    [AC_PATH_PROG([SEMODULE], semodule)
    AS_IF([test -f /usr/share/selinux/devel/Makefile && test "x$SEMODULE" != "x"],
        [with_selinux="yes"],
        [test "x$with_selinux" = "xyes"],
        [AC_MSG_ERROR(["Is selinux-policy-devel installed?"])]
    )
    ]
)

AM_CONDITIONAL([WITH_SELINUX], [test "x$with_selinux" = "xyes"])

AS_IF([test "$prefix" = "/usr" && test "$sysconfdir" = '${prefix}/etc'],
    [sysconfdir="/etc"]
)
AS_IF([test "$prefix" = "" && test "$datarootdir" = '${prefix}/share'],
    [datarootdir="/usr/share"]
)
AS_IF([test "$prefix" = "/usr" && test "$localstatedir" = '${prefix}/var'],
    [localstatedir="/var"]
)
AS_IF([test "x$prefix" = "xNONE"],
    [prefix="/usr/local"]
)
AS_IF([test "x$exec_prefix" = "xNONE"],
    [exec_prefix=$prefix]
)
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

AS_CASE([$cryptolib],[openssl],
    [PKG_CHECK_MODULES([LIBCRYPTO],[libcrypto])
     AC_CHECK_LIB(crypto,
        [AES_set_encrypt_key],
        [true],
        AC_MSG_ERROR(Faulty openssl crypto library)
     )
    AC_CHECK_HEADERS([openssl/aes.h],[],
        AC_MSG_ERROR(Is openssl-devel/libssl-dev installed?))
    AC_MSG_RESULT([Building with openssl crypto library])

    AC_CHECK_HEADERS([openssl/fips.h],
        [AC_DEFINE_UNQUOTED([HAVE_OPENSSL_FIPS_H], 1,
            [whether openssl/fips.h is available])]
    )
    AC_CHECK_LIB(crypto,
        [FIPS_mode_set],
        [AC_DEFINE_UNQUOTED([HAVE_OPENSSL_FIPS_MODE_SET_API], 1,
            [whether FIPS_mode_set API is available])]
    )
    ],
)

PKG_CHECK_MODULES([LIBTASN1],[libtasn1])

PKG_CHECK_MODULES([LIBTPMS],[libtpms >= 0.10])


AC_CHECK_LIB(c, clock_gettime, LIBRT_LIBS="", LIBRT_LIBS="-lrt")
AC_SUBST([LIBRT_LIBS])

AC_ARG_WITH([cuse],
            AS_HELP_STRING([--with-cuse],[build with CUSE interface]),
            [],
            [with_cuse=check]
)

AS_IF([test "x$with_cuse" != "xno"],
    [PKG_CHECK_MODULES([LIBFUSE],
        [fuse3],
        [with_cuse=yes],
        [PKG_CHECK_MODULES([LIBFUSE],
            [fuse],
            [LIBFUSE_CFLAGS="$LIBFUSE_CFLAGS -DWITH_FUSE2"],
            [AS_IF([test "x$with_cuse" = "xyes"],
                [AC_MSG_ERROR("Is fuse3-devel or fuse-devel installed? -- could not found libfuse3 or libfuse")],
                [with_cuse=no]
            )]
        )]
    )
    AS_IF([test "x$with_cuse" = "xyes"],
        [AC_DEFINE_UNQUOTED([WITH_CUSE], 1,
            [whether to build with CUSE interface])
        PKG_CHECK_MODULES([GTHREAD], gthread-2.0)])
    ]
)

AM_CONDITIONAL([WITH_CUSE],[test "$with_cuse" = "yes"])
AC_MSG_CHECKING([for whether to build with CUSE interface])
AC_MSG_RESULT([$with_cuse])

PKG_CHECK_MODULES([JSON_GLIB], [json-glib-1.0])

PKG_CHECK_MODULES([GLIB], [glib-2.0])

PKG_CHECK_MODULES([GMP], [gmp])

AC_MSG_CHECKING([for whether to build with chardev interface])

AS_CASE([$host_os],
    [linux-*],
    [with_chardev=yes
    AC_DEFINE_UNQUOTED([WITH_CHARDEV], 1,
        [whether to build with chardev interface])
    ],
    [with_chardev=no]
)

AM_CONDITIONAL([WITH_CHARDEV],[test "$with_chardev" = "yes"])
AC_MSG_RESULT($with_chardev)

AC_ARG_WITH([gnutls],
            AS_HELP_STRING([--with-gnutls],[build with gnutls library]),
            [],
            [with_gnutls=check]
)

dnl certtool changed how it takes private key passwords
dnl 3.3.29 is too old (RHEL 7); we need at least gnutls 3.4.0

AS_IF([test "x$with_gnutls" != "xno"],
    [PKG_CHECK_MODULES([GNUTLS],
        [gnutls >= 3.4.0],
        [],
        [AS_IF([test "x$with_gnutls" = "xyes"],
            [AC_MSG_ERROR("Is gnutls installed? -- could not get libs for gnutls")],
            [with_gnutls=no]
        )]
    )
    AC_PATH_PROG([GNUTLS_CERTTOOL], certtool)
    AS_IF([test "x$GNUTLS_CERTTOOL" = "x" && test "x$with_gnutls" = "xyes"],
        [AC_MSG_ERROR("Could not find certtool. Is gnutls-utils/gnutls-bin installed?")],
        [test "x$GNUTLS_CERTTOOL" = "x"],
        [with_gnutls=no]
    )
    AS_IF([test "x$with_gnutls" != "xno"],[with_gnutls="yes"])
    ]
)

AM_CONDITIONAL([WITH_GNUTLS], [test "x$with_gnutls" = "xyes"])


DEFAULT_PCR_BANKS="sha256"
AC_ARG_ENABLE([default-pcr-banks],
              AS_HELP_STRING(
                  [--enable-default-pcr-banks=list of PCR banks],
                  [Have swtpm_setup activate the given PCR banks by default;
                  default is sha256]
              ),
              [],
              []
)

AC_DEFUN([pcr_bank_checks], [
    AC_CHECK_PROG([bash], [bash], [yes], [no])
    AS_IF([test "x$bash" != "xyes"],
      [AC_MSG_ERROR([PCR bank verification requires bash, but executable not found.])])

    AC_MSG_CHECKING([which PCR banks to activate by default])
    REGEX="^(sha1|sha256|sha384|sha512)(,(sha1|sha256|sha384|sha512)){0,3}\$"
    AS_IF([bash -c "[[[ $DEFAULT_PCR_BANKS =~ $REGEX ]]] && exit 0 || exit 1"],
        [AC_MSG_RESULT([$DEFAULT_PCR_BANKS])],
        [AC_MSG_ERROR([$DEFAULT_PCR_BANKS is an invalid list of PCR banks])])
])

AS_IF([test "x$enable_default_pcr_banks" != "x"],[
     DEFAULT_PCR_BANKS="$enable_default_pcr_banks"
])
pcr_bank_checks
AC_SUBST([DEFAULT_PCR_BANKS])

dnl tests and tools needed for tests
AC_ARG_ENABLE([tests],
    [AS_HELP_STRING([--disable-tests], [Disable test; tools only needed for tests need not be installed])],
    [AS_CASE([$enableval],
        [yes],
        [enable_tests=yes],
        [no],
        [enable_tests=no],
        [AC_MSG_ERROR([bad value ${enableval} for --disable-tests])]
    )],
    [enable_tests=yes]
)
AM_CONDITIONAL(ENABLE_TESTS, [test x$enable_tests = xyes])

have_tcsd=no
AS_IF([test "x$enable_tests" = "xyes"],[
    dnl We either need netstat (more common across systems) or 'ss' for test cases
    AC_PATH_PROG([NETSTAT], [netstat])

    AS_IF([test "x$NETSTAT" = "x"],
        [AC_PATH_PROG([SS], [ss])
        AS_IF([test "x$SS" = "x"],
            [AC_MSG_ERROR(['netstat' and 'ss' tools are missing for tests: net-tools OR iproute/iproute2 package])]
        )
        ]
    )

    AC_PATH_PROG([TCSD], tcsd)
    AS_IF([test "x$TCSD" = "x"],
        [have_tcsd=no,
        AC_MSG_WARN([tcsd could not be found; typically need it for tss user account and tests])
        ],
        [have_tcsd=yes]
    )

    AC_PATH_PROG([EXPECT], expect)
    AS_IF([test "x$EXPECT" = "x"],
        AC_MSG_ERROR([expect is required: expect package])
    )

    AC_PATH_PROG([GAWK], gawk)
    AS_IF([test "x$GAWK" = "x"],
        AC_MSG_ERROR([gawk is required: gawk package])
    )

    AC_PATH_PROG([SOCAT], socat)
    AS_IF([test "x$SOCAT" = "x"],
        AC_MSG_ERROR([socat is required: socat package])
    )

    AC_PATH_PROG([BASE64], base64)
    AS_IF([test "x$BASE64" = "x"],
        AC_MSG_ERROR([base64 is required: base64 package])
    )

    AC_PATH_PROG([CP], cp)
    AS_IF([test "x$CP" = "x"],
	AC_MSG_ERROR([cp is required])
    )
])
AM_CONDITIONAL([HAVE_TCSD], test "$have_tcsd" != "no")

AM_PATH_PYTHON([3.3])

AC_ARG_ENABLE([hardening],
  AS_HELP_STRING([--disable-hardening], [Disable hardening flags]))

AS_IF([test "x$enable_hardening" != "xno"],
dnl Some versions of gcc fail with -Wstack-protector,
dnl some with -Wstack-protector-strong enabled
    [AS_IF([! $CC -fstack-protector-strong -Wstack-protector $srcdir/include/swtpm/tpm_ioctl.h 2>/dev/null],
        [AS_IF([ $CC -fstack-protector -Wstack-protector $srcdir/include/swtpm/tpm_ioctl.h 2>/dev/null],
            [HARDENING_CFLAGS="-fstack-protector -Wstack-protector"])],
        [HARDENING_CFLAGS="-fstack-protector-strong -Wstack-protector"])
dnl Only support -D_FORTIFY_SOURCE=2 and have higher levels passed in by user
dnl since they may create more overhead
    AS_IF([$CC $CFLAGS -Werror -D_FORTIFY_SOURCE=2 $srcdir/include/swtpm/tpm_ioctl.h 2>/dev/null],
        [HARDENING_CFLAGS="$HARDENING_CFLAGS -D_FORTIFY_SOURCE=2"])
dnl Check linker for 'relro' and 'now'
    save_CFLAGS="$CFLAGS"
    CFLAGS="-Wl,-z,relro -Werror"
    AC_MSG_CHECKING([whether linker supports -Wl,-z,relro])
    AC_LINK_IFELSE(
        [AC_LANG_SOURCE([[int main() { return 0; }]])],
        [HARDENING_LDFLAGS="$HARDENING_LDFLAGS -Wl,-z,relro"
        AC_MSG_RESULT(yes)
        ],
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
    ]
)

AC_ARG_ENABLE([test-coverage],
    AS_HELP_STRING([--enable-test-coverage], [Enable test coverage flags]))

AS_IF([test "x$enable_test_coverage" = "xyes"],
    [COVERAGE_CFLAGS="-fprofile-arcs -ftest-coverage"
    COVERAGE_LDFLAGS="-fprofile-arcs"
    ]
)

AC_ARG_ENABLE([sanitizers],
    AS_HELP_STRING([--enable-sanitizers], [Enable address/undefined sanitizers]))

AS_IF([test "x$enable_sanitizers" = "xyes"],
    [save_CFLAGS="$CFLAGS"
    CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"
    AC_MSG_CHECKING([whether linker supports sanitizer])
    AC_LINK_IFELSE(
        [AC_LANG_SOURCE([[int main() { return 0; }]])],
        [SANITIZER_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"
        SANITIZER_LDFLAGS="-fsanitize=address,undefined"
        AC_MSG_RESULT(yes)
        ],
        [AC_MSG_RESULT(no)]
    )
    CFLAGS="$save_CFLAGS"
    ]
)

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
CFLAGS="$CFLAGS -Wformat -Wformat-security -Wshadow"
CFLAGS="$CFLAGS $GNUTLS_CFLAGS $COVERAGE_CFLAGS $SANITIZER_CFLAGS"

LDFLAGS="$LDFLAGS $COVERAGE_LDFLAGS $SANITIZER_LDFLAGS"

dnl Simulate the following for systems with pkg-config < 0.28:
dnl PKG_CHECK_VAR([libtpms_cryptolib], [libtpms], [cryptolib],
dnl  [], AC_MSG_ERROR([Could not determine libtpms crypto library.]))
PKG_PROG_PKG_CONFIG

PKG_CHECK_VAR([libtpms_cryptolib],
    [libtpms],
    [cryptolib],
    [],
    [AC_MSG_ERROR([Could not determine libtpms crypto library.])]
)

AS_IF([test x"$libtpms_cryptolib" != x"$cryptolib"],
    [AC_MSG_NOTICE([libtpms is using $libtpms_cryptolib; we have to use the same])
    AS_IF([test "$cryptolib" = "openssl"],
        [AC_MSG_ERROR([do not use --with-openssl])],
        [AC_MSG_ERROR([use --with-openssl])]
    )
    ]
)

with_vtpm_proxy=no
AS_CASE([$host_os],
    [linux-*],
    [with_vtpm_proxy=yes
    AC_DEFINE_UNQUOTED([WITH_VTPM_PROXY], 1,
                     [whether to build in vTPM proxy support (Linux only)])
    ]
)

dnl Seccomp profile using -lseccomp (Linux only)
AS_CASE([$host_os],
    [linux-*],
    [with_seccomp_default=yes],
    [with_seccomp_default=no]
)

AC_MSG_CHECKING([for whether to build with seccomp profile])
AC_ARG_WITH([seccomp],
  AS_HELP_STRING([--with-seccomp],[build with seccomp profile]),
  AC_MSG_RESULT([$with_seccomp]),
  [with_seccomp=$with_seccomp_default]
  AC_MSG_RESULT([$with_seccomp])
)

AS_IF([test "x$with_seccomp" != "xno"],
    [PKG_CHECK_MODULES([LIBSECCOMP],[libseccomp])
    AC_DEFINE_UNQUOTED([WITH_SECCOMP], 1,
        [whether to build in seccomp profile (Linux only)])
    ]
)

MY_CFLAGS="$CFLAGS"
MY_LDFLAGS="$LDFLAGS"
AC_SUBST([MY_CFLAGS])
AC_SUBST([MY_LDFLAGS])

AC_CONFIG_FILES([Makefile                   \
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
		src/selinux/swtpm.fc        \
		src/selinux/swtpmcuse.fc    \
		src/swtpm/Makefile          \
		src/swtpm_bios/Makefile     \
		src/swtpm_cert/Makefile     \
		src/swtpm_ioctl/Makefile    \
		src/swtpm_localca/Makefile  \
		src/swtpm_setup/Makefile    \
		src/swtpm-sysusers.conf     \
		src/swtpm-tmpfiles.conf     \
		src/utils/Makefile          \
		src/utils/swtpm_conf.h      \
		man/Makefile                \
		man/man3/Makefile           \
		man/man5/Makefile           \
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
printf "enable_tests    : %5s  (no = no tests will run)\n" $enable_tests
printf "\n"
printf "active PCR banks      : %s\n" $DEFAULT_PCR_BANKS
printf "TPM 2 profile support : yes\n"
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
echo "      GNUTLS_LIBS = $GNUTLS_LIBS"
echo "         GMP_LIBS = $GMP_LIBS"
echo "       GMP_CFLAGS = $GMP_CFLAGS"
echo "   LIBFUSE_CFLAGS = $LIBFUSE_CFLAGS"
echo "     LIBFUSE_LIBS = $LIBFUSE_LIBS"
echo
echo "TSS_USER=$TSS_USER"
echo "TSS_GROUP=$TSS_GROUP"
echo
