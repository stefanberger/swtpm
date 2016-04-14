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

AC_INIT(swtpm, 0.1.0)
AC_PREREQ(2.12)
AC_CONFIG_SRCDIR(Makefile.am)
AC_CONFIG_HEADER(config.h)

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
AC_PROG_LIBTOOL

AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE([foreign 1.6])

DEBUG=""
AC_MSG_CHECKING([for debug-enabled build])
AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug], [create a debug build]),
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
	if test "$DEBUG" == "yes"; then
		CFLAGS="-O0 -g -DDEBUG"
	else
		CFLAGS="-g -O2"
	fi
elif test "$DEBUG" == "yes"; then
	CFLAGS="$CFLAGS -O0 -g -DDEBUG"
fi

AC_HEADER_STDC
AC_C_CONST
AC_C_INLINE

AC_TYPE_SIZE_T
AC_TYPE_SIGNAL

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
        if test "x$SEMODULE" == "x"; then
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
AM_CONDITIONAL([WITH_SELINUX], [test "x$with_selinux" == "xyes"])

GLIB_CFLAGS=$(pkg-config --cflags glib-2.0)
if test $? -ne 0; then
	AC_MSG_ERROR("Is glib-2.0 installed? -- could not get cflags")
fi
AC_SUBST([GLIB_CFLAGS])

GLIB_LIBS=$(pkg-config --libs glib-2.0)
if test $? -ne 0; then
	AC_MSG_ERROR("Is glib-2.0 installed? -- could not get libs")
fi
AC_SUBST([GLIB_LIBS])

GTHREAD_LIBS=$(pkg-config --libs gthread-2.0)
if test $? -ne 0; then
	AC_MSG_ERROR("Is glib-2.0 installed? -- could not get libs for gthread-2.0")
fi
AC_SUBST([GTHREAD_LIBS])

cryptolib=freebl

AC_ARG_WITH([openssl],
            AC_HELP_STRING([--with-openssl],
                           [build with openssl library]),
              [AC_CHECK_LIB(crypto,
                            [AES_set_encrypt_key],
                            [],
                            AC_MSG_ERROR(Faulty openssl crypto library))
               AC_CHECK_HEADERS([openssl/aes.h],[],
                            AC_MSG_ERROR(Is openssl-devel/libssl-dev installed?))
               AC_MSG_RESULT([Building with openssl crypto library])
               cryptolib=openssl
              ]
)

case "$cryptolib" in
freebl)
    AM_CONDITIONAL(SWTPM_USE_FREEBL, true)
    AM_CONDITIONAL(SWTPM_USE_OPENSSL, false)
    AC_DEFINE([USE_FREEBL_CRYPTO_LIBRARY],
              [1],
              [use freebl crypto library])

    NSPR_CFLAGS=$(nspr-config --cflags)
    if test $? -ne 0; then
        AC_MSG_ERROR("Could not find nspr-config. Is nspr-devel/libnspr4-dev installed?")
    fi
    AC_SUBST([NSPR_CFLAGS])

    NSS_CFLAGS=$(nss-config --cflags)
    if test $? -ne 0; then
        AC_MSG_ERROR("Could not find nss-config. Is nss-devel/libnss3-dev installed?")
    fi
    AC_SUBST([NSS_CFLAGS])

    NSS_LIBS=$(nss-config --libs)
    if test $? -ne 0; then
        AC_MSG_ERROR("Is nss-devel/libnss3-dev installed? -- could not get libs for nss")
    fi
    dnl On RHEL 7 ppc64 we need an explicit -lfreebl
    NSS_LIBS="$NSS_LIBS -lfreebl"
    AC_SUBST([NSS_LIBS])

    CPPFLAGS="$NSS_CFLAGS $NSPR_CFLAGS"
    AC_CHECK_HEADERS([sslerr.h],[],
                     AC_MSG_ERROR(nss-devel/libnss3-dev is bad))

    # Check for missing headers
    CFLAGS_save="$CFLAGS"
    CFLAGS="$NSS_CFLAGS $NSPR_CFLAGS"
    AC_CHECK_HEADERS([blapi.h],[],
                     AC_MSG_ERROR(nss-softokn-freebl-devel/libnss3-dev is missing blapi.h))
    # Check for missing freebl library or missing library functions
    LIBS_save="$LIBS"
    LIBS="$(nss-config --libs) $(nspr-config --libs)"
    AC_SEARCH_LIBS([AES_CreateContext], [freebl],[],
                   AC_MSG_ERROR("Could not find AES_CreateContext(). Is nss-softokn-freebl-devel/libnss3-dev installed?"),
                   [])
    LIBS="$LIBS_save"
    CPPFLAGS=""
    CFLAGS="$CFLAGS_save"

    ;;
openssl)
    AM_CONDITIONAL(SWTPM_USE_FREEBL, false)
    AM_CONDITIONAL(SWTPM_USE_OPENSSL, true)
    AC_DEFINE([USE_OPENSSL_CRYPTO_LIBRARY],
              [1],
              [use openssl crypto library])
    ;;
esac

LIBTASN1_LIBS=$(pkg-config --libs libtasn1)
if test $? -ne 0; then
	AC_MSG_ERROR("Is libtasn1-devel installed? -- could not get libs for libtasn1")
fi
AC_SUBST([LIBTASN1_LIBS])

LIBTPMS_LIBS=$(pkg-config --libs libtpms)
if test $? -ne 0; then
	AC_MSG_ERROR("Is libtpms-devel installed? -- could not get libs for libtpms")
fi
AC_SUBST([LIBTPMS_LIBS])

AC_PATH_PROG([TPM_NVDEFINE], tpm_nvdefine)
if test "x$TPM_NVDEFINE" == "x"; then
	AC_MSG_ERROR([NVRAM area tools are need: tpm-tools package])
fi

LIBFUSE_CFLAGS=$(pkg-config fuse --cflags)
if test $? -ne 0; then
	AC_MSG_ERROR("Is fuse-devel installed? -- could not get cflags for libfuse")
fi
AC_SUBST([LIBFUSE_CFLAGS])

LIBFUSE_LIBS=$(pkg-config fuse --libs)
if test $? -ne 0; then
	AC_MSG_ERROR("Is fuse-devel installed? -- could not get libs for libfuse")
fi
AC_SUBST([LIBFUSE_LIBS])

AC_ARG_WITH([gnutls],
            AC_HELP_STRING([--with-gnutls],
                           [build with gnutls library]),
            [],
            [with_gnutls=check]
)

if test "x$with_gnutls" != "xno"; then
    GNUTLS_LDFLAGS=$(pkg-config --libs gnutls)
    if test $? -ne 0; then
        if test "x$with_gnutls" == "xyes"; then
            AC_MSG_ERROR("Is gnutls installed? -- could not get libs for gnutls")
        else
            with_gnutls=no
        fi
    fi
fi

if test "x$with_gnutls" != "xno"; then
     AC_PATH_PROG([GNUTLS_CERTTOOL], certtool)
     if test "x$GNUTLS_CERTTOOL" == "x"; then
         if test "x$with_gnutls" == "xyes"; then
             AC_MSG_ERROR("Could not find certtool. Is gnutls-utils/gnutls-bin installed?")
         else
             with_gnutls=no
         fi
     fi
fi

if test "x$with_gnutls" != "xno"; then
    GNUTLS_CFLAGS=$(pkg-config gnutls --cflags)
    AC_CHECK_LIB([gnutls], [gnutls_load_file], [
                 GNUTLS_LIBS=-lgnutls
             ],
             [if test "x$with_gnutls" == "xyes"; then
                 AC_MSG_ERROR([GNUTLS >= 3.1.0 library not found: libgnutls.so])
              else
                 with_gnutls="no"
              fi])
fi

if test "x$with_gnutls" != "xno"; then
    AC_CHECK_HEADER(gnutls/abstract.h, [], \
             [if test "x$with_gnutls" == "xyes"; then
                 AC_MSG_ERROR([GNUTLS >= 3.1.0 library header not found: gnutls/abstract.h])
              else
                 with_gnutls="no"
              fi])
fi

if test "x$with_gnutls" != "xno"; then
    with_gnutls="yes"
fi
AM_CONDITIONAL([WITH_GNUTLS], [test "x$with_gnutls" == "xyes"])
AC_SUBST([GNUTLS_LIBS])

AC_PATH_PROG([EXPECT], expect)
if test "x$EXPECT" == "x"; then
	AC_MSG_ERROR([expect is required: expect package])
fi

AC_PATH_PROG([GAWK], gawk)
if test "x$GAWK" == "x"; then
	AC_MSG_ERROR([gawk is required: gawk package])
fi

AC_PATH_PROG([SOCAT], socat)
if test "x$SOCAT" == "x"; then
	AC_MSG_ERROR([socat is required: socat package])
fi

TMP="$($CC -fstack-protector-strong 2>&1)"
if echo $TMP | $GREP 'unrecognized command line option' >/dev/null; then
  HARDENING_CFLAGS="-fstack-protector -Wstack-protector "
else
  HARDENING_CFLAGS="-fstack-protector-strong -Wstack-protector "
fi

dnl Must not have -O0 but must have a -O for -D_FORTIFY_SOURCE=2
TMP1="$(echo $CFLAGS | sed -n 's/.*\(-O0\).*/\1/p')"
TMP2="$(echo $CFLAGS | sed -n 's/.*\(-O\).*/\1/p')"
if test -z "$TMP1" && test -n "$TPM2"; then
    HARDENING_CFLAGS+="-D_FORTIFY_SOURCE=2 "
fi
dnl Check ld for 'relro' and 'now'
if $LD --help 2>&1 | $GREP '\-z relro ' > /dev/null; then
  HARDENING_CFLAGS+="-Wl,-z,relro "
fi
if $LD --help 2>&1 | $GREP '\-z now ' > /dev/null; then
  HARDENING_CFLAGS+="-Wl,-z,now "
fi
AC_SUBST([HARDENING_CFLAGS])

AC_ARG_WITH([tss-user],
            AC_HELP_STRING([--with-tss-user=TSS_USER],
                           [The tss user to use]),
            [TSS_USER="$withval"],
            [TSS_USER="tss"]
)

AC_ARG_WITH([tss-group],
            AC_HELP_STRING([--with-tss-group=TSS_GROUP],
                           [The tss group to use]),
            [TSS_GROUP="$withval"],
            [TSS_GROUP="tss"]
)
AC_SUBST([TSS_USER])
AC_SUBST([TSS_GROUP])

CFLAGS="$CFLAGS -Wreturn-type -Wsign-compare -Wswitch-enum"
CFLAGS="$CFLAGS -Wmissing-prototypes -Wall -Werror"
CFLAGS="$CFLAGS -Wformat -Wformat-security"

dnl We have to make sure libtpms is using the same crypto library
dnl to avoid problems
AC_MSG_CHECKING([the crypto library libtpms is using])
dirs=$($CC $CFLAGS -Xlinker --verbose 2>/dev/null | \
       sed -n '/SEARCH_DIR/p' | \
       sed 's/SEARCH_DIR("=\?\(@<:@^"@:>@\+\)"); */\1\n/g')
for dir in $dirs; do
  if test -r $dir/libtpms.so; then
    if test -n "`ldd $dir/libtpms.so | grep libcrypto.so`"; then
      libtpms_cryptolib="openssl"
      break
    fi
    if test -n "`ldd $dir/libtpms.so | grep libnss3.so`"; then
      libtpms_cryptolib="freebl"
      break
    fi
  fi
done

if test -z "$libtpms_cryptolib"; then
  AC_MSG_ERROR([Could not determine libtpms crypto library.])
fi

AC_MSG_RESULT([$libtpms_cryptolib])

if test "$libtpms_cryptolib" != "$cryptolib"; then
  echo "libtpms is using $libtpms_cryptolib; we have to use the same"
  if test "$cryptolib" == "openssl"; then
    AC_MSG_ERROR([do not use --with-openssl])
  else
    AC_MSG_ERROR([use --with-openssl])
  fi
fi

AC_CONFIG_FILES([Makefile                    \
		dist/swtpm.spec             \
		etc/Makefile                \
		samples/Makefile            \
		include/Makefile            \
		include/swtpm/Makefile      \
		include/swtpm.h             \
		src/Makefile                \
		src/selinux/Makefile        \
		src/swtpm/Makefile          \
		src/swtpm_bios/Makefile     \
		src/swtpm_cert/Makefile     \
		src/swtpm_ioctl/Makefile    \
		src/swtpm_setup/Makefile    \
		src/swtpm_setup/swtpm_setup.h  \
		man/Makefile                \
		man/man3/Makefile           \
		man/man8/Makefile           \
		tests/Makefile              \
		tests/test_config           \
		])
AC_CONFIG_FILES([src/swtpm_setup/swtpm_setup.sh],
		[chmod 755 src/swtpm_setup/swtpm_setup.sh])
AC_OUTPUT

echo
printf "with_gnutls : %5s  (no = swtpm_cert will NOT be built)\n" $with_gnutls
printf "with_selinux: %5s  (no = SELinux policy extenions will NOT be build)\n" $with_selinux
echo
echo "cryptolib: $cryptolib"
echo
echo "CFLAGS=$CFLAGS"
echo "HARDENING_CFLAGS=$HARDENING_CFLAGS"
echo "LDFLAGS=$LDFLAGS"
echo
echo "TSS_USER=$TSS_USER"
echo "TSS_GROUP=$TSS_GROUP"
echo
