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

GLIB_CFLAGS=$(pkg-config --cflags glib-2.0)
if test $? -ne 0; then
	AC_MSG_ERROR("Is glib-2.0 installed? -- could not get cflags")
fi

GLIB_LDFLAGS=$(pkg-config --libs glib-2.0)
if test $? -ne 0; then
	AC_MSG_ERROR("Is glib-2.0 installed? -- could not get libs")
fi

GTHREAD_LDFLAGS=$(pkg-config --libs gthread-2.0)
if test $? -ne 0; then
	AC_MSG_ERROR("Is glib-2.0 installed? -- could not get libs for gthread-2.0")
fi

NSS_CFLAGS=$(pkg-config --cflags nss)
if test $? -ne 0; then
	AC_MSG_ERROR("Is nss-softokn-freebl-devel installed? -- could not get cflags for nss")
fi

NSS_LDFLAGS=$(pkg-config --libs nss)
if test $? -ne 0; then
	AC_MSG_ERROR("Is nss-softokn-freebl-devel installed? -- could not get libs for nss")
fi

CFLAGS="$CFLAGS $GLIB_CFLAGS $NSS_CFLAGS"
LDFLAGS="$LDFLAGS $GLIB_LDFLAGS $GTHREAD_LDFLAGS $NSS_LDFLAGS"

CPPFLAGS=$GLIB_CFLAGS
AC_CHECK_HEADERS([glib.h],[],
                 AC_MSG_ERROR([You must install glib2-devel]))

AC_PROG_CC
AC_PROG_INSTALL

#AM_GNU_GETTEXT_VERSION([0.15])
#AM_GNU_GETTEXT([external])

AC_CHECK_LIB([tpms], [TPMLIB_MainInit], [],
             [AC_MSG_ERROR([TPM library not found: libtpms.so])])
AC_CHECK_HEADER(libtpms/tpm_library.h, [], \
             [AC_MSG_ERROR([TPM library header not found: libtpms/tpm_library.h])])

saved_CFLAGS="$CFLAGS"
CFLAGS=`pkg-config fuse --cflags`
CPPFLAGS=$CFLAGS
AC_CHECK_LIB([fuse], [cuse_lowlevel_main], [],
             [AC_MSG_ERROR([FUSE library not found: libfuse.so])])
AC_CHECK_HEADER(cuse_lowlevel.h, [], \
             [AC_MSG_ERROR([FUSE library header not found: fuse/cuse_lowlevel.h])])
CFLAGS="$saved_CFLAGS"

AC_HEADER_STDC
AC_C_CONST
AC_C_INLINE

AC_TYPE_SIZE_T
AC_TYPE_SIGNAL

CFLAGS="$CFLAGS -Wreturn-type -Wsign-compare -Wswitch-enum"
CFLAGS="$CFLAGS -Wmissing-prototypes -Wall -Werror"

AC_CONFIG_FILES(Makefile                    \
		dist/swtpm.spec             \
		include/Makefile            \
		include/swtpm/Makefile      \
		src/Makefile                \
		src/selinux/Makefile        \
		src/swtpm/Makefile          \
		src/swtpm/swtpm.h           \
		man/Makefile                \
		man/man8/Makefile           \
		)
AC_OUTPUT

echo "CFLAGS=$CFLAGS"
echo "LDFLAGS=$LDFLAGS"
