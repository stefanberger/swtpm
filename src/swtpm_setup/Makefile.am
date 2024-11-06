#
# src/swtpm_setup/Makefile.am
#
# For the license, see the LICENSE file in the root directory.
#

MY_CFLAGS = @MY_CFLAGS@
MY_LDFLAGS = @MY_LDFLAGS@

noinst_HEADERS = \
	profile.h \
	swtpm.h \
	swtpm_setup.h \
	swtpm_setup_utils.h

bin_PROGRAMS = \
	swtpm_setup

swtpm_setup_SOURCES = \
	profile.c \
	swtpm.c \
	swtpm_setup.c \
	swtpm_setup_utils.c \
	swtpm_backend_dir.c \
	swtpm_backend_file.c

$(top_builddir)/src/utils/libswtpm_utils.la:
	$(MAKE) -C$(dir $@)

swtpm_setup_DEPENDENCIES = \
	$(top_builddir)/src/utils/libswtpm_utils.la

swtpm_setup_LDADD = \
	$(top_builddir)/src/utils/libswtpm_utils.la

swtpm_setup_LDFLAGS = \
	-L$(top_builddir)/src/utils -lswtpm_utils \
	$(MY_LDFLAGS) \
	$(HARDENING_LDFLAGS) \
	$(GLIB_LIBS) \
	$(JSON_GLIB_LIBS) \
	$(LIBCRYPTO_LIBS) \
	$(GNUTLS_LIBS)

swtpm_setup_CFLAGS = \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/include/swtpm \
	-I$(top_srcdir)/src/utils \
	-I$(top_builddir)/src/utils \
	$(MY_CFLAGS) \
	$(CFLAGS) \
	$(HARDENING_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(JSON_GLIB_CFLAGS) \
	$(GNUTLS_CFLAGS)

EXTRA_DIST = \
	README

CLEANFILES = *.gcno *.gcda *.gcov
