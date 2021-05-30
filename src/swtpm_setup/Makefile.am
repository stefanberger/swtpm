#
# src/swtpm_setup/Makefile.am
#
# For the license, see the LICENSE file in the root directory.
#

noinst_HEADERS = \
	swtpm.h \
	swtpm_setup.h \
	swtpm_setup_utils.h

bin_PROGRAMS = \
	swtpm_setup

swtpm_setup_SOURCES = \
	swtpm.c \
	swtpm_setup.c \
	swtpm_setup_utils.c

$(top_builddir)/src/utils/libswtpm_utils.la:
	$(MAKE) -C$(dir $@)

swtpm_setup_DEPENDENCIES = \
	$(top_builddir)/src/utils/libswtpm_utils.la

swtpm_setup_LDADD = \
	$(top_builddir)/src/utils/libswtpm_utils.la

swtpm_setup_LDFLAGS = \
	-L$(top_builddir)/src/utils -lswtpm_utils \
	$(HARDENING_LDFLAGS) \
	$(GLIB_LIBS) \
	$(JSON_GLIB_LIBS) \
	$(LIBCRYPTO_LIBS)

swtpm_setup_CFLAGS = \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/include/swtpm \
	-I$(top_srcdir)/src/utils \
	$(HARDENING_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(JSON_GLIB_CFLAGS)

EXTRA_DIST = \
	README

CLEANFILES = *.gcno *.gcda *.gcov
