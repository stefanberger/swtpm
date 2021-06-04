#
# src/utils/Makefile.am
#
# For the license, see the COPYING file in the root directory.
#

noinst_HEADERS = \
	swtpm_utils.h

noinst_LTLIBRARIES = \
	libswtpm_utils.la

libswtpm_utils_la_CFLAGS = \
	$(HARDENING_CFLAGS) \
	$(GLIB_CFLAGS)

libswtpm_utils_la_LDFLAGS = \
	$(HARDENING_LDFLAGS)

libswtpm_utils_la_SOURCES = \
	swtpm_utils.c
