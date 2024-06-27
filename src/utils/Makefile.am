#
# src/utils/Makefile.am
#
# For the license, see the COPYING file in the root directory.
#

MY_CFLAGS = @MY_CFLAGS@
MY_LDFLAGS = @MY_LDFLAGS@

noinst_HEADERS = \
	swtpm_utils.h

noinst_LTLIBRARIES = \
	libswtpm_utils.la

libswtpm_utils_la_CFLAGS = \
	$(MY_CFLAGS) \
	$(CFLAGS) \
	$(HARDENING_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(JSON_GLIB_CFLAGS)

libswtpm_utils_la_LDFLAGS = \
	$(MY_LDFLAGS) \
	$(HARDENING_LDFLAGS) \
	$(JSON_GLIB_LIBS)

libswtpm_utils_la_SOURCES = \
	swtpm_utils.c
