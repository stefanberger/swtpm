#
# src/swtpm_localca/Makefile.am
#
# For the license, see the LICENSE file in the root directory.
#

MY_CFLAGS = @MY_CFLAGS@
MY_LDFLAGS = @MY_LDFLAGS@

bin_PROGRAMS = \
	swtpm_localca

noinst_HEADERS = \
	swtpm_localca.h \
	swtpm_localca_utils.h

swtpm_localca_CFLAGS = \
	-I$(top_srcdir)/src/utils \
	$(MY_CFLAGS) \
	$(CFLAGS) \
	$(GLIB_CFLAGS) \
	$(HARDENING_CFLAGS)

swtpm_localca_DEPENDENCIES = \
	$(top_builddir)/src/utils/libswtpm_utils.la

swtpm_localca_LDADD = \
	$(top_builddir)/src/utils/libswtpm_utils.la

swtpm_localca_LDFLAGS = \
	-L$(top_builddir)/src/utils -lswtpm_utils \
	$(MY_LDFLAGS) \
	$(GLIB_LIBS) \
	$(HARDENING_LDFLAGS)

swtpm_localca_SOURCES = \
	swtpm_localca.c \
	swtpm_localca_utils.c
