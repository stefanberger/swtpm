#
# samples/Makefile.am
#
# For the license, see the LICENSE file in the root directory.
#

samplesconfdir = $(datadir)/@PACKAGE@
samplessysconfdir = $(sysconfdir)

samplesconf_SCRIPTS = \
	swtpm-create-tpmca \
	swtpm-create-user-config-files \
	swtpm-localca

samplessysconf_DATA = \
	swtpm-localca.conf \
	swtpm-localca.options

noinst_HEADERS = \
	swtpm_localca.h \
	swtpm_localca_utils.h

bin_PROGRAMS = \
	swtpm_localca

$(top_builddir)/src/utils/libswtpm_utils.la:
	$(MAKE) -C$(dir $@)

swtpm_localca_DEPENDENCIES = \
	$(top_builddir)/src/utils/libswtpm_utils.la

swtpm_localca_SOURCES = \
	swtpm_localca.c \
	swtpm_localca_utils.c

swtpm_localca_LDADD = \
	$(top_builddir)/src/utils/libswtpm_utils.la

swtpm_localca_LDFLAGS = \
	-L$(top_builddir)/src/utils -lswtpm_utils \
	$(HARDENING_LDFLAGS) \
	$(GLIB_LIBS)

swtpm_localca_CFLAGS = \
	-I$(top_srcdir)/src/utils \
	$(HARDENING_CFLAGS) \
	$(GLIB_CFLAGS)

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/swtpm-localca
	if test -z $(DESTDIR); then \
		chown -R @TSS_USER@:root $(DESTDIR)$(localstatedir)/lib/swtpm-localca || true; \
		chmod 0750 $(DESTDIR)$(localstatedir)/lib/swtpm-localca || true; \
	fi

EXTRA_DIST= \
	swtpm-create-tpmca \
	swtpm-create-user-config-files \
	swtpm-localca.conf \
	swtpm-localca.options
