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
	swtpm-localca.options \
	swtpm_setup.conf

$(top_builddir)/src/utils/libswtpm_utils.la:
	$(MAKE) -C$(dir $@)

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
	swtpm-localca.options \
	swtpm_setup.conf
