#
# samples/Makefile.am
#
# For the license, see the LICENSE file in the root directory.
#

samplesconfdir = $(datadir)/@PACKAGE@
samplessysconfdir = $(sysconfdir)

samplesconf_SCRIPTS = \
	swtpm-localca

samplessysconf_DATA = \
	swtpm-localca.conf \
	swtpm-localca.options 

install-data-local:
	$(MKDIR_P) $(DESTDIR)/$(localstatedir)/lib/swtpm-localca
	if test -z $(DESTDIR); then \
		chown @TSS_USER@:@TSS_GROUP@ $(DESTDIR)/$(localstatedir)/lib/swtpm-localca; \
	fi

install-exec:
	chmod 755 $(DESTDIR)/$(samplesconfdir)/swtpm-localca

EXTRA_DIST= \
	swtpm-localca \
	swtpm-localca.conf \
	swtpm-localca.options
