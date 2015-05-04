#
# samples/Makefile.am
#
# For the license, see the LICENSE file in the root directory.
#

samplesconfdir = $(datadir)/@PACKAGE@
samplessysconfdir = $(sysconfdir)

samplesconf_DATA = \
	swtpm-localca

samplessysconf_DATA = \
	swtpm-localca.conf \
	swtpm-localca.options 

install-data-local:
	$(MKDIR_P) $(DESTDIR)/$(localstatedir)/lib/swtpm-localca
	chown tss:tss $(DESTDIR)/$(localstatedir)/lib/swtpm-localca

EXTRA_DIST= \
	swtpm-localca \
	swtpm-localca.conf \
	swtpm-localca.options
