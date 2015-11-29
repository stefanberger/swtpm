#
# src/swtpm_setup/Makefile.am
#
# For the license, see the LICENSE file in the root directory.
#

noinst_HEADERS = \
	swtpm_setup.h

bin_PROGRAMS = \
	swtpm_setup

swtpm_setup_SOURCES = swtpm_setup.c

dist_bin_SCRIPTS = swtpm_setup.sh

install-exec-hook:
	if test -z $(DESTDIR); then \
		chown @TSS_USER@:@TSS_GROUP@ $(DESTDIR)/$(bindir)/swtpm_setup.sh; \
	fi
	chmod 755 $(DESTDIR)/$(bindir)/swtpm_setup.sh
	
EXTRA_DIST = \
	README
