#
# src/swtpm_setup/Makefile.am
#
# For the license, see the LICENSE file in the root directory.
#

bin_PROGRAMS = \
	swtpm_setup

swtpm_setup_SOURCES = swtpm_setup.c

dist_bin_SCRIPTS = swtpm_setup.sh

install-exec-hook:
	@if test $$(id -u) != 0; then					\
		echo "You must be root to install swtpm_setup.sh.";	\
		exit 1;							\
	fi
	chown tss:tss $(DESTDIR)/$(bindir)/swtpm_setup.sh
	chmod 750 $(DESTDIR)/$(bindir)/swtpm_setup.sh
	
EXTRA_DIST = \
	README
