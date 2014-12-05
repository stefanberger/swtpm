#
# src/swtpm_setup/Makefile.am
#
# For the license, see the LICENSE file in the root directory.
#

bin_PROGRAMS = \
	swtpm_setup

#	swtpm_tcsd_launcher

swtpm_setup_SOURCES = swtpm_setup.c

# swtpm_tcsd_launcher_SOURCES = tcsd-launcher.c

dist_bin_SCRIPTS = swtpm_setup.sh

install-exec-hook:
	chown tss:tss $(DESTDIR)/$(bindir)/swtpm_setup.sh
	chmod 750 $(DESTDIR)/$(bindir)/swtpm_setup.sh
	
#chmod 4755 $(DESTDIR)/$(bindir)/swtpm_tcsd_launcher
