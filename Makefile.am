#
# Makefile.am
#
# For the license, see the COPYING file in the root directory.
#

SUBDIRS   = \
	etc \
	include \
	man \
	samples \
	src \
	tests

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = \
	CHANGES \
	INSTALL \
	LICENSE \
	COPYING \
	README \
	autogen.sh

if WITH_SELINUX
selinux-install selinux-uninstall:
	@cd src/selinux && $(MAKE) $(AM_MAKEFLAGS) $@
.PHONY: selinux-install selinux-uninstall
endif

python-install python-uninstall:
	@cd samples && $(MAKE) $(AM_MAKEFLAGS) $@
	@cd src/swtpm_setup && $(MAKE) $(AM_MAKEFLAGS) $@
.PHONY: python-install python-uninstall
