#
# Makefile.am
#
# For the license, see the COPYING file in the root directory.
#

SUBDIRS   = \
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
	swtpm.spec \
	autogen.sh

if WITH_SELINUX
selinux-install selinux-uninstall:
	@cd src/selinux && $(MAKE) $(AM_MAKEFLAGS) $@
endif

.PHONY: selinux-install selinux-uninstall
