#
# Makefile.am
#
# For the license, see the COPYING file in the root directory.
#

SUBDIRS   = \
	include \
	samples \
	src \
	tests

if ENABLE_DOCS
SUBDIRS += man
endif # ENABLE_DOCS

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

syntax-check:
	@cd samples && $(MAKE) syntax-check
	@cd tests && $(MAKE) syntax-check

.PHONY: selinux-install selinux-uninstall syntax-check
