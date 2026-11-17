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
	cd $(srcdir) && codespell -L addresse,alog,daa,filp,ody,parm,te \
		$$(find include man src \( -name '*.pod' -o -name '*.c' -o -name '*.h' \) -not -path '*/.libs/*')
	@cd samples && $(MAKE) syntax-check
	@cd tests && $(MAKE) syntax-check

.PHONY: selinux-install selinux-uninstall syntax-check
