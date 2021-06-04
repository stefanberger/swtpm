#
# src/cuse_tpm_ioctl/Makefile.am
#
# For the license, see the LICENSE file in the root directory.
#

noinst_HEADERS =

bin_PROGRAMS = \
	swtpm_ioctl

swtpm_ioctl_SOURCES = tpm_ioctl.c

swtpm_ioctl_CFLAGS = \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/include \
	$(HARDENING_CFLAGS)

swtpm_ioctl_LDFLAGS = \
	$(HARDENING_LDFLAGS)

EXTRA_DIST = \
	README

CLEANFILES = *.gcno *.gcda *.gcov
