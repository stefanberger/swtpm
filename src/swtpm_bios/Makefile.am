#
# src/swtpm_bios/Makefile.am
#
# For the license, see the LICENSE file in the root directory.
#

MY_CFLAGS = @MY_CFLAGS@
MY_LDFLAGS = @MY_LDFLAGS@

noinst_HEADERS = \
	tpm_bios.h

bin_PROGRAMS = \
	swtpm_bios

swtpm_bios_CFLAGS = \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/include \
	$(MY_CFLAGS) \
	$(CFLAGS) \
	$(HARDENING_CFLAGS)

swtpm_bios_LDFLAGS = \
	$(MY_LDFLAGS) \
	$(HARDENING_LDFLAGS)

swtpm_bios_SOURCES = tpm_bios.c

EXTRA_DIST = \
	README

CLEANFILES = *.gcno *.gcda *.gcov
