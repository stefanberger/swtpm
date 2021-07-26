#
# src/swtpm_cert/Makefile.am
#
# For the license, see the LICENSE file in the root directory.
#

MY_CFLAGS = @MY_CFLAGS@
MY_LDFLAGS = @MY_LDFLAGS@

noinst_HEADERS =

bin_PROGRAMS =

if WITH_GNUTLS
bin_PROGRAMS += \
	swtpm_cert
endif

swtpm_cert_SOURCES = \
	ek-cert.c

swtpm_cert_CFLAGS = \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/include \
	$(MY_CFLAGS) \
	$(CFLAGS)

swtpm_cert_LDFLAGS = \
	$(MY_LDFLAGS) \
	$(HARDENING_LDFLAGS)

ek-cert.o : tpm_asn1.h

swtpm_cert_LDADD = \
	$(LIBTASN1_LIBS) \
	$(GNUTLS_LIBS)

tpm_asn1.h : tpm.asn
	asn1Parser -o $@ $^ 

EXTRA_DIST = \
	tpm.asn \
	tpm_asn1.h \
	README

CLEANFILES = *.gcno *.gcda *.gcov
