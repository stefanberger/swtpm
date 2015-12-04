#
# src/swtpm_cert/Makefile.am
#
# For the license, see the LICENSE file in the root directory.
#

noinst_HEADERS =

bin_PROGRAMS =

if WITH_GNUTLS
bin_PROGRAMS += \
	swtpm_cert
endif

swtpm_cert_SOURCES = \
	ek-cert.c

swtpm_cert_CFLAGS = \
	-I$(top_srcdir)/include

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
