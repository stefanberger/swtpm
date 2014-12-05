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

ek-cert.o : tpm_asn1.h

swtpm_cert_LDADD = -ltasn1

tpm_asn1.h : tpm.asn
	asn1Parser -o $@ $^ 

EXTRA_DIST = \
	tpm.asn
