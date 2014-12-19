#
# tests/Makefile.am
#
# For the license, see the LICENSE file in the root directory.
#

check_PROGRAMS =

TESTS = \
	test_init \
	test_getcap \
	test_locality \
	test_hashing \
	test_hashing2 \
	test_volatilestate \
	test_wrongorder \
	test_encrypted_state \
	\
	test_commandline \
	test_parameters \
	test_resume_volatile

if WITH_GNUTLS
TESTS += \
	test_swtpm_cert
endif
	
EXTRA_DIST=$(TESTS) \
	swtpm_setup.conf \
	create_certs.sh \
	data/issuercert.pem \
	data/pubek.pem \
	data/signkey.pem \
	data/keyfile.txt \
	data/pwdfile.txt \
	data/tpmstate1/tpm-00.permall \
	data/tpmstate1/tpm-00.volatilestate \
	data/tpmstate1/README \
	data/tpmstate2/tpm-00.permall \
	data/tpmstate2/tpm-00.volatilestate \
	data/tpmstate2/pwdfile.txt \
	data/tpmstate2/README \
	test_swtpm_cert
