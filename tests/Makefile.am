#
# tests/Makefile.am
#
# For the license, see the LICENSE file in the root directory.
#

check_PROGRAMS =

TESTS = \
	test_vtpm_proxy

if WITH_CHARDEV
TESTS += \
	test_ctrlchannel \
	test_ctrlchannel2
endif

TESTS += \
	test_encrypted_state \
	test_getcap \
	test_hashing \
	test_hashing2 \
	test_init \
	test_locality \
	test_migration_key \
	test_resume_volatile \
	test_save_load_encrypted_state \
	test_save_load_state \
	test_volatilestate \
	test_swtpm_bios \
	test_wrongorder

if WITH_SWTPM_SETUP
TESTS += \
	test_commandline \
	test_parameters
endif

if WITH_GNUTLS
TESTS += \
	test_swtpm_cert
if WITH_SWTPM_SETUP
TESTS += \
	test_swtpm_setup_create_cert
endif
endif

EXTRA_DIST=$(TESTS) \
	swtpm_setup.conf \
	create_certs.sh \
	data/issuercert.pem \
	data/pubek.pem \
	data/signkey.pem \
	data/keyfile.txt \
	data/pwdfile.txt \
	data/migkey1/volatilestate.bin \
	data/tpmstate1/tpm-00.permall \
	data/tpmstate1/tpm-00.volatilestate \
	data/tpmstate1/README \
	data/tpmstate2/tpm-00.permall \
	data/tpmstate2/tpm-00.volatilestate \
	data/tpmstate2/pwdfile.txt \
	data/tpmstate2/README \
	test_common \
	test_cuse \
	test_swtpm_cert
