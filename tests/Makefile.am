#
# tests/Makefile.am
#
# For the license, see the LICENSE file in the root directory.
#

check_PROGRAMS =

TESTS_ENVIRONMENT = \
  abs_top_testdir=`cd '$(top_srcdir)'/tests; pwd` \
  abs_top_builddir=`cd '$(top_builddir)'; pwd` \
  abs_top_srcdir=`cd '$(top_srcdir)'; pwd`

TESTS = \
	test_vtpm_proxy \
	test_tpm2_vtpm_proxy

TESTS += \
	test_commandline \
	test_ctrlchannel \
	test_ctrlchannel2 \
	test_ctrlchannel3 \
	test_ctrlchannel4 \
	test_encrypted_state \
	test_getcap \
	test_hashing \
	test_hashing2 \
	test_init \
	test_locality \
	test_migration_key \
	test_parameters \
	test_resume_volatile \
	test_save_load_encrypted_state \
	test_save_load_state \
	test_setbuffersize \
	test_volatilestate \
	test_swtpm_bios \
	test_tpm_probe \
	test_tpm12 \
	test_wrongorder \
	\
	test_print_capabilities \
	test_print_states \
	test_swtpm_setup_overwrite \
	test_swtpm_setup_file_backend \
	test_swtpm_setup_misc

TESTS += \
	test_tpm2_ctrlchannel2 \
	test_tpm2_derived_keys \
	test_tpm2_encrypted_state \
	test_tpm2_init \
	test_tpm2_file_permissions \
	test_tpm2_getcap \
	test_tpm2_locality \
	test_tpm2_hashing \
	test_tpm2_hashing2 \
	test_tpm2_hashing3 \
	test_tpm2_migration_key \
	test_tpm2_partial_reads \
	test_tpm2_print_capabilities \
	test_tpm2_print_states \
	test_tpm2_resume_volatile \
	test_tpm2_savestate \
	test_tpm2_save_load_encrypted_state \
	test_tpm2_save_load_state \
	test_tpm2_save_load_state_2 \
	test_tpm2_save_load_state_2_linear \
	test_tpm2_save_load_state_2_block \
	test_tpm2_save_load_state_3 \
	test_tpm2_save_load_state_da_timeout \
	test_tpm2_setbuffersize \
	test_tpm2_volatilestate \
	test_tpm2_wrongorder \
	test_tpm2_probe \
	\
	test_tpm2_swtpm_bios \
	\
	test_tpm2_ibmtss2 \
	test_tpm2_swtpm_setup_overwrite

if WITH_GNUTLS
TESTS += \
	test_samples_create_tpmca \
	test_swtpm_cert \
	test_swtpm_setup_create_cert \
	test_tpm2_parameters \
	test_tpm2_swtpm_cert \
	test_tpm2_swtpm_cert_ecc \
	test_tpm2_swtpm_localca \
	test_tpm2_swtpm_localca_pkcs11.test \
	test_tpm2_swtpm_setup_create_cert

if HAVE_TCSD
TESTS += \
	test_tpm2_samples_create_tpmca.test

# Prevent concurrency between these two
test_tpm2_samples_create_tpmca.log: test_tpm2_swtpm_localca_pkcs11.log
endif

endif

EXTRA_DIST=$(TESTS) \
	swtpm_setup.conf \
	common \
	create_certs.sh \
	data/ecpubek.pem \
	data/ecprivek.pem \
	data/issuercert.pem \
	data/pubek.pem \
	data/signkey.pem \
	data/signkey-encrypted.pem \
	data/keyfile.txt \
	data/keyfile256bit.txt \
	data/pwdfile.txt \
	data/migkey1/tpm2-volatilestate.bin \
	data/migkey1/volatilestate.bin \
	data/tpmstate1/tpm-00.permall \
	data/tpmstate1/tpm-00.volatilestate \
	data/tpmstate1/README \
	data/tpmstate2/tpm-00.permall \
	data/tpmstate2/tpm-00.volatilestate \
	data/tpmstate2/pwdfile.txt \
	data/tpmstate2/README \
	data/tpmstate2b/tpm-00.permall \
	data/tpmstate2b/tpm-00.volatilestate \
	data/tpmstate2b/pwdfile.txt \
	data/tpm2state1/tpm2-00.permall \
	data/tpm2state1/tpm2-00.volatilestate \
	data/tpm2state2/tpm2-00.permall \
	data/tpm2state2/tpm2-00.volatilestate \
	data/tpm2state2b/pwdfile.txt \
	data/tpm2state2b/tpm2-00.permall \
	data/tpm2state2b/tpm2-00.volatilestate \
	data/tpm2state2/pwdfile.txt \
	data/tpm2state3/hkey.priv \
	data/tpm2state3/hkey.pub \
	data/tpm2state3/signature.bin \
	data/tpm2state3/tpm2-00.permall \
	data/tpm2state3c/tpm2-00.volatilestate \
	data/tpm2state3c/tpm2-00.permall \
	data/tpm2state3d/tpm2-00.volatilestate \
	data/tpm2state3d/signature2.bin \
	data/tpm2state3d/tpm2-00.permall \
	data/tpm2state3b/h81000000.bin \
	data/tpm2state3b/h02000000.bin \
	data/tpm2state3b/tpm2-00.volatilestate \
	data/tpm2state3b/tpm2-00.permall \
	data/tpm2state4/tpm2-00.volatilestate \
	data/tpm2state4/tpm2-00.permall \
	data/tpm2state5/signature.bin \
	data/tpm2state5/tpm2-00.permall \
	load_vtpm_proxy \
	patches/0001-Deactivate-test-cases-accessing-rootcerts.txt.patch \
	patches/0002-Implement-powerup-for-swtpm.patch \
	patches/0003-Set-CRYPTOLIBRARY-to-openssl.patch \
	patches/0004-Store-and-restore-volatile-state-at-every-step.patch \
	patches/0005-Disable-tests-related-to-events.patch \
	patches/0006-Disable-testing-with-RSA-3072.patch \
	patches/0007-Disable-rev155-test-cases.patch \
	patches/0008-Disable-x509-test-cases.patch \
	patches/0009-Disable-getcapability-TPM_CAP_ACT.patch \
	patches/libtpm.patch \
	softhsm_setup \
	test_clientfds.py \
	test_common \
	test_cuse \
	test_setdatafd.py \
	test_swtpm_cert \
	_test_encrypted_state \
	_test_getcap \
	_test_hashing \
	_test_hashing2 \
	_test_init \
	_test_locality \
	_test_migration_key \
	_test_migration_key_2 \
	_test_print_capabilities \
	_test_print_states \
	_test_resume_volatile \
	_test_save_load_encrypted_state \
	_test_save_load_state \
	_test_setbuffersize \
	_test_swtpm_bios \
	_test_tpm_probe \
	_test_tpm2_derived_keys \
	_test_tpm2_encrypted_state \
	_test_tpm2_getcap \
	_test_tpm2_hashing \
	_test_tpm2_hashing2 \
	_test_tpm2_hashing3 \
	_test_tpm2_init \
	_test_tpm2_locality \
	_test_tpm2_migration_key \
	_test_tpm2_print_capabilities \
	_test_tpm2_print_states \
	_test_tpm2_probe \
	_test_tpm2_resume_volatile \
	_test_tpm2_savestate \
	_test_tpm2_save_load_encrypted_state \
	_test_tpm2_save_load_state \
	_test_tpm2_save_load_state_da_timeout \
	_test_tpm2_setbuffersize \
	_test_tpm2_swtpm_bios \
	_test_tpm2_volatilestate \
	_test_tpm2_wrongorder \
	_test_volatilestate \
	_test_wrongorder

check-display:
	@if test -n "$$SWTPM_EXE"; then \
		echo "*** Using SWTPM_EXE=$$SWTPM_EXE"; \
	fi
	@if test -n "$$SWTPM_BIOS"; then \
		echo "*** Using SWTPM_BIOS=$$SWTPM_BIOS"; \
	fi
	@if test -n "$$SWTPM_IOCTL"; then \
		echo "*** Using SWTPM_IOCTL=$$SWTPM_IOCTL"; \
	fi
	@if test -n "$$SWTPM_CERT"; then \
		echo "*** Using SWTPM_CERT=$$SWTPM_CERT"; \
	fi

check: check-am check-display
