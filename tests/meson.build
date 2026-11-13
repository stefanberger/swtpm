# Test environment variables
test_env = environment()
test_env.set('abs_top_testdir', meson.current_source_dir())
test_env.set('abs_top_builddir', meson.project_build_root())
test_env.set('abs_top_srcdir', meson.project_source_root())
test_deps = [swtpm, swtpm_ioctl, swtpm_bios, swtpm_setup]

configure_file(input: 'test_config.in', output: 'test_config', configuration: conf_data)

# some tests require python (sanity check since meson also needs it)
find_program('python', version: '>=3.3')

# 'netstat' and 'ss', net-tools OR iproute/iproute2 package
find_program('netstat', 'ss', required: true)

# tcsd, need it for tss user account and tests
tcsd = find_program('tcsd', required: false)
if tcsd.found()
  run_command('id', '-u', option_tss_user, check: true)
  run_command('id', '-g', option_tss_group, check: true)
endif

foreach program : ['expect', 'gawk', 'socat', 'base64', 'cp']
  find_program(program, required: true)
endforeach

foreach test : ['vtpm_proxy', 'tpm2_vtpm_proxy']
  test(test, find_program('test_' + test), env: test_env, suite: 'vtpm-proxy')
endforeach

basic_tests = [
  'test_commandline',
  'test_ctrlchannel',
  'test_ctrlchannel2',
  'test_ctrlchannel3',
  'test_ctrlchannel4',
  'test_encrypted_state',
  'test_getcap',
  'test_hashing',
  'test_hashing2',
  'test_init',
  'test_locality',
  'test_migration_key',
  'test_parameters',
  'test_resume_volatile',
  'test_save_load_encrypted_state',
  'test_save_load_state',
  'test_setbuffersize',
  'test_volatilestate',
  'test_swtpm_bios',
  'test_tpm_probe',
  'test_tpm12',
  'test_wrongorder',

  'test_print_capabilities',
  'test_print_states',
  'test_swtpm_setup_overwrite',
  'test_swtpm_setup_file_backend',
  'test_swtpm_setup_misc',
]

# TPM 2.0 tests
tpm2_tests = [
  'test_tpm2_avoid_da_lockout',
  'test_tpm2_chroot_socket',
  'test_tpm2_chroot_chardev',
  'test_tpm2_chroot_cuse',
  'test_tpm2_ctrlchannel2',
  'test_tpm2_ctrlchannel3',
  'test_tpm2_derived_keys',
  'test_tpm2_encrypted_state',
  'test_tpm2_init',
  'test_tpm2_file_permissions',
  'test_tpm2_getcap',
  'test_tpm2_locality',
  'test_tpm2_hashing',
  'test_tpm2_hashing2',
  'test_tpm2_hashing3',
  'test_tpm2_migration_key',
  'test_tpm2_partial_reads',
  'test_tpm2_print_capabilities',
  'test_tpm2_print_states',
  'test_tpm2_resume_volatile',
  'test_tpm2_savestate',
  'test_tpm2_save_load_encrypted_state',
  'test_tpm2_save_load_state',
  'test_tpm2_save_load_state_2',
  'test_tpm2_save_load_state_2_linear',
  'test_tpm2_save_load_state_2_block',
  'test_tpm2_save_load_state_3',
  'test_tpm2_save_load_state_da_timeout',
  'test_tpm2_save_load_state_locking',
  'test_tpm2_setbuffersize',
  'test_tpm2_volatilestate',
  'test_tpm2_wrongorder',
  'test_tpm2_probe',

  'test_tpm2_swtpm_bios',

  'test_tpm2_ibmtss2',
  'test_tpm2_swtpm_setup_overwrite',
  'test_tpm2_swtpm_setup_profile',
  'test_tpm2_swtpm_setup_profile_name',
  'test_tpm2_libtpms_versions_profiles',
]

tests = []

# Register basic TPM 1.2 tests
tests += basic_tests
foreach test_name : basic_tests
  test = find_program(test_name)
  test(
    test_name,
    test,
    env: test_env,
    timeout: 120,
    workdir: meson.current_source_dir(),
    suite: 'basic',
    depends: test_deps,
  )
endforeach

# Register TPM 2.0 tests
tests += tpm2_tests
foreach test_name : tpm2_tests
  test = find_program(test_name)
  test(
    test_name,
    test,
    env: test_env,
    timeout: 120,
    workdir: meson.current_source_dir(),
    suite: 'tpm2',
    depends: test_deps,
  )
endforeach

# Conditional tests that require GnuTLS
if with_gnutls
  gnutls_tests = ['test_swtpm_cert', 'test_tpm2_swtpm_cert']

  tests += gnutls_tests
  foreach test_name : gnutls_tests
    test = find_program(test_name)
    test(
      test_name,
      test,
      env: test_env,
      timeout: 180,
      workdir: meson.current_source_dir(),
      suite: 'gnutls',
      depends: test_deps + swtpm_cert,
    )
  endforeach
endif

tests_utils = files(
  'common',
  'load_vtpm_proxy',
  'test_common',
  'test_cuse',
)

tests_data = files(
  'data/ecprivek.pem',
  'data/ecpubek.pem',
  'data/issuercert.pem',
  'data/keyfile.txt',
  'data/keyfile256bit.txt',
  'data/migkey1/tpm2-volatilestate.bin',
  'data/migkey1/volatilestate.bin',
  'data/pubek.pem',
  'data/pwdfile.txt',
  'data/signkey-encrypted.pem',
  'data/signkey.pem',
  'data/tpm2state1/tpm2-00.permall',
  'data/tpm2state1/tpm2-00.volatilestate',
  'data/tpm2state2/pwdfile.txt',
  'data/tpm2state2/tpm2-00.permall',
  'data/tpm2state2/tpm2-00.volatilestate',
  'data/tpm2state2b/tpm2-00.permall',
  'data/tpm2state2b/tpm2-00.volatilestate',
  'data/tpm2state3/hkey.priv',
  'data/tpm2state3/hkey.pub',
  'data/tpm2state3/signature.bin',
  'data/tpm2state3/tpm2-00.permall',
  'data/tpm2state3b/h02000000.bin',
  'data/tpm2state3b/h81000000.bin',
  'data/tpm2state3b/tpm2-00.permall',
  'data/tpm2state3b/tpm2-00.volatilestate',
  'data/tpm2state3c/tpm2-00.permall',
  'data/tpm2state3c/tpm2-00.volatilestate',
  'data/tpm2state3d/signature2.bin',
  'data/tpm2state3d/tpm2-00.permall',
  'data/tpm2state3d/tpm2-00.volatilestate',
  'data/tpm2state4/tpm2-00.permall',
  'data/tpm2state4/tpm2-00.volatilestate',
  'data/tpm2state5/signature.bin',
  'data/tpm2state5/tpm2-00.permall',
  'data/tpm2state6/tpm2-00.permall',
  'data/tpmstate1/README',
  'data/tpmstate1/tpm-00.permall',
  'data/tpmstate1/tpm-00.volatilestate',
  'data/tpmstate2/README',
  'data/tpmstate2/pwdfile.txt',
  'data/tpmstate2/tpm-00.permall',
  'data/tpmstate2/tpm-00.volatilestate',
  'data/tpmstate2b/pwdfile.txt',
  'data/tpmstate2b/tpm-00.permall',
  'data/tpmstate2b/tpm-00.volatilestate',
  'patches/0001-Deactivate-test-cases-accessing-rootcerts.txt.patch',
  'patches/0002-Implement-powerup-for-swtpm.patch',
  'patches/0003-Set-CRYPTOLIBRARY-to-openssl.patch',
  'patches/0004-Store-and-restore-volatile-state-at-every-step.patch',
  'patches/0005-Disable-tests-related-to-events.patch',
  'patches/0010-Adjust-test-cases-for-OpenSSL-3.patch',
  'patches/0012-Disable-Nuvoton-commands.patch',
  'patches/libtpm.patch',
  '_test_encrypted_state',
  '_test_getcap',
  '_test_hashing',
  '_test_hashing2',
  '_test_init',
  '_test_locality',
  '_test_migration_key',
  '_test_migration_key_2',
  '_test_print_capabilities',
  '_test_print_states',
  '_test_resume_volatile',
  '_test_save_load_encrypted_state',
  '_test_save_load_state',
  '_test_setbuffersize',
  '_test_swtpm_bios',
  '_test_tpm2_avoid_da_lockout',
  '_test_tpm2_derived_keys',
  '_test_tpm2_encrypted_state',
  '_test_tpm2_file_permissions',
  '_test_tpm2_getcap',
  '_test_tpm2_hashing',
  '_test_tpm2_hashing2',
  '_test_tpm2_hashing3',
  '_test_tpm2_init',
  '_test_tpm2_locality',
  '_test_tpm2_migration_key',
  '_test_tpm2_print_capabilities',
  '_test_tpm2_print_states',
  '_test_tpm2_probe',
  '_test_tpm2_resume_volatile',
  '_test_tpm2_save_load_encrypted_state',
  '_test_tpm2_save_load_state',
  '_test_tpm2_save_load_state_da_timeout',
  '_test_tpm2_save_load_state_locking',
  '_test_tpm2_savestate',
  '_test_tpm2_setbuffersize',
  '_test_tpm2_swtpm_bios',
  '_test_tpm2_volatilestate',
  '_test_tpm2_wrongorder',
  '_test_tpm_probe',
  '_test_volatilestate',
  '_test_wrongorder',
  'create_certs.sh',
  'installed-runner.sh',
  'sed-inplace',
  'softhsm_setup',
  'swtpm_setup.conf',
  'test_clientfds.py',
  'test_setdatafd.py',
  'test_swtpm_cert',
)

tests_dir = get_option('prefix') / get_option('libexecdir') / 'installed-tests' / meson.project_name()
install_data(
  tests + tests_utils + tests_data,
  install_dir: tests_dir,
  preserve_path: true,
)

custom_target(
  'Installed runnable test list',
  output: 'tests',
  install: true,
  install_dir: tests_dir,
  command: ['echo', ' '.join(tests)],
  capture: true,
)

meson.add_install_script('meson_post_install.py', tests_dir / 'common')

shell_scripts_dirs += [meson.current_source_dir()]
