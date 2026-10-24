samplesdir = get_option('datadir') / 'swtpm'

configure_file(
  input: 'swtpm-localca.conf.in',
  output: 'swtpm-localca.conf',
  configuration: conf_data,
  install: true,
  install_dir: sysconfdir,
)

configure_file(
  input: 'swtpm-create-user-config-files.in',
  output: 'swtpm-create-user-config-files',
  configuration: conf_data,
  install: true,
  install_dir: samplesdir,
  install_mode: 'rwxr-xr-x',
)

swtpm_conf = configuration_data()
swtpm_conf.merge_from(conf_data)
swtpm_conf.set('DEFAULT_PCR_BANKS', option_default_pcr_banks)

configure_file(
  input: 'swtpm_setup.conf.in',
  output: 'swtpm_setup.conf',
  configuration: swtpm_conf,
  install: true,
  install_dir: sysconfdir,
)

configure_file(
  input: 'swtpm-localca.in',
  output: 'swtpm-localca',
  configuration: conf_data,
  install: true,
  install_dir: samplesdir,
  install_mode: 'rwxr-xr-x',
)

# Install static sample files
install_data(
  'swtpm-create-tpmca',
  install_dir: samplesdir,
  install_mode: 'rwxr-xr-x',
)

install_data('swtpm-localca.options', install_dir: sysconfdir)

install_emptydir(
  localstatedir / 'lib' / 'swtpm-localca',
  install_mode: ['rwxr-x---', option_tss_user, 'root'],
)

shell_scripts_dirs += [meson.current_build_dir(), meson.current_source_dir()]
