swtpm_conf_data = configuration_data()
swtpm_conf_data.set('SWTPM_VER_MAJOR', swtpm_ver_major)
swtpm_conf_data.set('SWTPM_VER_MINOR', swtpm_ver_minor)
swtpm_conf_data.set('SWTPM_VER_MICRO', swtpm_ver_micro)
swtpm_conf_data.set('SYSCONFDIR', sysconfdir)
swtpm_conf_data.set('BINDIR', get_option('bindir'))
swtpm_conf_data.set('DATAROOTDIR', get_option('datadir'))
swtpm_conf_data.set('DEFAULT_PCR_BANKS', option_default_pcr_banks)

swtpm_conf_h = configure_file(
  input: 'swtpm_conf.h.in',
  output: 'swtpm_conf.h',
  configuration: swtpm_conf_data,
)

libswtpm_utils = static_library(
  'swtpm_utils',
  sources: [
    'swtpm_utils.c',
    swtpm_conf_h,
  ],
  dependencies: [
    glib_dep,
    json_glib_dep,
  ],
  include_directories: [
    include_inc,
    root_inc,
  ],
)
