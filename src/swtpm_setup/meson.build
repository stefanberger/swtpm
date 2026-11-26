swtpm_setup = executable(
  'swtpm_setup',
  sources: [
    'profile.c',
    'swtpm.c',
    'swtpm_setup.c',
    'swtpm_setup_utils.c',
    'swtpm_backend_dir.c',
    'swtpm_backend_file.c',
  ],
  dependencies: [
    glib_dep,
    json_glib_dep,
    libcrypto_dep,
  ],
  include_directories: [
    include_inc,
    root_inc,
    swtpm_inc,
    include_directories('../utils'),
  ],
  link_with: [libswtpm_utils],
  install: true,
)
