# swtpm_localca executable
swtpm_localca = executable('swtpm_localca',
  sources: [
    'swtpm_localca.c',
    'swtpm_localca_utils.c',
  ],
  dependencies: [
    glib_dep,
    gmp_dep,
  ],
  include_directories: [
    include_directories('../utils'),
    root_inc,
  ],
  link_with: [libswtpm_utils],
  install: true
)
