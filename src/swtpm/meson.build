libswtpm_libtpms_sources = [
  'capabilities.c',
  'check_algos.c',
  'common.c',
  'ctrlchannel.c',
  'fips.c',
  'key.c',
  'logging.c',
  'mainloop.c',
  'options.c',
  'pidfile.c',
  'profile.c',
  'seccomp_profile.c',
  'server.c',
  'swtpm_aes.c',
  'swtpm_debug.c',
  'swtpm_io.c',
  'swtpm_nvstore.c',
  'swtpm_nvstore_dir.c',
  'swtpm_nvstore_linear.c',
  'swtpm_nvstore_linear_file.c',
  'tlv.c',
  'tpmlib.c',
  'tpmstate.c',
  'utils.c',
]

if with_cuse
  libswtpm_libtpms_sources += ['threadpool.c']
endif

# libswtpm_libtpms private shared library
libswtpm_libtpms = shared_library(
  'swtpm_libtpms',
  sources: libswtpm_libtpms_sources,
  dependencies: [
    libtpms_dep,
    glib_dep,
    json_glib_dep,
    librt_dep,
    libseccomp_dep,
    libcrypto_dep,
  ],
  include_directories: [
    include_inc,
    root_inc,
    swtpm_inc,
    include_directories('../utils'),
  ],
  install: true,
  install_dir: get_option('libdir') / 'swtpm',
)

# Common sources for swtpm executables
swtpm_sources = [
  'main.c',
  'daemonize.c',
  'swtpm.c',
  'swtpm_chardev.c',
]

# Add conditional CUSE source
if with_cuse
  swtpm_sources += ['cuse_tpm.c']
endif

# Main swtpm executable
swtpm = executable(
  'swtpm',
  sources: swtpm_sources,
  dependencies: [
    libtpms_dep,
    glib_dep,
    fuse_dep,
    gthread_dep,
  ],
  include_directories: [
    include_inc,
    root_inc,
    swtpm_inc,
    include_directories('../utils'),
  ],
  c_args: [
    '-DHAVE_SWTPM_CUSE_MAIN',
  ],
  link_with: [libswtpm_libtpms],
  install: true,
)

# swtpm_cuse executable (CUSE-only)
if with_cuse
  executable(
    'swtpm_cuse',
    sources: ['cuse_tpm.c'],
    dependencies: [
      libtpms_dep,
      glib_dep,
      fuse_dep,
      gthread_dep,
    ],
    include_directories: [
      include_inc,
      root_inc,
      swtpm_inc,
      include_directories('../utils'),
    ],
    link_with: [libswtpm_libtpms],
    install: true,
  )
endif
