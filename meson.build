project(
  'swtpm',
  'c',
  version: '0.11.0',
  license: 'BSD-3-Clause',
  default_options: ['c_std=gnu99', 'warning_level=1', 'werror=true'],
  meson_version: '>=1.3.0',
)

cc = meson.get_compiler('c')
fs = import('fs')

host_system = host_machine.system()
prefix = get_option('prefix')
sysconfdir = get_option('sysconfdir')
localstatedir = get_option('localstatedir')

option_cuse = get_option('cuse')
option_gnutls = get_option('gnutls')
option_selinux = get_option('selinux')
option_chardev = get_option('chardev')
option_vtpm_proxy = get_option('vtpm_proxy')
option_seccomp = get_option('seccomp')
option_tests = get_option('tests')
option_hardening = get_option('hardening')
option_default_pcr_banks = ','.join(get_option('default_pcr_banks'))
option_tss_user = get_option('tss_user')
option_tss_group = get_option('tss_group')

conf_data = configuration_data()
version_parts = meson.project_version().split('.')
swtpm_ver_major = version_parts[0].to_int()
swtpm_ver_minor = version_parts[1].to_int()
swtpm_ver_micro = version_parts[2].to_int()

warning_flags = [
  '-Wreturn-type',
  '-Wsign-compare',
  '-Wswitch-enum',
  '-Wmissing-prototypes',
  '-Wformat',
  '-Wformat-security',
  '-Wshadow',
]
supported_warning_flags = cc.get_supported_arguments(warning_flags)
add_project_arguments(supported_warning_flags, language: 'c')

libtpms_dep = dependency('libtpms', version: '>=0.10.0')
cryptolib = libtpms_dep.get_variable('cryptolib')
if cryptolib != 'openssl'
  error('Unsupported crypto library: ' + cryptolib)
endif

libtasn1_dep = dependency('libtasn1')

json_glib_dep = dependency('json-glib-1.0')
glib_dep = dependency('glib-2.0')
gmp_dep = dependency('gmp')

# OpenSSL
libcrypto_dep = dependency('libcrypto')
cc.has_function('AES_set_encrypt_key', dependencies: libcrypto_dep, required: true)
cc.has_header('openssl/aes.h', dependencies: libcrypto_dep, required: true)
if cc.has_header('openssl/fips.h', dependencies: libcrypto_dep)
  conf_data.set('HAVE_OPENSSL_FIPS_H', 1)
endif
if cc.has_function('FIPS_mode_set', dependencies: libcrypto_dep)
  conf_data.set('HAVE_OPENSSL_FIPS_MODE_SET_API', 1)
endif

# Find optional librt dependency for clock_gettime
# Check if clock_gettime is in libc first, then try librt
librt_dep = dependency('', required: false)
if not cc.has_function('clock_gettime')
  librt_dep = cc.find_library('rt', required: true)
  if not cc.has_function('clock_gettime', dependencies: librt_dep)
    error('clock_gettime function not found')
  endif
endif

with_cuse = false
if not option_cuse.disabled()
  fuse3_dep = dependency('fuse3', required: false)
  fuse_dep = dependency('fuse', required: false)

  if fuse3_dep.found()
    fuse_dep = fuse3_dep
    with_cuse = true
  elif fuse_dep.found()
    with_cuse = true
    fuse_dep = declare_dependency(dependencies: fuse_dep, compile_args: ['-DWITH_FUSE2'])
  elif option_cuse.enabled()
    error('CUSE support requested but FUSE not found')
  endif

  if with_cuse
    conf_data.set('WITH_CUSE', 1)
    gthread_dep = dependency('gthread-2.0')
  endif
endif

with_chardev = false
if not option_chardev.disabled()
  if host_system == 'linux'
    with_chardev = true
    conf_data.set('WITH_CHARDEV', 1)
  elif option_chardev.enabled()
    error('Character device support requested but not available on this platform')
  endif
endif

with_vtpm_proxy = false
if not option_vtpm_proxy.disabled()
  if host_system == 'linux'
    with_vtpm_proxy = true
    conf_data.set('WITH_VTPM_PROXY', 1)
  elif option_vtpm_proxy.enabled()
    error('VTPM proxy support requested but not available on this platform')
  endif
endif

option_seccomp.disable_auto_if(host_system != 'linux')
libseccomp_dep = dependency('libseccomp', required: option_seccomp)
if libseccomp_dep.found()
  conf_data.set('WITH_SECCOMP', 1)
endif

gnutls_dep = dependency('gnutls', version: '>=3.4.0', required: option_gnutls)
with_gnutls = gnutls_dep.found()
if with_gnutls
  conf_data.set('WITH_GNUTLS', 1)
  asn1parser = find_program('asn1Parser', required: true)
endif

# Hardening flags
hardening_cflags = []
if option_hardening
  args = ['-fstack-protector-strong', '-Wstack-protector']
  if cc.has_multi_arguments(args)
    hardening_cflags += args
  else
    args = ['-fstack-protector', '-Wstack-protector']
    if cc.has_multi_arguments(args)
      hardening_cflags += args
    endif
  endif

  if get_option('optimization') != '0'
    args = '-D_FORTIFY_SOURCE=2'
    if cc.has_argument(args)
      hardening_cflags += args
    endif
  endif

  args = '-Wl,-z,relro'
  if cc.has_link_argument(args)
    hardening_cflags += args
  endif

  args = '-Wl,-z,now'
  if cc.has_link_argument(args)
    hardening_cflags += args
  endif
endif
add_project_arguments(hardening_cflags, language: 'c')

pod2man = find_program('pod2man', required: false)

# SELinux support
with_selinux = false
if not option_selinux.disabled()
  selinux_makefile = '/usr/share/selinux/devel/Makefile'
  if fs.exists(selinux_makefile)
    with_selinux = true
    conf_data.set('WITH_SELINUX', 1)
  elif option_selinux.enabled()
    error('SELinux support requested but requirements not met')
  endif
endif

conf_data.set('PACKAGE', '"@0@"'.format(meson.project_name()))
conf_data.set('PACKAGE_NAME', '"@0@"'.format(meson.project_name()))
conf_data.set('PACKAGE_VERSION', '"@0@"'.format(meson.project_version()))
conf_data.set('VERSION', '"@0@"'.format(meson.project_version()))
conf_data.set('SWTPM_VER_MAJOR', swtpm_ver_major)
conf_data.set('SWTPM_VER_MINOR', swtpm_ver_minor)
conf_data.set('SWTPM_VER_MICRO', swtpm_ver_micro)

conf_data.set_quoted('TSS_USER', option_tss_user)
conf_data.set_quoted('TSS_GROUP', option_tss_group)
conf_data.set_quoted('SWTPM_DEFAULT_PCR_BANKS', option_default_pcr_banks)

conf_data.set_quoted('SYSCONFDIR', sysconfdir)
conf_data.set_quoted('LOCALSTATEDIR', localstatedir)
conf_data.set_quoted('BINDIR', get_option('bindir'))
conf_data.set_quoted('SBINDIR', get_option('sbindir'))
conf_data.set_quoted('LIBDIR', get_option('libdir'))
conf_data.set_quoted('DATADIR', get_option('datadir'))
conf_data.set_quoted('DATAROOTDIR', get_option('datadir'))
conf_data.set_quoted('MANDIR', get_option('mandir'))
conf_data.set_quoted('SYSCONFDIR', sysconfdir)

configure_file(output: 'config.h', configuration: conf_data)
configure_file(input: 'swtpm.spec.in', output: 'swtpm.spec', configuration: conf_data)
root_inc = include_directories('.')

shell_scripts_dirs = []

subdir('debian')
subdir('include')
if pod2man.found()
  subdir('man')
endif
subdir('samples')
subdir('src')
if option_tests
  subdir('tests')
endif

run_target(
  'syntax-check',
  command: [
    find_program('check_shell_scripts.py'),
    '-v', shell_scripts_dirs,
  ],
  env: {
    # SC2009: Consider using pgrep instead of grepping ps output.
    # SC2317: (info): Command appears to be unreachable. Check usage (or ignore if invoked indirectly).
    'SHELLCHECK_ARGS': '-x -e SC2009,SC2317',
  },
)

summary_info = {}
summary_info += {
  'gnutls' + (with_gnutls ? '' : ' (swtpm_cert NOT built)'): gnutls_dep,
}
summary_info += {
  'selinux'
  + (with_selinux ? '' : ' (SELinux policy NOT built))'): with_selinux,
}
summary_info += {'cuse': fuse_dep}
summary_info += {'chardev': with_chardev}
summary_info += {'vtpm_proxy': with_vtpm_proxy}
summary_info += {'seccomp': libseccomp_dep}
summary_info += {'PCR banks': option_default_pcr_banks}
summary_info += {'TSS user': option_tss_user}
summary_info += {'TSS group': option_tss_group}
summary_info += {'tests': option_tests}
summary(summary_info, bool_yn: true)
