# The SELinux Makefile is tricky to work with from meson...
# https://github.com/mesonbuild/meson/pull/14889

sh = find_program('/bin/sh')
find_program('make')
selinux_makefile = '/usr/share/selinux/devel/Makefile'
selinux_packages_dir = join_paths(get_option('prefix'), get_option('datadir'), 'selinux', 'packages')

swtpm_fc = configure_file(
  input: 'swtpm.fc.in',
  output: 'swtpm.fc',
  configuration: {'prefix': get_option('prefix')},
)

swtpm_te = configure_file(
  input: 'swtpm.te',
  output: 'swtpm.te',
  copy: true,
)

custom_target(
  'swtpm.pp',
  output: 'swtpm.pp',
  input: [swtpm_te, swtpm_fc],
  command: [
    sh,
    '-c', 'cd '
    + meson.current_build_dir()
    + '&& make QUIET=0 -f '
    + selinux_makefile
    + ' swtpm.pp',
  ],
  install_dir: selinux_packages_dir,
  console: true,
)

swtpm_svirt_te = configure_file(
  input: 'swtpm_svirt.te',
  output: 'swtpm_svirt.te',
  copy: true,
)

custom_target(
  'swtpm_svirt.pp',
  output: 'swtpm_svirt.pp',
  input: [swtpm_svirt_te],
  command: [
    sh,
    '-c', 'cd '
    + meson.current_build_dir()
    + '&& make QUIET=0 -f '
    + selinux_makefile
    + ' swtpm_svirt.pp',
  ],
  install_dir: selinux_packages_dir,
  console: true,
)

swtpm_libvirt_te = configure_file(
  input: 'swtpm_libvirt.te',
  output: 'swtpm_libvirt.te',
  copy: true,
)

custom_target(
  'swtpm_libvirt.pp',
  output: 'swtpm_libvirt.pp',
  input: [swtpm_libvirt_te],
  command: [
    sh,
    '-c', 'cd '
    + meson.current_build_dir()
    + '&& make QUIET=0 -f '
    + selinux_makefile
    + ' swtpm_libvirt.pp',
  ],
  install_dir: selinux_packages_dir,
  console: true,
)

if with_cuse
  swtpmcuse_fc = configure_file(
    input: 'swtpmcuse.fc.in',
    output: 'swtpmcuse.fc',
    configuration: {'prefix': get_option('prefix')},
  )

  swtpmcuse_te = configure_file(
    input: 'swtpmcuse.te',
    output: 'swtpmcuse.te',
    copy: true,
  )

  custom_target(
    'swtpmcuse.pp',
    output: 'swtpmcuse.pp',
    input: [swtpmcuse_te, swtpmcuse_fc],
    command: [
      sh,
      '-c', 'cd '
      + meson.current_build_dir()
      + '&& make QUIET=0 -f '
      + selinux_makefile
      + ' swtpmcuse.pp',
    ],
    install_dir: selinux_packages_dir,
    console: true,
  )

endif
