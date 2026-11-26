man8_pods = [
  'swtpm.pod',
  'swtpm_bios.pod',
  'swtpm_cert.pod',
  'swtpm_ioctl.pod',
  'swtpm_localca.pod',
  'swtpm_setup.pod',
  'swtpm-create-tpmca.pod',
]

man8_pages = []
foreach pod : man8_pods
  name = pod.split('.pod')[0] # Extract name before .pod
  man8_page = custom_target(
    name + '.8',
    input: pod,
    output: name + '.8',
    command: [pod2man, '-r', 'swtpm', '-c', '', '-n', name, '--section=8', '@INPUT@'],
    capture: true,
    install: true,
    install_dir: get_option('mandir') / 'man8',
  )
  man8_pages += man8_page
endforeach

# Install static man pages (already generated)
install_data('swtpm-localca.8', install_dir: get_option('mandir') / 'man8')

# Install swtpm_cuse.8 only if CUSE is enabled
if with_cuse
  install_data('swtpm_cuse.8', install_dir: get_option('mandir') / 'man8')
endif
