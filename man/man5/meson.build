man5_pods = [
  'swtpm_setup.conf.pod',
  'swtpm-localca.options.pod',
  'swtpm-localca.conf.pod',
]

man5_pages = []
foreach pod : man5_pods
  name = pod.split('.pod')[0] # Extract name before .pod
  man5_page = custom_target(
    name + '.5',
    input: pod,
    output: name + '.5',
    command: [pod2man, '-r', 'swtpm', '-c', '', '-n', name, '--section=5', '@INPUT@'],
    capture: true,
    install: true,
    install_dir: get_option('mandir') / 'man5',
  )
  man5_pages += man5_page
endforeach
