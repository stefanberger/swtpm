man3_pods = ['swtpm_ioctls.pod']

man3_pages = []
foreach pod : man3_pods
  name = pod.split('.')[0] # Extract name before first dot
  man3_page = custom_target(
    name + '.3',
    input: pod,
    output: name + '.3',
    command: [pod2man, '-r', 'swtpm', '-c', '', '-n', name, '--section=3', '@INPUT@'],
    capture: true,
    install: true,
    install_dir: get_option('mandir') / 'man3',
  )
  man3_pages += man3_page
endforeach
