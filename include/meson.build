subdir('swtpm')

configure_file(
  input: 'swtpm.h.in',
  output: 'swtpm.h',
  configuration: conf_data,
)

# Make swtpm.h available for other parts of the build
include_inc = include_directories('.')
swtpm_inc = include_directories('swtpm')
