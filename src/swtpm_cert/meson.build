if with_gnutls
  # Generate tpm_asn1.h from tpm.asn
  tpm_asn1_h = custom_target('tpm_asn1.h',
    input: 'tpm.asn',
    output: 'tpm_asn1.h',
    command: [asn1parser, '-o', '@OUTPUT@', '@INPUT@']
  )

  # swtpm_cert executable (conditional on GnuTLS)
  swtpm_cert = executable('swtpm_cert',
    sources: [
      'ek-cert.c',
      tpm_asn1_h,
    ],
    dependencies: [
      libtasn1_dep,
      gnutls_dep,
      gmp_dep,
    ],
    include_directories: [
      include_inc,
      root_inc,
    ],
    install: true
  )
endif
