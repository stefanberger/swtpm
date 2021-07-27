#
# man/man8/Makefile.am
#
# For the license, see the COPYING file in the root directory.
#


man8_PODS = \
	swtpm.pod \
	swtpm_bios.pod \
	swtpm_cert.pod \
	swtpm_cuse.pod \
	swtpm_ioctl.pod \
	swtpm_localca.pod \
	swtpm_setup.pod \
	swtpm_setup.conf.pod \
	swtpm-create-tpmca.pod \
	swtpm-localca.options.pod \
	swtpm-localca.conf.pod

man8_generated_MANS = \
	swtpm.8 \
	swtpm_bios.8 \
	swtpm_cert.8 \
	swtpm_ioctl.8 \
	swtpm_localca.8 \
	swtpm_setup.8 \
	swtpm_setup.conf.8 \
	swtpm-create-tpmca.8 \
	swtpm-localca.options.8 \
	swtpm-localca.conf.8

if WITH_CUSE
man8_generated_MANS += \
	swtpm_cuse.8
endif

man8_static_MANS = \
	swtpm-localca.8

man8_MANS = \
	$(man8_generated_MANS) \
	$(man8_static_MANS)

%.8 : %.pod
	@pod2man -r "swtpm" \
		-c "" \
		-n $(basename $@) \
		--section=8 $< > $@

EXTRA_DIST = $(man8_static_MANS) $(man8_PODS)

CLEANFILES = $(man8_generated_MANS)
