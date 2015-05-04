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
	swtpm_setup.pod \
	swtpm_setup.conf.pod
	swtpm-localca.pod \
	swtpm-localca.options.pod \
	swtpm-localca.conf.pod

man8_MANS = \
	swtpm.8 \
	swtpm_bios.8 \
	swtpm_cert.8 \
	swtpm_cuse.8 \
	swtpm_ioctl.8 \
	swtpm_setup.8 \
	swtpm_setup.conf.8 \
	swtpm_setup.sh.8 \
	swtpm-localca.8 \
	swtpm-localca.options.8 \
	swtpm-localca.conf.8

%.8 : %.pod
	@pod2man -r "swtpm" \
		-c "" \
		-n $(basename $@) \
		--section=8 $< > $@

EXTRA_DIST = $(man8_MANS) $(man8_PODS)
