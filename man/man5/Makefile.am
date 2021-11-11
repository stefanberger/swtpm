#
# man/man5/Makefile.am
#
# For the license, see the COPYING file in the root directory.
#


man5_PODS = \
	swtpm_setup.conf.pod \
	swtpm-localca.options.pod \
	swtpm-localca.conf.pod

man5_MANS = \
	swtpm_setup.conf.5 \
	swtpm-localca.options.5 \
	swtpm-localca.conf.5

%.5 : %.pod
	@pod2man -r "swtpm" \
		-c "" \
		-n $(basename $@) \
		--section=5 $< > $@

EXTRA_DIST = $(man5_MANS) $(man5_PODS)
