#
# man/man8/Makefile.am
#
# For the license, see the COPYING file in the root directory.
#


man8_PODS = \
	swtpm.pod \
	swtpm_cuse.pod

man8_MANS = \
	swtpm.8 \
	swtpm_cuse.8

%.8 : %.pod
	@pod2man -r "swtpm" \
		-c "" \
		-n $(basename $@) \
		--section=8 $< > $@

EXTRA_DIST = $(man8_MANS) $(man8_PODS)
