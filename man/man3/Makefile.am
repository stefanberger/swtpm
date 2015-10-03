#
# man/man3/Makefile.am
#
# For the license, see the COPYING file in the root directory.
#


man3_PODS = \
	swtpm_ioctls.pod

man3_MANS = \
	swtpm_ioctls.3

%.3 : %.pod
	@pod2man -r "swtpm" \
		-c "" \
		-n $(basename $@) \
		--section=3 $< > $@

EXTRA_DIST = $(man3_MANS) $(man3_PODS)
