#
# src/Makefile.am
#
# For the license, see the COPYING file in the root directory.
#

policiesconfdir = $(datadir)/@PACKAGE@

POLICIES = \
	swtpmcuse.pp \
	swtpmcuse_svirt.pp

policiesconf_DATA = \
	$(POLICIES)

all: $(POLICIES)

clean:
	$(RM) -r tmp $(POLICIES)

%.pp : %.te
	bash $(PWD)/adapt_policy.sh
	$(RM) -r tmp
	make -f /usr/share/selinux/devel/Makefile $@

.NOTPARALLEL: %.te

EXTRA_DIST = \
	adapt_policy.sh \
	swtpmcuse.fc \
	swtpmcuse.if \
	swtpmcuse.te \
	swtpmcuse_svirt.te
