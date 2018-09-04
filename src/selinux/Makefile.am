#
# src/Makefile.am
#
# For the license, see the COPYING file in the root directory.
#

policiesconfdir = $(datadir)/@PACKAGE@

POLICIES = \
	swtpm.pp \
	swtpm_svirt.pp \
	swtpmcuse.pp

policiesconf_DATA = \
	$(POLICIES)

swtpm.pp_FILES = \
	$(addprefix $(top_srcdir)/src/selinux/,\
	  swtpm.fc swtpm.if swtpm.te)

swtpm_svirt.pp_FILES = \
	$(addprefix $(top_srcdir)/src/selinux/,\
	  swtpm_svirt.te)

swtpmcuse.pp_FILES = \
	$(addprefix $(top_srcdir)/src/selinux/,\
	  swtpmcuse.te swtpmcuse.fc swtpmcuse.if)

all: $(POLICIES)

clean:
	$(RM) -r tmp $(POLICIES)

.SECONDEXPANSION:
%.pp : $$($$@_FILES)
	echo "Creating $@ from $^"
	$(RM) -r $(top_srcdir)/src/selinux/tmp/
	cp $^ ./ 2>/dev/null || true
	+make -f /usr/share/selinux/devel/Makefile $@ || make -f /usr/share/selinux/devel/Makefile $@
	$(RM) -r ./tmp/
	if test $(shell pwd) != $(abspath $(top_srcdir)/src/selinux); then \
		$(RM) *.te *.fc *.if; \
	fi

.NOTPARALLEL: %.te

EXTRA_DIST = \
	swtpm.fc \
	swtpm.if \
	swtpm.te \
	swtpm_svirt.te \
	swtpmcuse.fc \
	swtpmcuse.if \
	swtpmcuse.te

CLEANFILES = *.pp