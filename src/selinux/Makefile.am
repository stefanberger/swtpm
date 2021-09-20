#
# src/Makefile.am
#
# For the license, see the COPYING file in the root directory.
#

policiesconfdir = $(datadir)/selinux/packages

POLICIES = \
	swtpm.pp \
	swtpm_svirt.pp

if WITH_CUSE
POLICIES += \
	swtpmcuse.pp
endif

POLICIES_BZ2 = \
	$(addsuffix .bz2,$(POLICIES))

policiesconf_DATA = \
	$(POLICIES)

swtpm.pp_FILES = \
	$(addprefix $(top_srcdir)/src/selinux/,\
	  swtpm.fc swtpm.if swtpm.te)

swtpm_svirt.pp_FILES = \
	$(addprefix $(top_srcdir)/src/selinux/,\
	  swtpm_svirt.te swtpm.fc swtpm.if swtpm.te)

if WITH_CUSE
swtpmcuse.pp_FILES = \
	$(addprefix $(top_srcdir)/src/selinux/,\
	  swtpmcuse.te swtpmcuse.fc swtpmcuse.if)
endif

all: $(POLICIES_BZ2)

clean:
	$(RM) -r tmp $(POLICIES) $(POLICIES_BZ2)

PRIORITY ?= 400
selinux-install: $(POLICIES_BZ2)
	@if test $(shell id -u) != 0; then \
		echo "You have to be root for this operation"; exit 1; \
	fi
	semodule --priority $(PRIORITY) --install $(POLICIES_BZ2)
	restorecon -i "$(prefix)/bin/swtpm"
if WITH_CUSE
	restorecon -i "$(prefix)/bin/swtpm_cuse"
endif

selinux-uninstall:
	@if test $(shell id -u) != 0; then \
		echo "You have to be root for this operation"; exit 1; \
	fi
	semodule --priority $(PRIORITY) --remove $(patsubst %.pp.bz2,%,$(POLICIES_BZ2))

.PHONY: selinux-install selinux-uninstall

%.pp.bz2: %.pp
	@echo Compressing $^ -\> $@
	bzip2 -k -f -9 $^

.SECONDEXPANSION:
.NOTPARALLEL:
%.pp : $$($$@_FILES)
	echo "Creating $@ from $^"
	$(RM) -r $(top_srcdir)/src/selinux/tmp/
	cp $^ ./ 2>/dev/null || true
	make -f /usr/share/selinux/devel/Makefile $@
	$(RM) -r ./tmp/
	if test $(abspath $(shell pwd)) != $(abspath $(top_srcdir)/src/selinux); then \
		$(RM) *.te *.fc *.if; \
	fi

EXTRA_DIST = \
	swtpm.fc \
	swtpm.if \
	swtpm.te \
	swtpm_svirt.te \
	swtpmcuse.fc \
	swtpmcuse.if \
	swtpmcuse.te

CLEANFILES = *.pp *.pp.bz2
