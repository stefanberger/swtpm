#
# samples/Makefile.am
#
# For the license, see the LICENSE file in the root directory.
#

samplesconfdir = $(datadir)/@PACKAGE@
samplessysconfdir = $(sysconfdir)

samplesconf_SCRIPTS = \
	swtpm-create-tpmca \
	swtpm-create-user-config-files \
	swtpm-localca

samplessysconf_DATA = \
	swtpm-localca.conf \
	swtpm-localca.options

PY_SWTPM_LOCALCA_FILES = $(wildcard py_swtpm_localca/*.py)

PY_PACKAGE_NAME=swtpm_localca
PY_PACKAGE_NV=$(PY_PACKAGE_NAME)-$(SWTPM_VER_MAJOR).$(SWTPM_VER_MINOR).$(SWTPM_VER_MICRO)
PY_PACKAGE=dist/$(PY_PACKAGE_NV).tar.gz

# for out-of-tree builds we need to copy setup.py
$(PY_PACKAGE): $(PY_SWTPM_LOCALCA_FILES)
	@$(CP) $(srcdir)/setup.py ./ &>/dev/null || true
	./setup.py sdist

all-local: $(PY_PACKAGE)

python-install: $(PY_PACKAGE)
	echo "Installing python to DESTDIR '/$(DESTDIR)'"
	./setup.py install --prefix=$(prefix) --root "/$(DESTDIR)" --install-layout deb 2>/dev/null || \
		./setup.py install --prefix=$(prefix) --root "/$(DESTDIR)" 2>/dev/null

python-uninstall:
	echo "Local pip3 uninstall"
	$(PIP3) uninstall -y $(PY_PACKAGE_NAME)

if PYTHON_INSTALLATION
install-exec-local: $(PY_PACKAGE)
	@if ! test $(findstring /usr, "$(DESTDIR)$(bindir)"); then \
		echo "Warning: Not installing python package to $(DESTDIR)$(bindir)"; \
	else \
		$(MAKE) python-install; \
	fi

uninstall-local:
	@if ! test $(findstring /usr, "$(DESTDIR)$(bindir)"); then \
		echo "Cleanup for distcheck build not implemented" ; \
	else \
		$(MAKE) python-uninstall; \
	fi
endif


install-data-local:
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/swtpm-localca
	if test -z $(DESTDIR); then \
		chown -R @TSS_USER@:root $(DESTDIR)$(localstatedir)/lib/swtpm-localca || true; \
		chmod 0750 $(DESTDIR)$(localstatedir)/lib/swtpm-localca || true; \
	fi

# for out-of-tree builds we need to clean up
clean-local:
	if test "$(top_srcdir)" != "$(top_builddir)"; then \
		rm -f setup.py; \
	fi
	rm -rf py_swtpm_localca/__pycache__/
	rm -rf swtpm_localca.egg-info/
	rm -rf dist

EXTRA_DIST= \
	setup.py \
	swtpm-create-tpmca \
	swtpm-create-user-config-files \
	swtpm-localca \
	swtpm-localca.conf \
	swtpm-localca.options
