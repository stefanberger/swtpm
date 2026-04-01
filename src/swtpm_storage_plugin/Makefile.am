#
# src/swtpm_storage_plugin/Makefile.am
#
# For the license, see the COPYING file in the root directory.
#

MY_CFLAGS = @MY_CFLAGS@
MY_LDFLAGS = @MY_LDFLAGS@

if WITH_STORAGE_PLUGIN
storageplugindir = $(libdir)/$(PACKAGE)/storage_plugins
storageplugin_LTLIBRARIES = swtpm_storage_plugin_dir.la swtpm_storage_plugin_file.la

STORAGE_PLUGIN_CFLAGS = \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/include/swtpm \
	-I$(top_srcdir)/src/swtpm \
	-I$(top_srcdir)/src/swtpm_setup \
	-I$(top_srcdir)/src/swtpm_storage_plugin \
	$(MY_CFLAGS) \
	$(CFLAGS) \
	$(HARDENING_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(JSON_GLIB_CFLAGS)

STORAGE_PLUGIN_LDFLAGS = \
	-module \
	-avoid-version \
	-rpath $(storageplugindir) \
	$(MY_LDFLAGS) \
	$(HARDENING_LDFLAGS)

swtpm_storage_plugin_dir_la_SOURCES = \
	swtpm_storage_plugin_dir.c
swtpm_storage_plugin_dir_la_CFLAGS = $(STORAGE_PLUGIN_CFLAGS)
swtpm_storage_plugin_dir_la_LDFLAGS = $(STORAGE_PLUGIN_LDFLAGS)

swtpm_storage_plugin_file_la_SOURCES = \
	swtpm_storage_plugin_file.c
swtpm_storage_plugin_file_la_CFLAGS = $(STORAGE_PLUGIN_CFLAGS)
swtpm_storage_plugin_file_la_LDFLAGS = $(STORAGE_PLUGIN_LDFLAGS)

noinst_HEADERS = \
	swtpm_storage_plugin.h

endif

CLEANFILES = *.gcno *.gcda *.gcov
