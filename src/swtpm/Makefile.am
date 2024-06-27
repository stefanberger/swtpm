#
# src/swtpm/Makefile.am
#
# For the license, see the COPYING file in the root directory.
#

MY_CFLAGS = @MY_CFLAGS@
MY_LDFLAGS = @MY_LDFLAGS@

noinst_HEADERS = \
	capabilities.h \
	common.h \
	ctrlchannel.h \
	fips.h \
	key.h \
	locality.h \
	logging.h \
	main.h \
	mainloop.h \
	options.h \
	daemonize.h \
	pidfile.h \
	seccomp_profile.h \
	server.h \
	swtpm_aes.h \
	swtpm_debug.h \
	swtpm_io.h \
	swtpm_nvstore.h \
	swtpm_nvstore_linear.h \
	threadpool.h \
	tlv.h \
	tpmlib.h \
	tpmstate.h \
	utils.h \
	vtpm_proxy.h

privlibdir = $(libdir)/@PACKAGE@
privlib_LTLIBRARIES = libswtpm_libtpms.la

libswtpm_libtpms_la_SOURCES = \
	capabilities.c \
	common.c \
	ctrlchannel.c \
	fips.c \
	key.c \
	logging.c \
	mainloop.c \
	options.c \
	pidfile.c \
	seccomp_profile.c \
	server.c \
	swtpm_aes.c \
	swtpm_debug.c \
	swtpm_io.c \
	swtpm_nvstore.c \
	swtpm_nvstore_dir.c \
	swtpm_nvstore_linear.c \
	swtpm_nvstore_linear_file.c \
	tlv.c \
	tpmlib.c \
	tpmstate.c \
	utils.c

if WITH_CUSE
libswtpm_libtpms_la_SOURCES += \
	threadpool.c
endif

libswtpm_libtpms_la_CFLAGS = \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/include/swtpm \
	-I$(top_srcdir)/src/utils \
	$(MY_CFLAGS) \
	$(CFLAGS) \
	$(HARDENING_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(JSON_GLIB_CFLAGS) \
	$(LIBSECCOMP_CFLAGS)

libswtpm_libtpms_la_LDFLAGS = \
	$(MY_LDFLAGS) \
	$(HARDENING_LDFLAGS)

libswtpm_libtpms_la_LIBADD = \
	$(LIBTPMS_LIBS) \
	$(GLIB_LIBS) \
	$(JSON_GLIB_LIBS) \
	$(LIBRT_LIBS) \
	$(LIBSECCOMP_LIBS) \
	$(LIBCRYPTO_LIBS)

bin_PROGRAMS = swtpm
if WITH_CUSE
bin_PROGRAMS += swtpm_cuse
endif

swtpm_DEPENDENCIES = $(privlib_LTLIBRARIES)

swtpm_SOURCES = \
		main.c \
		daemonize.c \
		swtpm.c \
		swtpm_chardev.c
if WITH_CUSE
swtpm_SOURCES += cuse_tpm.c
endif

swtpm_CFLAGS = \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/include/swtpm \
	-I$(top_srcdir)/src/utils \
	$(MY_CFLAGS) \
	$(HARDENING_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(LIBFUSE_CFLAGS) \
	-DHAVE_SWTPM_CUSE_MAIN

swtpm_LDFLAGS = \
	$(MY_LDFLAGS) \
	$(HARDENING_LDFLAGS)

swtpm_LDADD = \
	libswtpm_libtpms.la \
	$(LIBFUSE_LIBS) \
	$(GLIB_LIBS) \
	$(GTHREAD_LIBS) \
	$(LIBTPMS_LIBS)

swtpm_cuse_DEPENDENCIES = $(privlib_LTLIBRARIES)

swtpm_cuse_SOURCES = \
	cuse_tpm.c

swtpm_cuse_CFLAGS = \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/include/swtpm \
	-I$(top_srcdir)/src/utils \
	$(MY_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(LIBFUSE_CFLAGS) \
	$(HARDENING_CFLAGS)

swtpm_cuse_LDFLAGS = \
	$(MY_LDFLAGS) \
	$(HARDENING_LDFLAGS)

swtpm_cuse_LDADD = \
	libswtpm_libtpms.la \
	$(LIBFUSE_LIBS) \
	$(GLIB_LIBS) \
	$(GTHREAD_LIBS) \
	$(LIBTPMS_LIBS)

AM_CPPFLAGS   = 
LDADD         = -ltpms

CLEANFILES = *.gcno *.gcda *.gcov
