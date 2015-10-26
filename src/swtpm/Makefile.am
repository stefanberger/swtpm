#
# src/swtpm/Makefile.am
#
# For the license, see the COPYING file in the root directory.
#

noinst_HEADERS = \
	common.h \
	key.h \
	logging.h \
	main.h \
	options.h \
	pidfile.h \
	swtpm_aes.h \
	swtpm_debug.h \
	swtpm_io.h \
	swtpm_nvfile.h

lib_LTLIBRARIES = libswtpm_libtpms.la

libswtpm_libtpms_la_SOURCES = \
	common.c \
	key.c \
	logging.c \
	options.c \
	pidfile.c \
	swtpm_aes.c \
	swtpm_debug.c \
	swtpm_io.c \
	swtpm_nvfile.c

libswtpm_libtpms_la_CFLAGS = \
	$(HARDENING_CFLAGS)

if SWTPM_USE_FREEBL
libswtpm_libtpms_la_CFLAGS += \
	$(NSS_CFLAGS) \
	$(NSPR_CFLAGS)
endif

libswtpm_libtpms_la_LIBADD = \
	$(LIBTPMS_LIBS)

if SWTPM_USE_FREEBL
libswtpm_libtpms_la_LIBADD += \
	$(NSS_LIBS)
endif

bin_PROGRAMS = swtpm swtpm_cuse

swtpm_DEPENDENCIES = $(lib_LTLIBRARIES)

swtpm_SOURCES = \
		main.c \
		swtpm.c

swtpm_CFLAGS = \
	-I$(top_srcdir)/include/swtpm \
	$(HARDENING_CFLAGS)

if SWTPM_USE_FREEBL
swtpm_CFLAGS += \
	$(NSS_CFLAGS)
	$(NSPR_CFLAGS)
endif

swtpm_LDADD = \
	-L$(PWD)/.libs -lswtpm_libtpms \
	$(LIBTPMS_LIBS)

if SWTPM_USE_FREEBL
swtpm_LDADD += \
	$(NSS_LIBS)
endif

swtpm_cuse_DEPENDENCIES = $(lib_LTLIBRARIES)

swtpm_cuse_SOURCES = \
	cuse_tpm.c

swtpm_cuse_CFLAGS = \
	-I$(top_srcdir)/include/swtpm \
	$(GLIB_CFLAGS) \
	$(LIBFUSE_CFLAGS) \
	$(HARDENING_CFLAGS)

swtpm_cuse_LDADD = \
	-L$(PWD)/.libs -lswtpm_libtpms \
	$(LIBFUSE_LIBS) \
	$(GLIB_LIBS) \
	$(GTHREAD_LIBS) \
	$(LIBTPMS_LIBS)

AM_CPPFLAGS   = 
LDADD         = -ltpms
