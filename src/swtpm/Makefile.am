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
	swtpm_aes.c \
	swtpm_debug.c \
	swtpm_io.c \
	swtpm_nvfile.c

bin_PROGRAMS = swtpm swtpm_cuse

swtpm_DEPENDENCIES = $(lib_LTLIBRARIES)

swtpm_SOURCES = \
		main.c \
		swtpm.c

swtpm_CFLAGS = \
	-I$(top_srcdir)/include/swtpm

swtpm_LDADD = -L$(PWD)/.libs -lswtpm_libtpms

swtpm_cuse_DEPENDENCIES = $(lib_LTLIBRARIES)

swtpm_cuse_SOURCES = \
	cuse_tpm.c

swtpm_cuse_CFLAGS = \
	-I$(top_srcdir)/include/swtpm \
	$(shell pkg-config --cflags fuse)

swtpm_cuse_LDFLAGS = \
	$(shell pkg-config --libs-only-l fuse)

swtpm_cuse_LDADD = -L$(PWD)/.libs -lswtpm_libtpms

AM_CPPFLAGS   = 
LDADD         = -ltpms
