#
# src/Makefile.am
#
# For the license, see the COPYING file in the root directory.
#

SUBDIRS = \
	utils \
	swtpm

if WITH_STORAGE_PLUGIN
SUBDIRS += swtpm_storage_plugin
endif

SUBDIRS += \
	swtpm_bios \
	swtpm_cert \
	swtpm_ioctl \
	swtpm_localca \
	swtpm_setup

if WITH_SELINUX
SUBDIRS += \
	selinux
endif

sysusersdir = $(prefix)/lib/sysusers.d
sysusers_DATA = swtpm-sysusers.conf

tmpfilesdir = $(prefix)/lib/tmpfiles.d
tmpfiles_DATA = swtpm-tmpfiles.conf

EXTRA_DIST = \
	swtpm-sysusers.conf \
	swtpm-tmpfiles.conf
