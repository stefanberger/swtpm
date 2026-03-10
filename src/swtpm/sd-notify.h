/* SPDX-License-Identifier: BSD-3-Clause */

/*
 * sd-notify.h -- Minimal sd_notify() implementation without libsystemd
 */

#ifndef SWTPM_SD_NOTIFY_H
#define SWTPM_SD_NOTIFY_H

int sd_notify(int unset_environment, const char *state);

#endif /* SWTPM_SD_NOTIFY_H */
