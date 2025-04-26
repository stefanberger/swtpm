/*
 * utils.h -- utilities
 *
 * (c) Copyright IBM Corporation 2015.
 *
 * Author: Stefan Berger <stefanb@us.ibm.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * Neither the names of the IBM Corporation nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _SWTPM_UTILS_H_
#define _SWTPM_UTILS_H_

#include "config.h"

#include <signal.h>
#include <stdbool.h>
#include <sys/uio.h>

#include <glib.h>

#include <libtpms/tpm_library.h>

#define ROUND_TO_NEXT_POWER_OF_2_32(a) \
    do { \
      a--; \
      a |= a >> 1; \
      a |= a >> 2; \
      a |= a >> 4; \
      a |= a >> 8; \
      a |= a >> 16; \
      a++; \
    } while(0);

typedef void (*sighandler_t)(int);

int install_sighandlers(int pipefd[2], sighandler_t handler);
void uninstall_sighandlers(void);
int change_process_owner(const char *owner);
int do_chroot(const char *path);

void tpmlib_debug_libtpms_parameters(TPMLIB_TPMVersion);

char *fd_to_filename(int fd);

ssize_t write_full(int fd, const void *buffer, size_t buflen);
ssize_t writev_full(int fd, const struct iovec *iov, int iovcnt);
ssize_t file_write(const char *filename, int flags, mode_t mode,
                   bool clear_umask, const void *buffer, size_t buflen);

ssize_t read_eintr(int fd, void *buffer, size_t buflen);

int json_get_submap_value(const char *json_input, const char *field_name,
                          const char *field_name2, char **value);
int json_get_map_key_value(const char *json_input,
                           const char *key, char **value);
int json_set_map_key_value(char **json_input,
                           const char *key, const char *value);
int json_get_array_entry_value(const char *json_input,
                               const char *field0_name,
                               const char *field1_name, const char *field1_value,
                               const char *field2_name, char **value);

ssize_t strv_strncmp(const gchar *const*str_array, const gchar *s, size_t n);

gboolean strv_contains_all(const gchar *const*haystack, const gchar *const*needles);

size_t strv_remove(gchar **array, const gchar *toremove, ssize_t len,
                   gboolean freethem);
typedef char *(*gencmpstr_t)(gchar *string, ssize_t *cmplen);
size_t strv_dedup(gchar **array, gencmpstr_t strtrafo, gboolean freethem);

gchar **strv_extend(gchar **array, const gchar *const*append);

#endif /* _SWTPM_UTILS_H_ */
