/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * utils.h: Header file for utils.c
 *
 * Author: Stefan Berger, stefanb@linux.ibm.com
 *
 * Copyright (c) IBM Corporation, 2021
 */

#ifndef SWTPM_UTILS_H
#define SWTPM_UTILS_H

#include <pwd.h>

#include <glib.h>

#define min(X,Y) ((X) < (Y) ? (X) : (Y))
#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

#define SWTPM_CLOSE(FD)	\
    if ((FD) >= 0) {	\
        close((FD));	\
        (FD) = -1;	\
    }

#define SWTPM_G_FREE(var)	\
    do {		\
        g_free(var);	\
        var = NULL;	\
    } while(0)

extern gchar *gl_LOGFILE;

void append_to_file(const char *pathname, const char *str);
void logit(const char *logfile, const char *fmt, ...);
void logerr(const char *logfile, const char *fmt, ...);

char *pathjoin(char *buffer, size_t bufferlen, const char *p1, const char *p2, const char *p3);

gchar **concat_arrays(char **arr1, char **arr2, gboolean free_arr1);
ssize_t concat(unsigned char *buf, size_t buflen, ...);
ssize_t memconcat(unsigned char **buffer, ...);

gchar *resolve_string(const gchar *inp);
gchar *print_as_hex(const unsigned char *input, size_t input_len);
gchar **split_cmdline(const gchar *cmdline);

int read_file(const gchar *filename, gchar **buffer, gsize *buffer_len);
int read_file_lines(const char *filename, gchar ***config_file_lines);

int write_file(const gchar *filename, const unsigned char *data, size_t data_len);
int write_to_tempfile(gchar **filename, const unsigned char *data, size_t data_len);

gchar *str_replace(const char *in, const char *torep, const char *rep);

int check_directory_access(const gchar *directory, int mode, const struct passwd *curr_user);

int json_get_map_value(const char *json_input, const char *field_name,
                       gchar **value);

int strv_strcmp(gchar *const*str_array, const gchar *s);

#endif /* SWTPM_UTILS_H */
