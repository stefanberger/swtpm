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

/*
 * Wrapper for g_spawn_sync taking const gchar ** argv / envp that
 * internal glib function g_spawn_sync_impl & fork_exec will also use like
 * this on posix.
 */
static inline gboolean spawn_sync(const gchar           *working_directory,
                                  const gchar          **argv,
                                  const gchar          **envp,
                                  GSpawnFlags            flags,
                                  GSpawnChildSetupFunc   child_setup,
                                  gpointer               user_data,
                                  gchar                **standard_output,
                                  gchar                **standard_error,
                                  gint                  *wait_status,
                                  GError               **error)
{
    g_auto(GStrv) _argv = g_strdupv((gchar **)argv);
    g_auto(GStrv) _envp = g_strdupv((gchar **)envp);

    return g_spawn_sync(working_directory, _argv, _envp, flags, child_setup,
                        user_data, standard_output, standard_error, wait_status,
                        error);
}

/* Wrapper g_spawn_async that take const gchar ** for argv and envp. */
static inline gboolean spawn_async(const gchar          *working_directory,
                                   const gchar         **argv,
                                   const gchar         **envp,
                                   GSpawnFlags           flags,
                                   GSpawnChildSetupFunc  child_setup,
                                   gpointer              user_data,
                                   GPid                 *child_pid,
                                   GError              **error)
{
    g_auto(GStrv) _argv = g_strdupv((gchar **)argv);
    g_auto(GStrv) _envp = g_strdupv((gchar **)envp);

    return g_spawn_async_with_pipes(
                working_directory, _argv, _envp, flags, child_setup, user_data,
                child_pid, NULL, NULL, NULL, error);
}

#endif /* SWTPM_UTILS_H */
