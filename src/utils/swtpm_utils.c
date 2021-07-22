/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * swtpm_setup_utils.c: Utility functions for swtpm_setup et al.
 *
 * Author: Stefan Berger, stefanb@linux.ibm.com
 *
 * Copyright (c) IBM Corporation, 2021
 */

#include "config.h"

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <glib.h>

#include "swtpm_utils.h"

void append_to_file(const char *pathname, const char *str)
{
    size_t n, len;
    int fd = open(pathname, O_WRONLY|O_APPEND|O_CREAT|O_NOFOLLOW, S_IRUSR|S_IWUSR|S_IRGRP);

    if (fd >= 0) {
        len = strlen(str);
        n = write(fd, str, len);
        if (n != len) {
            fprintf(stderr, "Error writing to %s: %s\n", pathname, strerror(errno));
        }
        close(fd);
    } else {
        fprintf(stderr, "Error opening file %s: %s\n", pathname, strerror(errno));
    }
}

static void alog(FILE *stream, const char *logfile, const char *fmt, va_list ap)
{
    char *str = NULL;
    int n;

    n = vasprintf(&str, fmt, ap);
    if (n < 0)
        return;

    if (logfile == NULL)
        fprintf(stream, "%s", str);
    else
        append_to_file(logfile, str);

    free(str);
}

void logit(const char *logfile, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    alog(stdout, logfile, fmt, ap);
    va_end(ap);
}

void logerr(const char *logfile, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    alog(stderr, logfile, fmt, ap);
    va_end(ap);
}

/* Join paths of up to 3 parts into a pre-allocated buffer. The last part is optional */
char *pathjoin(char *buffer, size_t bufferlen, const char *p1, const char *p2, const char *p3)
{
    char *res = NULL;
    int n = snprintf(buffer, bufferlen, "%s%s%s%s%s",
                     p1,
                     G_DIR_SEPARATOR_S,
                     p2,
                     p3 ? G_DIR_SEPARATOR_S : "",
                     p3 ? p3 : "");
    if (n < 0) {
        logerr(gl_LOGFILE, "Error: Could not print into buffer.\n");
    } else if ((size_t)n >= bufferlen) {
        logerr(gl_LOGFILE, "Error: Buffer for path is too small.\n");
    } else {
        res = buffer;
    }
    return res;
}

/* Concatenate two NULL-terminated arrays creating one new one;
 * This function does not duplicate the memory for the elements.
 * Either one of the arrays may be NULL. The first array can be freed.
 */
gchar **concat_arrays(char **arr1, char **arr2, gboolean free_arr1)
{
    size_t n = 0;
    gchar **res;
    size_t i;

    for (i = 0; arr1 != NULL && arr1[i]; i++)
        n++;
    for (i = 0; arr2 != NULL && arr2[i]; i++)
        n++;

    res = g_malloc0(sizeof(char *) * (n + 1));
    for (i = 0, n = 0; arr1 != NULL && arr1[i]; i++)
        res[n++] = arr1[i];
    for (i = 0; arr2 != NULL && arr2[i]; i++)
        res[n++] = arr2[i];

    if (free_arr1 && arr1)
        g_free(arr1);

    return res;
}

/* Concatenate buffers into a given buffer of a given length 'buflen' */
ssize_t concat(unsigned char *buffer, size_t buflen, ...)
{
    va_list ap;
    ssize_t offset = 0;

    va_start(ap, buflen);

    while (1) {
        size_t len;
        unsigned char *i = va_arg(ap, unsigned char *);

        if (i == NULL)
            break;

        len = va_arg(ap, size_t);
        if (offset + len > buflen) {
            offset = -(offset + len);
            break;
        }

        memcpy(&buffer[offset], i, len);
        offset += len;
   }
   va_end(ap);

   return offset;
}

/* Concatenate buffers and allocate a new buffer and return its size */
ssize_t memconcat(unsigned char **buffer, ...)
{
    va_list ap;
    ssize_t offset = 0;
    size_t allocated = 128;
    unsigned char *p;

    *buffer = g_malloc(allocated);
    p = *buffer;

    va_start(ap, buffer);

    while (1) {
        size_t len;
        unsigned char *i = va_arg(ap, unsigned char *);

        if (i == NULL)
            break;

        len = va_arg(ap, size_t);
        if (offset + len > allocated) {
            allocated += offset + len;
            *buffer = g_realloc(*buffer, allocated);
            p = *buffer;
        }

        memcpy(&p[offset], i, len);
        offset += len;
   }
   va_end(ap);

   return offset;
}

/* Print an input buffer as hex number */
gchar *print_as_hex(unsigned char *input, size_t input_len)
{
    gchar *out = g_malloc(input_len * 2 + 1);
    size_t i;

    for (i = 0; i < input_len; i++)
        g_snprintf(&out[i * 2], 3, "%02x", input[i]);

    return out;
}

/* Split a command line and remove all trailing and leading spaces from all entries and remove
 * 0-length strings entirely.
 */
gchar **split_cmdline(const gchar *cmdline) {
    gchar **result = g_strsplit(cmdline, " ", -1);
    size_t i, j;

    for (i = 0, j = 0; result[i] != NULL; i++) {
        gchar *chomped = g_strchomp(result[i]);

        if (strlen(chomped) == 0) {
            g_free(chomped);
            result[i] = NULL;
        } else {
            result[i] = NULL;
            result[j++] = chomped;
        }
    }
    return result;
}

/* resolve environment variables in a string */
gchar *resolve_string(const gchar *inp) {
    char *pe;
    gchar *result = NULL;
    gchar *new_res, *tmp;
    size_t sidx = 0;
    const gchar *envval;

    while (1) {
        gchar *ps = g_strstr_len(&inp[sidx], -1, "${");
        if (ps == NULL) {
            if (sidx == 0) {
                g_free(result); /* coverity */
                return g_strdup(inp);
            }
            new_res = g_strconcat(result ? result : "", &inp[sidx], NULL);
            g_free(result);
            return new_res;
        }

        tmp = g_strndup(&inp[sidx], ps - &inp[sidx]);
        new_res = g_strconcat(result ? result : "", tmp, NULL);
        g_free(tmp);
        g_free(result);
        result = new_res;

        pe = g_strstr_len(&ps[2], -1, "}");
        if (pe == NULL) {
            new_res = g_strconcat(result ? result : "", ps, NULL);
            g_free(result);
            return new_res;
        }

        /* name of environment variable */
        tmp = g_strndup(&ps[2], pe - &ps[2]);

        envval = g_getenv(tmp);
        new_res = g_strconcat(result ? result : "",
                              envval ? envval : "",
                              NULL);
        g_free(tmp);
        g_free(result);
        result = new_res;
        sidx = &pe[1] - inp;
    }
}

/* Read an entire file */
int read_file(const gchar *filename, gchar **buffer, gsize *buffer_len)
{
    GError *error = NULL;

    if (!g_file_get_contents(filename, buffer, buffer_len, &error)) {
        logerr(gl_LOGFILE, "%s\n", error->message);
        g_error_free(error);
        return 1;
    }
    return 0;
}

/* Read a file and convert its lines into a NULL-termianted array */
int read_file_lines(const char *filename, gchar ***config_file_lines)
{
    g_autofree gchar *buffer = NULL;
    gsize buffer_len;
    size_t start = 0;
    gchar **array;
    gsize array_len = 1; /* null-terminated array */

    if (read_file(filename, &buffer, &buffer_len) != 0)
        return 1;

    array = g_malloc0(sizeof(char *) * array_len);

    while (start < buffer_len) {
        size_t off = start;

        /* search for end-of-string or next newline */
        while (off < buffer_len && buffer[off] != '\n')
            off++;

        if (off > start) {
            /* non-empty line */
            array = g_realloc(array, sizeof(char *) * (array_len + 1));
            array[array_len - 1] = g_strndup(&buffer[start], off - start);
            array_len++;
        }
        start = off + 1;
    }
    array[array_len - 1] = NULL;
    *config_file_lines = array;

    return 0;
}

static ssize_t write_to_fd(int fd, const unsigned char *data, size_t data_len)
{
    ssize_t n;

    n = write(fd, data, data_len);
    if (n < 0) {
        logerr(gl_LOGFILE, "Could not write to file: %s\n", strerror(errno));
    } else if ((size_t)n != data_len) {
        logerr(gl_LOGFILE, "Could not write all bytes to the file.\n");
        n = -1;
    }
    return n;
}

/* Write to a file with the given name */
int write_file(const gchar *filename, const unsigned char *data, size_t data_len)
{
    ssize_t n;
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC,
                  S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH );
    if (fd < 0) {
        logerr(gl_LOGFILE, "Could not open file %s for writing: %s\n",
               filename, strerror(errno));
        return 1;
    }

    n = write_to_fd(fd, data, data_len);
    close(fd);
    if (n < 0)
        return 1;

    return 0;
}

int write_to_tempfile(gchar **filename, const unsigned char *data, size_t data_len)
{
    GError *error = NULL;
    int fd = g_file_open_tmp("XXXXXX", filename, &error);
    ssize_t n;

    if (error) {
        logerr(gl_LOGFILE, "Could not create temporary file: %s\n", error->message);
        g_error_free(error);
        return 1;
    }

    n = write_to_fd(fd, data, data_len);
    if (n < 0)
        goto error;

    n = lseek(fd, 0, SEEK_SET);
    if (n < 0) {
        logerr(gl_LOGFILE, "Could not seek(0) on file '%s': %s\n", filename, strerror(errno));
        goto error;
    }
    return fd;

error:
    close(fd);
    return -1;
}

/* replace occurences of 'torep' with 'rep' in a string 'in' */
gchar *str_replace(const char *in, const char *torep, const char *rep)
{
    char *res;
    const char *s, *b;
    size_t torep_len;
    size_t rep_len;
    size_t ctr = 0;
    size_t off = 0;

    if (in == NULL || torep == NULL || rep == NULL)
        return NULL;

    torep_len = strlen(torep);
    if (torep_len == 0)
        return NULL;

    rep_len = strlen(rep);

    s = in;
    while ((s = strstr(s, torep)) != NULL) {
        s += torep_len;
        ctr++;
    }

    res = g_malloc(strlen(in) - ctr * torep_len + ctr * rep_len + 1);

    b = s = in;
    while ((s = strstr(s, torep)) != NULL) {
        strncpy(&res[off], b, s - b);
        off += (s - b);
        s += torep_len;
        b = s;
        strcpy(&res[off], rep);
        off += rep_len;
    }
    strcpy(&res[off], b);

    return res;
}

int check_directory_access(const gchar *directory, int mode, const struct passwd *curr_user)
{
    struct stat statbuf;

    if (stat(directory, &statbuf) != 0 || (statbuf.st_mode & S_IFMT) != S_IFDIR) {
        logerr(gl_LOGFILE,
               "User %s cannot access directory %s. Make sure it exists and is a directory.\n",
               curr_user ? curr_user->pw_name : "<unknown>", directory);
        return 1;
    }
    if ((mode & R_OK) && access(directory, R_OK) != 0) {
        logerr(gl_LOGFILE, "Need read rights on directory %s for user %s.\n",
               directory, curr_user ? curr_user->pw_name : "<unknown>");
        return 1;
    }
    if ((mode & W_OK) && access(directory, W_OK) != 0) {
        logerr(gl_LOGFILE, "Need write rights on directory %s for user %s.\n",
               directory, curr_user ? curr_user->pw_name : "<unknown>");
        return 1;
    }
    return 0;
}
