/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * swtpm_backend_file.c: storage backend specific functions for file://
 *
 * Author: Stefan Reiter, stefan@pimaker.at
 */

#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "compiler_dependencies.h"
#include "swtpm.h"
#include "swtpm_utils.h"

struct file_state {
    gchar* path;
    bool is_blockdev;
};

/* Parse a file:// URI by removing the prefix and checking if block device. */
static void *parse_file_state(const gchar* uri) {
    struct file_state *ret;
    struct stat statbuf;
    int stat_ret;
    bool noent = false;

    if (strncmp(uri, "file://", 7) == 0) {
        uri += 7;
    }

    stat_ret = stat(uri, &statbuf);
    if (stat_ret != 0) {
        noent = errno == ENOENT;
        if (!noent) {
            logerr(gl_LOGFILE, "Couldn't stat file %s: %s\n", uri, strerror(errno));
            return NULL;
        }
    }

    ret = g_malloc(sizeof(struct file_state));
    ret->path = g_strdup(uri);
    ret->is_blockdev = noent ? false : S_ISBLK(statbuf.st_mode);

    return (void*)ret;
}

/* Check user access in 'mode' to file/blockdev specified in backend state. */
static int check_access(void *state,
                        int mode SWTPM_ATTR_UNUSED,
                        const struct passwd *curr_user SWTPM_ATTR_UNUSED) {
    const gchar *path = ((struct file_state*)state)->path;
    int ret = access(path, R_OK|W_OK);
    return ret == 0 || errno == ENOENT ? 0 : 1;
}

/* Delete state from file: if regular file, unlink, if blockdev, zero header so
 * swtpm binary will treat it as a new instance. */
static int delete_state(void *state) {
    const struct file_state *fstate = (struct file_state*)state;
    int fd;

    if (fstate->is_blockdev) {
        char zerobuf[8] = {0}; /* swtpm header has 8 byte */
        fd = open(fstate->path, O_WRONLY);
        if (fd < 0) {
            logerr(gl_LOGFILE, "Couldn't open file for clearing %s: %s\n",
                   fstate->path, strerror(errno));
            return 1;
        }
        /* writing less bytes than requested is bad, but won't set errno */
        errno = 0;
        if (write(fd, zerobuf, sizeof(zerobuf)) < (long)sizeof(zerobuf)) {
            logerr(gl_LOGFILE, "Couldn't write file for clearing %s: %s\n",
                   fstate->path, strerror(errno));
            close(fd);
            return 1;
        }
        close(fd);
    } else {
        if (unlink(fstate->path)) {
            logerr(gl_LOGFILE, "Couldn't unlink file for clearing %s: %s\n",
                   fstate->path, strerror(errno));
            return 1;
        }
    }

    return 0;
}

/* Free an instance of file_state. */
static void free_file_state(void *state) {
    if (state) {
        struct file_state *fstate = (struct file_state*)state;
        g_free(fstate->path);
        g_free(fstate);
    }
}

struct swtpm_backend_ops swtpm_backend_file = {
    .parse_backend = parse_file_state,
    .check_access = check_access,
    .delete_state = delete_state,
    .free_backend = free_file_state,
};
