/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * swtpm_backend_dir.c: storage backend specific functions for dir://
 *
 * Originally by: Stefan Berger, stefanb@linux.ibm.com
 * Refactored as module: Stefan Reiter, stefan@pimaker.at
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "swtpm.h"
#include "swtpm_utils.h"

struct dir_state {
    gchar* dir;
};

/* Parse a dir:// URI by removing the prefix if given. */
static void *parse_dir_state(const gchar* uri) {
    struct dir_state *ret;

    if (strncmp(uri, "dir://", 6) == 0) {
        uri += 6;
    }

    ret = g_malloc(sizeof(struct dir_state));
    ret->dir = g_strdup(uri);

    return (void*)ret;
}

/* Check user access in 'mode' to directory specified in backend state. */
static int check_access(void *state, int mode, const struct passwd *curr_user) {
    gchar *tpm_state_path = ((struct dir_state*)state)->dir;
    gchar *p;
    struct stat statbuf;
    char path[PATH_MAX];

    /* check lockfile */
    p = pathjoin(path, sizeof(path), tpm_state_path, ".lock", NULL);
    if (!p)
        return 1;
    if (stat(p, &statbuf) == 0 && access(p, R_OK|W_OK) != 0) {
        logerr(gl_LOGFILE, "User %s cannot read/write lockfile %s.\n",
               curr_user ? curr_user->pw_name : "<unknown>", p);
        return 1;
    }

    /* check access to state directory itself */
    return check_directory_access(tpm_state_path, mode, curr_user);
}

/* Delete swtpm's state file. Those are the files with suffixes
 * 'permall', 'volatilestate', and 'savestate'.
 */
static int delete_statefiles(void *state)
{
    gchar *tpm_state_path = ((struct dir_state*)state)->dir;
    GError *error = NULL;
    GDir *dir = g_dir_open(tpm_state_path, 0, &error);
    int ret = 1;

    if (dir == NULL) {
        logerr(gl_LOGFILE, "%s\n", error->message);
        g_error_free(error);
        return 1;
    }
    while (1) {
        const gchar *fn = g_dir_read_name(dir);

        if (fn == NULL) {
            if (errno != 0 && errno != ENOENT
#ifdef __FreeBSD__
                && errno != EINVAL
#endif
                ) {
                logerr(gl_LOGFILE, "Error getting next filename: %s\n", strerror(errno));
                break;
            } else {
                ret = 0;
                break;
            }
        }
        if (g_str_has_suffix(fn, "permall") ||
            g_str_has_suffix(fn, "volatilestate") ||
            g_str_has_suffix(fn, "savestate")) {
            g_autofree gchar *fullname = g_strjoin(G_DIR_SEPARATOR_S,
                                                   tpm_state_path, fn, NULL);
            if (unlink(fullname) != 0) {
                logerr(gl_LOGFILE, "Could not remove %s: %s\n", fn, strerror(errno));
                break;
            }
        }
    }

    g_dir_close(dir);

    return ret;
}

/* Free an instance of dir_state. */
static void free_dir_state(void *state) {
    if (state) {
        struct dir_state *dstate = (struct dir_state*)state;
        g_free(dstate->dir);
        g_free(dstate);
    }
}

struct swtpm_backend_ops swtpm_backend_dir = {
    .parse_backend = parse_dir_state,
    .check_access = check_access,
    .delete_state = delete_statefiles,
    .free_backend = free_dir_state,
};
