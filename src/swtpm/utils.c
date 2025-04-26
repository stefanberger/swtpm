/*
 * utils.s -- utilities
 *
 * (c) Copyright IBM Corporation 2014, 2015, 2019.
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

#include "config.h"

#include <grp.h>
#include <pwd.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#if defined __APPLE__
#include <fcntl.h>
#include <sys/param.h>
#endif

#include <json-glib/json-glib.h>

#include <openssl/rand.h>

#include "utils.h"
#include "logging.h"
#include "tpmlib.h"
#include "swtpm_debug.h"

void uninstall_sighandlers()
{
    if (signal(SIGTERM, SIG_DFL) == SIG_ERR)
        logprintf(STDERR_FILENO, "Could not uninstall signal handler for SIGTERM.\n");

    if (signal(SIGPIPE, SIG_DFL) == SIG_ERR)
        logprintf(STDERR_FILENO, "Could not uninstall signal handler for SIGPIPE.\n");
}

int install_sighandlers(int pipefd[2], sighandler_t handler)
{
    if (pipe(pipefd) < 0) {
        logprintf(STDERR_FILENO, "Error: Could not open pipe.\n");
        goto err_exit;
    }

    if (signal(SIGTERM, handler) == SIG_ERR) {
        logprintf(STDERR_FILENO, "Could not install signal handler for SIGTERM.\n");
        goto err_close_pipe;
    }

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        logprintf(STDERR_FILENO, "Could not install signal handler for SIGPIPE.\n");
        goto err_close_pipe;
    }

    return 0;

err_close_pipe:
    close(pipefd[0]);
    pipefd[0] = -1;
    close(pipefd[1]);
    pipefd[1] = -1;

err_exit:
    return -1;
}

int
change_process_owner(const char *user)
{
    struct passwd *passwd;
    long int uid, gid;
    char *endptr = NULL;

    uid = strtoul(user, &endptr, 10);
    if (*endptr != '\0') {
        /* a string */
        passwd = getpwnam(user);
        if (!passwd) {
            logprintf(STDERR_FILENO,
                      "Error: User '%s' does not exist.\n",
                      user);
            return -14;
        }

        if (initgroups(passwd->pw_name, passwd->pw_gid) < 0) {
            logprintf(STDERR_FILENO,
                      "Error: initgroups(%s, %d) failed.\n",
                      passwd->pw_name, passwd->pw_gid);
           return -10;
        }
        gid = passwd->pw_gid;
        uid = passwd->pw_uid;
    } else {
        /* an integer */
        if ((unsigned long int)uid > UINT_MAX) {
            logprintf(STDERR_FILENO,
                      "Error: uid %s outside valid range.\n",
                      user);
            return -13;
        }
        gid = uid;
    }

    if (setgid(gid) < 0) {
        logprintf(STDERR_FILENO,
                  "Error: setgid(%d) failed.\n",
                  gid);
        return -11;
    }
    if (setuid(uid) < 0) {
        logprintf(STDERR_FILENO,
                  "Error: setuid(%d) failed.\n",
                  uid);
        return -12;
    }
    return 0;
}

int
do_chroot(const char *path)
{
    if (chroot(path) < 0) {
        logprintf(STDERR_FILENO, "chroot failed: %s\n",
                  strerror(errno));
        return -1;
    }

    if (chdir("/") < 0) {
        logprintf(STDERR_FILENO, "chdir failed: %s\n",
                  strerror(errno));
        return -1;
    }

    if (!RAND_status()) {
        logprintf(STDERR_FILENO,
                  "Error: no good entropy source in chroot environment\n");
        return -1;
    }

    return 0;
}

void tpmlib_debug_libtpms_parameters(TPMLIB_TPMVersion tpmversion)
{
    switch (tpmversion) {
    case TPMLIB_TPM_VERSION_1_2:
        TPM_DEBUG("TPM 1.2: Compiled for %u auth, %u transport, "
                  "and %u DAA session slots\n",
            tpmlib_get_tpm_property(TPMPROP_TPM_MIN_AUTH_SESSIONS),
            tpmlib_get_tpm_property(TPMPROP_TPM_MIN_TRANS_SESSIONS),
            tpmlib_get_tpm_property(TPMPROP_TPM_MIN_DAA_SESSIONS));
        TPM_DEBUG("TPM 1.2: Compiled for %u key slots, %u owner evict slots\n",
            tpmlib_get_tpm_property(TPMPROP_TPM_KEY_HANDLES),
            tpmlib_get_tpm_property(TPMPROP_TPM_OWNER_EVICT_KEY_HANDLES));
        TPM_DEBUG("TPM 1.2: Compiled for %u counters, %u saved sessions\n",
            tpmlib_get_tpm_property(TPMPROP_TPM_MIN_COUNTERS),
            tpmlib_get_tpm_property(TPMPROP_TPM_MIN_SESSION_LIST));
        TPM_DEBUG("TPM 1.2: Compiled for %u family, "
                  "%u delegate table entries\n",
            tpmlib_get_tpm_property(TPMPROP_TPM_NUM_FAMILY_TABLE_ENTRY_MIN),
            tpmlib_get_tpm_property(TPMPROP_TPM_NUM_DELEGATE_TABLE_ENTRY_MIN));
        TPM_DEBUG("TPM 1.2: Compiled for %u total NV, %u savestate, "
                  "%u volatile space\n",
            tpmlib_get_tpm_property(TPMPROP_TPM_MAX_NV_SPACE),
            tpmlib_get_tpm_property(TPMPROP_TPM_MAX_SAVESTATE_SPACE),
            tpmlib_get_tpm_property(TPMPROP_TPM_MAX_VOLATILESTATE_SPACE));
#if 0
        TPM_DEBUG("TPM1.2: Compiled for %u NV defined space\n",
            tpmlib_get_tpm_property(TPMPROP_TPM_MAX_NV_DEFINED_SIZE));
#endif
    break;
    case TPMLIB_TPM_VERSION_2:
    break;
    }
}

char *fd_to_filename(int fd)
{
#if defined __linux__

    char buffer[64];
    char *path;

    snprintf(buffer, sizeof(buffer), "/proc/self/fd/%d", fd);

    path = realpath(buffer, NULL);
    if (!path) {
        logprintf(STDERR_FILENO, "Could not read %s: %s\n",
                  buffer, strerror(errno));
        return NULL;
    }

    return path;

#elif defined __APPLE__

    char *path = malloc(MAXPATHLEN);
    if (!path) {
        logprintf(STDERR_FILENO, "Out of memory.\n");
        return NULL;
    }
    if (fcntl(fd, F_GETPATH, path) < 0) {
        logprintf(STDERR_FILENO, "fcntl for F_GETPATH failed: %\n",
                  strerror(errno));
        free(path);
        return NULL;
    }
    return path;

#else
    (void)fd;
    logprintf(STDERR_FILENO,
              "Cannot convert file descriptor to filename on this platform.\n");
    return NULL;

#endif
}

/*
 * write_full: Write all bytes of a buffer into the file descriptor
 *             and handle partial writes on the way.
 *
 * @fd: file descriptor to write to
 * @buffer: buffer
 * @buflen: length of buffer
 *
 * Returns -1 in case not all bytes could be transferred, number of
 * bytes written otherwise (must be equal to buflen).
 */
ssize_t write_full(int fd, const void *buffer, size_t buflen)
{
    size_t written = 0;
    ssize_t n;

    while (written < buflen) {
        n = write(fd, buffer, buflen - written);
        if (n == 0)
            return -1;
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        written += n;
        buffer = (const char *)buffer + n;
    }
    return written;
}

/*
 * writev_full: Write all bytes of an iovec into the file descriptor
 *              and handle partial writes on the way.
 * @fd: file descriptor to write to
 * @iov: pointer to iov
 * @iovcnt: length of iov array
 *
 * Returns -1 in case not all bytes could be transferred, number of
 * bytes written otherwise (must be equal to buflen).
 */
ssize_t writev_full(int fd, const struct iovec *iov, int iovcnt)
{
    int i;
    size_t off;
    unsigned char *buf;
    ssize_t n;
    size_t bytecount = 0;
    size_t numbufs = 0;
    size_t lastidx = -1;

    for (i = 0; i < iovcnt; i++) {
        if (iov[i].iov_len) {
            bytecount += iov[i].iov_len;
            numbufs++;
            lastidx = i;
        }
    }

    if (numbufs == 1)
        return write_full(fd, iov[lastidx].iov_base, iov[lastidx].iov_len);

    buf = malloc(bytecount);
    if (!buf) {
        errno = ENOMEM;
        return -1;
    }

    off = 0;
    for (i = 0; i < iovcnt; i++) {
        if (!iov[i].iov_len)
            continue;
        memcpy(&buf[off], iov[i].iov_base, iov[i].iov_len);
        off += iov[i].iov_len;
    }

    n = write_full(fd, buf, off);

    free(buf);

    return n;
}

/*
 * file_write: Write a buffer to a file.
 *
 * @filename: filename
 * @flags: file open flags
 * @mode: file mode bits
 * @clear_umask: whether to clear the umask and restore it after
 * @buffer: buffer
 * @buflen: length of buffer
 *
 * Returns -1 in case an error occurred, number of bytes written otherwise.
 */
ssize_t file_write(const char *filename, int flags, mode_t mode,
                   bool clear_umask, const void *buffer, size_t buflen)
{
    mode_t orig_umask = 0;
    ssize_t res;
    int fd;

    if (clear_umask)
        orig_umask = umask(0);

    fd = open(filename, flags, mode);

    if (clear_umask)
        umask(orig_umask);

    if (fd < 0)
        return -1;

    res = buflen;
    if (write_full(fd, buffer, buflen) != res)
        res = -1;

    if (close(fd) < 0)
        res = -1;

    if (res < 0)
        unlink(filename);

    return res;
}

/*
 * read_einter: Read bytes from a file descriptor into a buffer
 *              and handle EINTR. Perform one read().
 *
 * @fd: file descriptor to read from
 * @buffer: buffer
 * @buflen: length of buffer
 *
 * Returns -1 in case an error occurred, number of bytes read otherwise.
 */
ssize_t read_eintr(int fd, void *buffer, size_t buflen)
{
    ssize_t n;

    while (true) {
        n = read(fd, buffer, buflen);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        return n;
    }
}

/*
 * file_read: Read contents of file and adjust mode bits
 *
 * @filename: filename
 * @buffer: pointer to buffer pointer to allocate memory for file contents
 * @do_chmod: whether to change the file's mode bits
 * @mode: the mode bits
 *
 * Read the contents of the file into a buffer allocated by this function.
 * Adjust the file mode bits if @do_chmod is set or if file is not writable.
 * Returns -1 on error with errno set, number of bytes read (= size of
 * allocated buffer) otherwise.
 */
ssize_t file_read(const char *filename, void **buffer,
                  bool do_chmod, mode_t mode)
{
    struct stat statbuf;
    ssize_t ret = -1;
    size_t buflen;
    int n, fd;

    fd = open(filename, O_RDONLY);
    if (fd < 0)
        return -1;

    n = fstat(fd, &statbuf);
    if (n < 0)
        goto err_close;

    buflen = statbuf.st_size;
    *buffer = malloc(buflen);
    if (!*buffer) {
        errno = ENOMEM;
        goto err_close;
    }

    ret = read_eintr(fd, *buffer, buflen);
    if (ret < 0 || (size_t)ret != buflen)
        goto err_close;

    /* make sure file is always writable */
    if (!do_chmod && (statbuf.st_mode & 0200) == 0) {
        mode |= 0200;
        do_chmod = true;
    } else if (do_chmod && (statbuf.st_mode & ACCESSPERMS) == mode) {
        do_chmod = false;
    }

    if (do_chmod && fchmod(fd, mode) < 0)
        goto err_close;

    ret = buflen;

err_close:
    if (close(fd) < 0)
        ret = -1;

    return ret;
}

/*
 * Get the value of a map's key.
 *
 * Returns:
 * 0 : success
 * -1 : failure to parse the JSON input
 * -2 : could not find the key
 */
int json_get_map_key_value(const char *json_input,
                           const char *key, char **value)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(JsonParser) jp = NULL;
    g_autoptr(JsonReader) jr = NULL;
    JsonNode *root;

    jp = json_parser_new();
    if (!json_parser_load_from_data(jp, json_input, -1, &error)) {
        logprintf(STDERR_FILENO,
                  "Could not parse JSON '%s': %s\n", json_input, error->message);
        return -1;
    }

    root = json_parser_get_root(jp);
    if (!root) {
        logprintf(STDERR_FILENO,
                  "Could not get root of JSON '%s'\n", json_input);
        return -1;
    }
    jr = json_reader_new(root);

    if (!json_reader_read_member(jr, key))
        return -2;

    *value = g_strdup(json_reader_get_string_value(jr));
    if (*value == NULL) {
        /* value not a string */
        logprintf(STDERR_FILENO,
                  "'%s' in JSON map is not a string\n", key);
        return -1;
    }

    return 0;
}

/*
 * Set the value of a map's key and return the new string
 *
 * Returns:
 * 0 : success
 * -1 : fatal failure
 */
int json_set_map_key_value(char **json_string,
                           const char *key, const char *value)
{
    g_autoptr(JsonParser) jp = NULL;
    g_autoptr(GError) error = NULL;
    g_autoptr(JsonGenerator) jg = NULL;
    JsonObject *jo;
    JsonNode *root;

    jg = json_generator_new();
    if (!jg)
        return -1;

    jp = json_parser_new();
    if (!json_parser_load_from_data(jp, *json_string, -1, &error)) {
        logprintf(STDERR_FILENO,
                  "Could not parse JSON '%s': %s\n", *json_string, error->message);
        return -1;
    }

    root = json_parser_get_root(jp);
    if (!root) {
        logprintf(STDERR_FILENO,
                  "Could not get root of JSON '%s'\n", *json_string);
        return -1;
    }
    json_generator_set_root(jg, root);

    jo = json_node_get_object(root);
    json_object_set_string_member(jo, key, value);

    g_free(*json_string);
    *json_string = json_generator_to_data(jg, NULL);

    return 0;
}

/*
 * In the given JSON map find a map with name @field_name and then
 * access the field @field_name2 in this map and return its value.
 *
 * @json_input: JSON object as string
 * @field_name: Name of map
 * @field_name2: Name of entry in map
 * @value: Results is returned here
 *
 * Returns 0 in case of success, -1 otherwise.
 */
int json_get_submap_value(const char *json_input, const char *field_name,
                          const char *field_name2, char **value)
{
    g_autoptr(JsonParser) jp = NULL;
    g_autoptr(JsonReader) jr = NULL;
    g_autoptr(GError) error = NULL;
    JsonNode *root;

    jp = json_parser_new();
    if (!json_parser_load_from_data(jp, json_input, -1, &error)) {
        logprintf(STDERR_FILENO,
                  "Could not parse JSON '%s': %s\n", json_input, error->message);
        return -1;
    }

    root = json_parser_get_root(jp);
    if (!root) {
        logprintf(STDERR_FILENO,
                  "Could not get root of JSON '%s'\n", json_input);
        return -1;
    }
    jr = json_reader_new(root);

    if (!json_reader_read_member(jr, field_name)) {
        logprintf(STDERR_FILENO, "Missing '%s' field in '%s'\n",
                  field_name, json_input);
        return -1;
    }

    if (!json_reader_read_member(jr, field_name2)) {
        logprintf(STDERR_FILENO, "Missing '%s/%s' field in '%s'\n",
                  field_name, field_name2, json_input);
        return -1;
    }
    *value = g_strdup(json_reader_get_string_value(jr));
    if (*value == NULL) {
        /* value not a string */
        logprintf(STDERR_FILENO,
                  "'%s/%s' field in '%s' is not a string\n",
                  field_name, field_name2, json_input);
        return -1;
    }

    return 0;
}

/*
 * In the given JSON map select @field0_name whose value must be an array.
 * Inside the array of maps, find a map whose @field1_name has the value
 * @field1_value. Then select field2_name and return its value.
 *
 * @json_input: JSON array of maps as a string
 * @field0_name: The name of the map entry holding the array of maps
 * @field1_name: The name of an entry in the map
 * @field1_value: The value of an entry in the map
 * @field2_name: Name of entry in map whose value to return
 * @value: Results is returned here
 *
 * Returns 0 in case of success, -1 otherwise.
 */
int json_get_array_entry_value(const char *json_input,
                               const char *field0_name,
                               const char *field1_name, const char *field1_value,
                               const char *field2_name, char **value)
{
    g_autoptr(JsonParser) jp = NULL;
    g_autoptr(JsonReader) jr = NULL;
    g_autoptr(GError) error = NULL;
    const gchar *strval;
    JsonNode *root;
    guint idx;

    jp = json_parser_new();
    if (!json_parser_load_from_data(jp, json_input, -1, &error)) {
        logprintf(STDERR_FILENO,
                  "Could not parse JSON '%s': %s\n", json_input, error->message);
        return -1;
    }

    root = json_parser_get_root(jp);
    if (!root) {
        logprintf(STDERR_FILENO,
                  "Could not get root of JSON '%s'\n", json_input);
        return -1;
    }
    jr = json_reader_new(root);

    if (!json_reader_read_member(jr, field0_name)) {
        logprintf(STDERR_FILENO,
                  "Could not find the initial field '%s'in '%s'\n",
                  field0_name, json_input);
        return -1;
    }
    for (idx = 0;; idx++) {
        if (!json_reader_read_element(jr, idx)) {
            logprintf(STDERR_FILENO,
                      "Could not find an element with name '%s' and value '%s'\n",
                      field1_name, field1_value);
            return -1;
        }
        if (json_reader_read_member(jr, field1_name)) {
            if ((strval = json_reader_get_string_value(jr)) != NULL &&
                g_strcmp0(strval, field1_value) == 0) {

                json_reader_end_member(jr);
                if (!json_reader_read_member(jr, field2_name)) {
                    logprintf(STDERR_FILENO,
                              "Found map entry in '%s' but could not find field '%s'",
                              json_input, field2_name);
                    return -1;
                }
                *value = g_strdup(json_reader_get_string_value(jr));
                if (*value == NULL) {
                    /* value not a string */
                    logprintf(STDERR_FILENO,
                              "'%s' field in '%s' is not a string\n",
                              field2_name, json_input);
                    return -1;
                }
                return 0;
            }
            json_reader_end_member(jr);
        }
        json_reader_end_element(jr);
    }
    /* must never get here */
    return -1;
}

ssize_t strv_strncmp(const gchar *const*str_array, const gchar *s, size_t n)
{
    size_t i;

    for (i = 0; str_array[i]; i++) {
        if (strncmp(str_array[i], s, n) == 0)
            return (ssize_t)i;
    }
    return -1;
}

/* Try to find exactly the needle in the given haystack */
static ssize_t strv_strcmp(const gchar *const*haystack, const gchar *needle)
{
    size_t i;

    for (i = 0; haystack[i]; i++) {
        if (strcmp(haystack[i], needle) == 0)
            return (ssize_t)i;
    }
    return -1;
}

/*
 * Try to find all the needles in the haystack; both arrays of strings
 * must be NULL-terminated.
 */
gboolean strv_contains_all(const gchar *const*haystack, const gchar *const*needles)
{
    size_t i;

    for (i = 0; needles[i]; i++) {
        if (strv_strcmp(haystack, needles[i]) < 0)
            return false;
    }
    return true;
}

/*
 * Remove all entries in the @array that either fully match @toremove
 * (@len = -1) or where @toremove is a prefix of.
 * This function returns the number of entries that were removed.
 */
size_t strv_remove(gchar **array, const gchar *toremove, ssize_t len,
                   gboolean freethem)
{
    size_t i = 0, j, num = 0;

    while (array[i]) {
        if ((len < 0 && strcmp(array[i], toremove) == 0) ||
            (len > 0 && strncmp(array[i], toremove, len) == 0)) {
            if (freethem)
                g_free(array[i]);

            j = i;
            do {
                j++;
                array[j - 1] = array[j];
            } while(array[j]);

            num++;
        } else {
            i++;
        }
    }
    return num;
}

/*
 * Deduplicate items in a NULL-terminated array of strings.
 * When a duplicate item is found then the first item is removed and all later
 * ones are kept -- this is to deduplicate items in the same way as libtpms
 * deduplicates comma separated items in a string. The string to use for
 * finding duplicates is expected to be returned from an optional gencmpstr_t
 * function that in the simplest case can return the passed string and adjust
 * string comparison to be done on full string (len = -1) or prefix comparison.
 * If not function is given then full string matching is done.
 *
 * This function returns the number of entries removed from the array.
 */
size_t strv_dedup(gchar **array, gencmpstr_t gencmpstr, gboolean freethem)
{
    gboolean free_cmp = false;
    size_t num = 0, i = 0, j;
    ssize_t len = 0;
    gchar *cmp;

    while (array[i]) {
        if (gencmpstr) {
            cmp = gencmpstr(array[i], &len);
            free_cmp = array[i] != cmp;
        } else {
            cmp = array[i];
            len = strlen(cmp);
        }

        j = i + 1;
        while (array[j]) {
            if ((len < 0 && strcmp(array[j], cmp) == 0) ||
                (len > 0 && strncmp(array[j], cmp, len) == 0)) {

                num++;
                if (freethem)
                    g_free(array[i]);

                /*
                 * Keep the later ones in the array since libtpms also keeps
                 * later items ones in string when deduplicating.
                 */
                j = i;
                do {
                    array[j] = array[j + 1];
                    j++;
                } while (array[j]);
                break;
            }
            j++;
        }

        if (free_cmp)
            g_free(cmp);
        i++;
    }
    return num;
}

/*
 * Append entries from a 2nd string array to the first one. Make copies of
 * each entry.
 */
gchar **strv_extend(gchar **array, const gchar *const*append)
{
    size_t len1 = 0, len2 = 0, i;

    if (array)
        len1 = g_strv_length(array);

    while (append[len2])
        len2++;

    array = g_realloc(array, sizeof(char *) * (len1 + len2 + 1));

    for (i = 0; i < len2; i++)
        array[len1 + i] = g_strdup(append[i]);
    array[len1 + len2] = NULL;

    return array;
}
