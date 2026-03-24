#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <libtpms/tpm_error.h>

#include "compiler_dependencies.h"
#include "src/swtpm_setup/swtpm.h"
#include "src/swtpm/swtpm_nvstore.h"

extern struct swtpm_backend_ops swtpm_backend_dir;
extern struct nvram_backend_ops nvram_dir_ops;

/* satisfy swtpm_backend_dir.c dependency from src/utils/swtpm_utils.h */
gchar *gl_LOGFILE;

static char *mapped_dir_uri;

static char *extract_path_option(const char *uri)
{
    const size_t prefix_len = strlen("plugin://");
    const char *query;
    const char *path;

    if (!uri || strncmp(uri, "plugin://", prefix_len) != 0)
        return NULL;

    query = strchr(uri, '?');
    if (!query || !query[1])
        return NULL;
    query++;

    path = query;
    if (strncmp(path, "path=", 5) != 0 || !path[5])
        return NULL;

    return g_uri_unescape_string(path + 5, NULL);
}

static char *map_uri_to_dir_uri(const char *uri)
{
    char *ret = NULL;
    g_autofree gchar *path = extract_path_option(uri);
    if (!path || !path[0])
        return NULL;

    {
        size_t len = strlen(path) + strlen("dir://") + 1;
        ret = malloc(len);
        if (!ret)
            return NULL;
        snprintf(ret, len, "dir://%s", path);
        return ret;
    }
}

static TPM_RESULT map_plugin_uri_to_dir(const char *uri)
{
    if (!uri || strncmp(uri, "plugin://", 9) != 0)
        return TPM_FAIL;

    free(mapped_dir_uri);
    mapped_dir_uri = map_uri_to_dir_uri(uri);
    if (!mapped_dir_uri)
        return TPM_FAIL;

    return mapped_dir_uri ? TPM_SUCCESS : TPM_FAIL;
}

static TPM_RESULT plugin_prepare(const char *uri)
{
    TPM_RESULT rc = map_plugin_uri_to_dir(uri);

    if (rc != TPM_SUCCESS)
        return rc;
    fprintf(stderr,
            "plugin_wrapper: plugin_prepare using mapped_dir_uri='%s'\n",
            mapped_dir_uri ? mapped_dir_uri : "(null)");
    return nvram_dir_ops.prepare(mapped_dir_uri);
}

static TPM_RESULT plugin_lock(const char *uri SWTPM_ATTR_UNUSED, unsigned int retries)
{
    return nvram_dir_ops.lock(mapped_dir_uri, retries);
}

static void plugin_unlock(void)
{
    nvram_dir_ops.unlock();
}

static TPM_RESULT plugin_load(unsigned char **data,
                              uint32_t *length,
                              uint32_t tpm_number,
                              const char *name,
                              const char *uri SWTPM_ATTR_UNUSED)
{
    return nvram_dir_ops.load(data, length, tpm_number, name, mapped_dir_uri);
}

static TPM_RESULT plugin_store(unsigned char *edata,
                               uint32_t data_length,
                               uint32_t tpm_number,
                               const char *name,
                               const char *uri SWTPM_ATTR_UNUSED,
                               TPM_BOOL do_fsync)
{
    return nvram_dir_ops.store(edata, data_length, tpm_number, name,
                               mapped_dir_uri, do_fsync);
}

static TPM_RESULT plugin_delete(uint32_t tpm_number,
                                const char *name,
                                TPM_BOOL mustExist,
                                const char *uri SWTPM_ATTR_UNUSED)
{
    return nvram_dir_ops.delete(tpm_number, name, mustExist, mapped_dir_uri);
}

static TPM_RESULT plugin_check_state(const char *uri SWTPM_ATTR_UNUSED,
                                     const char *name,
                                     size_t *blobsize)
{
    return nvram_dir_ops.check_state(mapped_dir_uri, name, blobsize);
}

static TPM_RESULT plugin_restore_backup_pre_start(const char *uri SWTPM_ATTR_UNUSED)
{
    if (!nvram_dir_ops.restore_backup_pre_start)
        return TPM_FAIL;
    return nvram_dir_ops.restore_backup_pre_start(mapped_dir_uri);
}

static TPM_RESULT plugin_restore_backup(const char *uri SWTPM_ATTR_UNUSED)
{
    if (!nvram_dir_ops.restore_backup)
        return TPM_FAIL;
    return nvram_dir_ops.restore_backup(mapped_dir_uri);
}

static void plugin_cleanup(void)
{
    if (nvram_dir_ops.cleanup)
        nvram_dir_ops.cleanup();
    free(mapped_dir_uri);
    mapped_dir_uri = NULL;
}

/* swtpm_setup side */
static void *setup_parse_backend(const gchar *uri)
{
    void *state;
    g_autofree gchar *dir_uri = NULL;

    if (!uri || strncmp(uri, "plugin://", strlen("plugin://")) != 0)
        return NULL;

    dir_uri = map_uri_to_dir_uri(uri);
    if (!dir_uri)
        return NULL;

    state = swtpm_backend_dir.parse_backend(dir_uri);
    return state;
}

static int setup_check_access(void *state, int mode, const struct passwd *curr_user)
{
    return swtpm_backend_dir.check_access(state, mode, curr_user);
}

static int setup_delete_state(void *state)
{
    return swtpm_backend_dir.delete_state(state);
}

static void setup_free_backend(void *state)
{
    swtpm_backend_dir.free_backend(state);
}

struct swtpm_backend_ops swtpm_backend_plugin_ops = {
    .parse_backend = setup_parse_backend,
    .check_access = setup_check_access,
    .delete_state = setup_delete_state,
    .free_backend = setup_free_backend,
};

/* swtpm side */
struct nvram_backend_ops nvram_backend_plugin_ops = {
    .prepare = plugin_prepare,
    .lock = plugin_lock,
    .unlock = plugin_unlock,
    .load = plugin_load,
    .store = plugin_store,
    .delete = plugin_delete,
    .check_state = plugin_check_state,
    .restore_backup_pre_start = plugin_restore_backup_pre_start,
    .restore_backup = plugin_restore_backup,
    .cleanup = plugin_cleanup,
};
