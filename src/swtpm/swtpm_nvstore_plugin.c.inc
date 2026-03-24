/*
 * swtpm_nvstore_plugin.c.inc: NVRAM backend for plugin://
 *
 * URI format: plugin:///absolute/path/to/plugin.so[?<options>]
 *   URI authority carries the absolute path to the plugin .so file.
 *
 * Plugin .so must export symbol "nvram_backend_plugin_ops"
 * (struct nvram_backend_ops *).
 * 
 * Author: Yu Fan, <yu.fan@smartx.com>
 */

#include <dlfcn.h>


static struct {
    TPM_BOOL initialized;
    char *loaded_uri;
    void *handle;
    struct nvram_backend_ops *backend_ops;
} plugin_state = {
    .initialized = FALSE,
    .loaded_uri = NULL,
    .handle = NULL,
    .backend_ops = NULL
};

static char *
SWTPM_NVRAM_Plugin_ExtractSoPath(const char *uri)
{
    const size_t prefix_len = strlen("plugin://");
    const char *start;
    const char *query_sep;

    if (!uri || strncmp(uri, "plugin://", prefix_len) != 0)
        return NULL;

    start = uri + prefix_len;
    query_sep = strchr(start, '?');
    if (query_sep)
        return strndup(start, query_sep - start);

    return strdup(start);
}

static TPM_RESULT
SWTPM_NVRAM_Plugin_Prepare(const char *uri)
{
    TPM_RESULT rc = TPM_SUCCESS;
    g_autofree gchar *so_path = NULL;
    void *handle = NULL;
    struct nvram_backend_ops *backend_ops = NULL;
    char *loaded_uri = NULL;

    if (plugin_state.initialized) {
        if (strcmp(plugin_state.loaded_uri, uri) == 0) {
            /* same URI loaded; nothing to do */
            return TPM_SUCCESS;
        }

        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_Plugin_Prepare: Cannot prepare twice\n");
        return TPM_FAIL;
    }

    so_path = SWTPM_NVRAM_Plugin_ExtractSoPath(uri);
    if (!so_path || !g_path_is_absolute(so_path)) {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_Plugin_Prepare: Invalid plugin URI: %s\n",
                  uri ? uri : "<null>");
        return TPM_FAIL;
    }

    handle = dlopen(so_path, RTLD_LAZY | RTLD_GLOBAL);
    if (handle == NULL) {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_Plugin_Prepare: Failed to load backend: %s\n", dlerror());
        return TPM_FAIL;
    }

    backend_ops = dlsym(handle, "nvram_backend_plugin_ops");
    if (backend_ops == NULL) {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_Plugin_Prepare: Failed to find backend operations: %s\n",
                  dlerror());
        rc = TPM_FAIL;
        goto cleanup;
    }

    if (backend_ops->prepare == NULL) {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_Plugin_Prepare: Backend does not implement prepare operation\n");
        rc = TPM_FAIL;
        goto cleanup;
    }

    rc = backend_ops->prepare(uri);
    if (rc != TPM_SUCCESS) {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_Plugin_Prepare: Backend prepare failed: %s\n", so_path);
        rc = TPM_FAIL;
        goto cleanup;
    }

    loaded_uri = strdup(uri);
    if (!loaded_uri) {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_Plugin_Prepare: Out of memory\n");
        rc = TPM_FAIL;
        goto cleanup;
    }

    plugin_state.handle = handle;
    plugin_state.backend_ops = backend_ops;
    plugin_state.loaded_uri = loaded_uri;
    plugin_state.initialized = TRUE;

cleanup:
    if (rc == TPM_FAIL) {
        if (backend_ops != NULL && backend_ops->cleanup) {
            backend_ops->cleanup();
        }

        if (handle != NULL) {
            dlclose(handle);
        }
        free(loaded_uri);
    }

    return rc;
}

static void SWTPM_NVRAM_Plugin_Cleanup(void)
{
    if (plugin_state.handle != NULL) {
        if (plugin_state.backend_ops != NULL &&
            plugin_state.backend_ops->cleanup) {
            plugin_state.backend_ops->cleanup();
        }
        dlclose(plugin_state.handle);
        plugin_state.handle = NULL;
    }

    plugin_state.backend_ops = NULL;
    free(plugin_state.loaded_uri);
    plugin_state.loaded_uri = NULL;
    plugin_state.initialized = FALSE;
}

static TPM_RESULT
SWTPM_NVRAM_Plugin_Lock(const char *uri, unsigned int retries)
{
    if (plugin_state.backend_ops == NULL || plugin_state.backend_ops->lock == NULL) {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_Plugin_Lock: Backend does not implement lock operation\n");
        return TPM_FAIL;
    }
    return plugin_state.backend_ops->lock(uri, retries);
}

static void
SWTPM_NVRAM_Plugin_Unlock(void)
{
    if (plugin_state.backend_ops == NULL || plugin_state.backend_ops->unlock == NULL) {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_Plugin_Unlock: Backend does not implement unlock operation\n");
        return;
    }
    plugin_state.backend_ops->unlock();
}

static TPM_RESULT
SWTPM_NVRAM_Plugin_LoadData(unsigned char **data,
                            uint32_t *length,
                            uint32_t tpm_number,
                            const char *name,
                            const char *uri)
{
    if (plugin_state.backend_ops == NULL || plugin_state.backend_ops->load == NULL) {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_Plugin_LoadData: Backend does not implement load operation\n");
        return TPM_FAIL;
    }

    return plugin_state.backend_ops->load(data, length, tpm_number, name, uri);
}

static TPM_RESULT
SWTPM_NVRAM_Plugin_StoreData(unsigned char *edata,
                             uint32_t data_length,
                             uint32_t tpm_number,
                             const char *name,
                             const char *uri,
                             TPM_BOOL do_fsync)
{
    if (plugin_state.backend_ops == NULL || plugin_state.backend_ops->store == NULL) {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_Plugin_StoreData: Backend does not implement store operation\n");
        return TPM_FAIL;
    }

    return plugin_state.backend_ops->store(edata, data_length, tpm_number, name, uri,
                                           do_fsync);
}

static TPM_RESULT
SWTPM_NVRAM_Plugin_DeleteData(uint32_t tpm_number,
                              const char *name,
                              TPM_BOOL mustExist,
                              const char *uri)
{
    if (plugin_state.backend_ops == NULL ||
        plugin_state.backend_ops->delete == NULL) {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_Plugin_DeleteData: Backend does not implement delete operation\n");
        return TPM_FAIL;
    }

    return plugin_state.backend_ops->delete(tpm_number, name, mustExist, uri);
}

static TPM_RESULT
SWTPM_NVRAM_Plugin_CheckState(const char *uri,
                              const char *name,
                              size_t *blobsize)
{
    if (plugin_state.backend_ops == NULL ||
        plugin_state.backend_ops->check_state == NULL) {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_Plugin_CheckState: Backend does not implement check_state operation\n");
        return TPM_FAIL;
    }

    return plugin_state.backend_ops->check_state(uri, name, blobsize);
}

static TPM_RESULT
SWTPM_NVRAM_Plugin_RestoreBackupPreStart(const char *uri)
{
    if (plugin_state.backend_ops == NULL ||
        plugin_state.backend_ops->restore_backup_pre_start == NULL) {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_Plugin_RestoreBackupPreStart: Backend does not implement restore_backup_pre_start operation\n");
        return TPM_FAIL;
    }

    return plugin_state.backend_ops->restore_backup_pre_start(uri);
}

static TPM_RESULT
SWTPM_NVRAM_Plugin_RestoreBackup(const char *uri)
{
    if (plugin_state.backend_ops == NULL ||
        plugin_state.backend_ops->restore_backup == NULL) {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_Plugin_RestoreBackup: Backend does not implement restore_backup operation\n");
        return TPM_FAIL;
    }

    return plugin_state.backend_ops->restore_backup(uri);
}

struct nvram_backend_ops nvram_plugin_ops = {
    .prepare = SWTPM_NVRAM_Plugin_Prepare,
    .lock = SWTPM_NVRAM_Plugin_Lock,
    .unlock = SWTPM_NVRAM_Plugin_Unlock,
    .load = SWTPM_NVRAM_Plugin_LoadData,
    .store = SWTPM_NVRAM_Plugin_StoreData,
    .delete = SWTPM_NVRAM_Plugin_DeleteData,
    .check_state = SWTPM_NVRAM_Plugin_CheckState,
    .restore_backup_pre_start = SWTPM_NVRAM_Plugin_RestoreBackupPreStart,
    .restore_backup = SWTPM_NVRAM_Plugin_RestoreBackup,
    .cleanup = SWTPM_NVRAM_Plugin_Cleanup
};
