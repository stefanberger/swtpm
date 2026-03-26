/*
 * swtpm_nvstore_plugin_stub.c.inc: stubs for plugin backend
 */

static TPM_RESULT
SWTPM_NVRAM_Plugin_Prepare(const char *uri SWTPM_ATTR_UNUSED)
{
    logprintf(STDERR_FILENO,
              "SWTPM_NVRAM_Plugin_Prepare: plugin backend requires dlopen and is unsupported on this platform.\n");
    return TPM_FAIL;
}

static TPM_RESULT
SWTPM_NVRAM_Plugin_Lock(const char *uri SWTPM_ATTR_UNUSED,
                        unsigned int retries SWTPM_ATTR_UNUSED)
{
    return TPM_FAIL;
}

static void
SWTPM_NVRAM_Plugin_Unlock(void)
{
}

static TPM_RESULT
SWTPM_NVRAM_Plugin_LoadData(unsigned char **data SWTPM_ATTR_UNUSED,
                            uint32_t *length SWTPM_ATTR_UNUSED,
                            uint32_t tpm_number SWTPM_ATTR_UNUSED,
                            const char *name SWTPM_ATTR_UNUSED,
                            const char *uri SWTPM_ATTR_UNUSED)
{
    return TPM_FAIL;
}

static TPM_RESULT
SWTPM_NVRAM_Plugin_StoreData(unsigned char *edata SWTPM_ATTR_UNUSED,
                             uint32_t data_length SWTPM_ATTR_UNUSED,
                             uint32_t tpm_number SWTPM_ATTR_UNUSED,
                             const char *name SWTPM_ATTR_UNUSED,
                             const char *uri SWTPM_ATTR_UNUSED,
                             TPM_BOOL do_fsync SWTPM_ATTR_UNUSED)
{
    return TPM_FAIL;
}

static TPM_RESULT
SWTPM_NVRAM_Plugin_DeleteData(uint32_t tpm_number SWTPM_ATTR_UNUSED,
                              const char *name SWTPM_ATTR_UNUSED,
                              TPM_BOOL mustExist SWTPM_ATTR_UNUSED,
                              const char *uri SWTPM_ATTR_UNUSED)
{
    return TPM_FAIL;
}

static TPM_RESULT
SWTPM_NVRAM_Plugin_CheckState(const char *uri SWTPM_ATTR_UNUSED,
                              const char *name SWTPM_ATTR_UNUSED,
                              size_t *blobsize SWTPM_ATTR_UNUSED)
{
    return TPM_FAIL;
}

static TPM_RESULT
SWTPM_NVRAM_Plugin_RestoreBackupPreStart(const char *uri SWTPM_ATTR_UNUSED)
{
    return TPM_FAIL;
}

static TPM_RESULT
SWTPM_NVRAM_Plugin_RestoreBackup(const char *uri SWTPM_ATTR_UNUSED)
{
    return TPM_FAIL;
}

static void SWTPM_NVRAM_Plugin_Cleanup(void)
{
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
