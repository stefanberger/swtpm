/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Thin module for dir:// backends.  Does not implement NVRAM/setup logic itself.
 *
 * Call chain (NVRAM, swtpm):
 *   SWTPM_NVRAM_LoadStoragePluginOps → dlopen(this .so) →
 *   dlsym("swtpm_storage_plugin_get_nvram_backend_ops") →
 *   swtpm_storage_plugin_get_nvram_backend_ops() → returns &nvram_dir_ops
 *   nvram_dir_ops is defined in libswtpm_libtpms (weak ref here binds at load).
 *
 * Call chain (setup, swtpm_setup):
 *   load_swtpm_backend_ops → dlopen(this .so) →
 *   dlsym("swtpm_storage_plugin_get_setup_backend_ops") →
 *   swtpm_storage_plugin_get_setup_backend_ops() → returns &swtpm_backend_dir
 *   swtpm_backend_dir is defined in the swtpm_setup binary (weak ref binds at load).
 */
#include "config.h"

#include <stddef.h>

#include "swtpm_storage_plugin.h"

extern struct nvram_backend_ops nvram_dir_ops __attribute__((weak));
extern struct swtpm_backend_ops swtpm_backend_dir __attribute__((weak));

struct nvram_backend_ops *swtpm_storage_plugin_get_nvram_backend_ops(void)
{
    if (&nvram_dir_ops == NULL)
        return NULL;

    return &nvram_dir_ops;
}

struct swtpm_backend_ops *swtpm_storage_plugin_get_setup_backend_ops(void)
{
    if (&swtpm_backend_dir == NULL)
        return NULL;

    return &swtpm_backend_dir;
}
