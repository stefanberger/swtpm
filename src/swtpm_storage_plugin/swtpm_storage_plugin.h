/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef SWTPM_STORAGE_PLUGIN_H
#define SWTPM_STORAGE_PLUGIN_H

struct nvram_backend_ops;
struct swtpm_backend_ops;

struct nvram_backend_ops *swtpm_storage_plugin_get_nvram_backend_ops(void);
struct swtpm_backend_ops *swtpm_storage_plugin_get_setup_backend_ops(void);

typedef struct nvram_backend_ops *(*swtpm_plugin_get_nvram_backend_ops_t)(void);
typedef struct swtpm_backend_ops *(*swtpm_plugin_get_setup_backend_ops_t)(void);

#define SWTPM_DIR_STORAGE_PLUGIN_NAME "swtpm_storage_plugin_dir.so"
#define SWTPM_FILE_STORAGE_PLUGIN_NAME "swtpm_storage_plugin_file.so"
#define SWTPM_DIR_STORAGE_PLUGIN_NVRAM_SYMBOL "swtpm_storage_plugin_get_nvram_backend_ops"
#define SWTPM_DIR_STORAGE_PLUGIN_SETUP_SYMBOL "swtpm_storage_plugin_get_setup_backend_ops"

#endif
