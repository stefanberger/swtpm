/**
 * swtpm_backend_plugin.c.inc: storage backend for plugin://
 * Loads a pluggable NVRAM backend from a .so and delegates to it.
 *
 * URI format: plugin:///absolute/path/to/plugin.so[?<options>]
 *   URI authority carries the absolute path to the plugin .so file.
 *
 * Plugin .so must export the symbol "swtpm_backend_plugin_ops" (struct
 * swtpm_backend_ops *) for ABI compatibility with existing backend plugins.
 *
 * Author: Yu Fan, <yu.fan@smartx.com>
 */

#include <dlfcn.h>
#include <unistd.h>

#include "compiler_dependencies.h"

static gchar *plugin_extract_so_path(const gchar *uri)
{
    const size_t prefix_len = strlen("plugin://");
    const gchar *start;
    const gchar *query_sep;

    if (!uri || strncmp(uri, "plugin://", prefix_len) != 0)
        return NULL;

    start = uri + prefix_len;
    query_sep = strchr(start, '?');
    if (query_sep)
        return g_strndup(start, query_sep - start);

    return g_strdup(start);
}

struct plugin_state {
    void *handle;
    struct swtpm_backend_ops *backend_ops;
    void *backend_state;
};

/* Parse plugin:///absolute/path/to/plugin.so[?<options>] URI. */
static void *parse_plugin_state(const gchar *uri)
{
    struct plugin_state *ret = NULL;
    g_autofree gchar *so_path = NULL;
    void *handle = NULL;
    struct swtpm_backend_ops *ops = NULL;
    void *backend_state = NULL;

    so_path = plugin_extract_so_path(uri);
    if (!so_path || !g_path_is_absolute(so_path)) {
        logerr(gl_LOGFILE, "Invalid plugin URI (expected plugin:///absolute/path/to/plugin.so[?<options>]): %s\n",
               uri ? uri : "<null>");
        return NULL;
    }

    if (getuid() == 0) {
        logerr(gl_LOGFILE, "Refusing plugin backend %s while running as root\n",
               so_path);
        return NULL;
    }

    if (access(so_path, R_OK) != 0) {
        logerr(gl_LOGFILE, "No permission to access plugin backend %s: %s\n",
               so_path, strerror(errno));
        return NULL;
    }

    handle = dlopen(so_path, RTLD_LAZY | RTLD_GLOBAL);
    if (!handle) {
        logerr(gl_LOGFILE, "Failed to load plugin backend %s: %s\n", so_path, dlerror());
        return NULL;
    }

    ops = dlsym(handle, "swtpm_backend_plugin_ops");
    if (!ops) {
        logerr(gl_LOGFILE, "Plugin backend %s does not export swtpm_backend_plugin_ops: %s\n",
               so_path, dlerror());
        goto error;
    }

    if (!ops->parse_backend) {
        logerr(gl_LOGFILE, "Plugin backend %s does not implement parse_backend.\n",
               so_path);
        goto error;
    }

    backend_state = ops->parse_backend(uri);
    if (!backend_state) {
        logerr(gl_LOGFILE, "Failed to parse backend state for plugin %s.\n", so_path);
        goto error;
    }

    ret = g_malloc(sizeof(struct plugin_state));
    ret->handle = handle;
    ret->backend_ops = ops;
    ret->backend_state = backend_state;
    return (void *)ret;

error:
    if (handle)
        dlclose(handle);

    return NULL;
}

static int check_access(void *state, int mode, const struct passwd *curr_user)
{
    struct plugin_state *pstate = (struct plugin_state *)state;

    if (!pstate || !pstate->backend_ops || !pstate->backend_ops->check_access) {
        logerr(gl_LOGFILE, "Plugin backend does not implement check_access.\n");
        return 1;
    }
    return pstate->backend_ops->check_access(pstate->backend_state, mode, curr_user);
}

static int delete_state(void *state)
{
    struct plugin_state *pstate = (struct plugin_state *)state;

    if (!pstate || !pstate->backend_ops || !pstate->backend_ops->delete_state) {
        logerr(gl_LOGFILE, "Plugin backend does not implement delete_state.\n");
        return 1;
    }
    return pstate->backend_ops->delete_state(pstate->backend_state);
}

static void free_plugin_state(void *state)
{
    struct plugin_state *pstate = (struct plugin_state *)state;

    if (!pstate)
        return;
    if (pstate->backend_ops && pstate->backend_ops->free_backend)
        pstate->backend_ops->free_backend(pstate->backend_state);
    if (pstate->handle)
        dlclose(pstate->handle);
    g_free(pstate);
}

struct swtpm_backend_ops swtpm_backend_plugin = {
    .parse_backend = parse_plugin_state,
    .check_access = check_access,
    .delete_state = delete_state,
    .free_backend = free_plugin_state,
};
