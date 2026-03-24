/**
 * swtpm_backend_plugin_stub.c.inc: stub for plugin backend
 */

#include "compiler_dependencies.h"

static void *parse_plugin_state(const gchar *uri SWTPM_ATTR_UNUSED)
{
    logerr(gl_LOGFILE,
           "plugin backend requires dlopen and is unsupported on this platform.\n");
    return NULL;
}

static int check_access(void *state SWTPM_ATTR_UNUSED, int mode SWTPM_ATTR_UNUSED,
                        const struct passwd *curr_user SWTPM_ATTR_UNUSED)
{
    return 1;
}

static int delete_state(void *state SWTPM_ATTR_UNUSED)
{
    return 1;
}

static void free_plugin_state(void *state SWTPM_ATTR_UNUSED)
{
}

struct swtpm_backend_ops swtpm_backend_plugin = {
    .parse_backend = parse_plugin_state,
    .check_access = check_access,
    .delete_state = delete_state,
    .free_backend = free_plugin_state,
};
