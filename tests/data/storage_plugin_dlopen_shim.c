#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>

#include "compiler_dependencies.h"

void *dlopen(const char *filename SWTPM_ATTR_UNUSED, int flags SWTPM_ATTR_UNUSED)
{
    return NULL;
}
