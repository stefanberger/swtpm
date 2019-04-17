/*
 * options.c -- Option parsing
 *
 * (c) Copyright IBM Corporation 2014, 2015.
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

#include "sys_dependencies.h"

#include <limits.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <pwd.h>
#include <grp.h>

#include "options.h"

static void
option_error_set(char **error, const char *format, ...)
{
    va_list ap;
    int ret;

    va_start(ap, format);
    ret = vasprintf(error, format, ap);
    va_end(ap);

    (void)ret;
}

/*
 * option_value_add
 * Add a option's value that was parsed following a template to the collection
 * of option values.
 * @ovs: OptionValues where to add the given value
 * @optdesc: the template to use for parsing this option
 * @val: the value to parses as a datatype given in optdesc
 * @error: Pointer to a pointer for an error message
 *
 * Returns 0 on success, -1 on error.
 */
static int
option_value_add(OptionValues *ovs, const OptionDesc optdesc, const char *val,
                 char **error)
{
    int ret = 0;
    char *endptr = NULL;
    long int li;
    long unsigned int lui;
    struct passwd *passwd;
    struct group *group;
    
    size_t idx = ovs->n_options;
    
    ovs->options = realloc(ovs->options, (idx + 1) * sizeof(*ovs->options));
    if (!ovs->options) {
        option_error_set(error, "Out of memory");
        return -1;
    }

    ovs->n_options = idx + 1;
    ovs->options[idx].type = optdesc.type;
    ovs->options[idx].name = optdesc.name;

    switch (optdesc.type) {
    case OPT_TYPE_STRING:
        ovs->options[idx].u.string = strdup(val);
        if (!ovs->options[idx].u.string) {
            option_error_set(error, "Out of memory");
            return -1;
        }
        break;
    case OPT_TYPE_INT:
        li = strtol(val, &endptr, 10);
        if (*endptr != '\0') {
            option_error_set(error, "invalid number '%s'", val);
            return -1;
        }
        if (li < INT_MIN || li > INT_MAX) {
            option_error_set(error, "number %li outside valid range", li);
        }
        ovs->options[idx].u.integer = li;

        break;
    case OPT_TYPE_UINT:
        lui = strtol(val, &endptr, 10);
        if (*endptr != '\0') {
            option_error_set(error, "invalid number '%s'", val);
            return -1;
        }
        if (lui > UINT_MAX) {
            option_error_set(error, "number %li outside valid range", lui);
        }
        ovs->options[idx].u.uinteger = lui;

        break;
    case OPT_TYPE_BOOLEAN:
        if (!strcasecmp(val, "true") || !strcasecmp(val, "1")) {
            ovs->options[idx].u.boolean = true;
        } else {
            ovs->options[idx].u.boolean = false;
        }
        break;
    case OPT_TYPE_MODE_T:
        lui = strtol(val, &endptr, 8);
        if (*endptr != '\0') {
            option_error_set(error, "invalid mode type '%s'", val);
            return -1;
        }
        if (lui > 0777) {
            option_error_set(error, "mode %s is invalid", val);
            return -1;
        }
        ovs->options[idx].u.mode = (mode_t)lui;

        break;
    case OPT_TYPE_UID_T:
        lui = strtol(val, &endptr, 10);
        if (*endptr == '\0') {
            if (lui > UINT_MAX) {
                option_error_set(error, "uid %s outside valid range", val);
                return -1;
            }
        } else {
            /* try as a string */
            passwd = getpwnam(val);
            if (!passwd) {
                option_error_set(error, "User '%s' does not exist.\n", val);
                return -1;
            }
            lui = passwd->pw_uid;
        }
        ovs->options[idx].u.uid = (uid_t)lui;

        break;
    case OPT_TYPE_GID_T:
        lui = strtol(val, &endptr, 10);
        if (*endptr == '\0') {
            if (lui > UINT_MAX) {
                option_error_set(error, "gid %s outside valid range", val);
                return -1;
            }
        } else {
            /* try as a string */
            group = getgrnam(val);
            if (!group) {
                option_error_set(error, "Group '%s' does not exist.\n", val);
                return -1;
            }
            lui = group->gr_gid;
        }
        ovs->options[idx].u.gid = (uid_t)lui;

        break;
    }

    return ret;
}

/*
 * options_parse:
 * Parse the string of options following the template; return the
 * parsed Options or an error string.
 * @opts: string containing the comma separated options to parse
 * @optdesc: template to follow when parsing individual options
 * @error: Pointer to a pointer for holding an error message
 *
 * Returns the parse options, types, and values in OptionValues.
 */
OptionValues *
options_parse(char *opts, const OptionDesc optdesc[], char **error)
{
    char *saveptr;
    char *tok;
    int i;
    OptionValues *ovs = calloc(sizeof(OptionValues), 1);
    bool found;
    char *opts_bak;

    if (!ovs) {
        option_error_set(error, "Out of memory.");
        return NULL;
    }

    opts_bak = strdup(opts);
    if (!opts_bak) {
        option_error_set(error, "Out of memory.");
        goto error;
    }

    saveptr = opts_bak; /* make coverity happy */

    tok = strtok_r(opts_bak, ",", &saveptr);
    while (tok) {
        size_t toklen = strlen(tok);

        found = false;
        i = 0;
        while (optdesc[i].name) {
            size_t len = strlen(optdesc[i].name);

            if (toklen > len + 1 && tok[len] == '=' &&
                !strncmp(optdesc[i].name, tok, len)) {
                const char *v = &tok[len + 1];

                if (option_value_add(ovs, optdesc[i], v, error) < 0)
                    goto error;
                found = true;
                break;
            } else if (!strcmp(optdesc[i].name, tok)) {
                if (option_value_add(ovs, optdesc[i], "true", error) < 0)
                    goto error;
                found = true;
                break;
            }
            i++;
        }
        if (!found) {
            option_error_set(error, "Unknown option '%s'", tok);
            goto error;
        }

        tok = strtok_r(NULL, ",", &saveptr);
    }

    free(opts_bak);

    return ovs;

error:
    free(opts_bak);

    option_values_free(ovs);
    return NULL;
}

/*
 * option_values_free
 * Free the option values
 * @ovs: OptionValues structure to free; may be NULL
 */
void
option_values_free(OptionValues *ovs)
{
    size_t i;

    if (!ovs)
        return;

    for (i = 0; i < ovs->n_options; i++) {
        switch (ovs->options[i].type) {
        case OPT_TYPE_STRING:
            free(ovs->options[i].u.string);
            break;
        case OPT_TYPE_INT:
        case OPT_TYPE_UINT:
        case OPT_TYPE_BOOLEAN:
        case OPT_TYPE_MODE_T:
        case OPT_TYPE_UID_T:
        case OPT_TYPE_GID_T:
            break;
        }
    }
    free(ovs->options);
    free(ovs);
}

/*
 * Given the name of a string option, return the value it received when it
 * was parsed.
 * @ovs: The OptionValues
 * @name: the name of the option
 * @def: the default value
 *
 * Returns the parsed value or the default value if none was parsed;
 * If the value is of different type than a string, NULL is returned.
 */
const char *
option_get_string(OptionValues *ovs, const char *name, const char *def)
{
    size_t i;

    for (i = 0; i < ovs->n_options; i++) {
        if (!strcmp(name, ovs->options[i].name)) {
            if (ovs->options[i].type == OPT_TYPE_STRING)
                return ovs->options[i].u.string;
            return NULL;
        }
    }

    return def;
}

/*
 * Given the name of an int option, return the value it received when it
 * was parsed.
 * @ovs: The OptionValues
 * @name: the name of the option
 * @def: the default value
 *
 * Returns the parsed value or the default value if none was parsed
 * If the value is of different type than an integer, -1 is returned.
 */
int
option_get_int(OptionValues *ovs, const char *name, int def)
{
    size_t i;

    for (i = 0; i < ovs->n_options; i++) {
        if (!strcmp(name, ovs->options[i].name)) {
            if (ovs->options[i].type == OPT_TYPE_INT)
                return ovs->options[i].u.integer;
            return -1;
        }
    }

    return def;
}

/*
 * Given the name of an uint option, return the value it received when it
 * was parsed.
 * @ovs: The OptionValues
 * @name: the name of the option
 * @def: the default value
 *
 * Returns the parsed value or the default value if none was parsed
 * If the value is of different type than an integer, ~0 is returned.
 */
unsigned int
option_get_uint(OptionValues *ovs, const char *name, unsigned int def)
{
    size_t i;

    for (i = 0; i < ovs->n_options; i++) {
        if (!strcmp(name, ovs->options[i].name)) {
            if (ovs->options[i].type == OPT_TYPE_UINT)
                return ovs->options[i].u.uinteger;
            return ~0;
        }
    }

    return def;
}

/*
 * Given the name of a boolean option, return the value it received when it
 * was parsed.
 * @ovs: The OptionValues
 * @name: the name of the option
 * @def: the default value
 *
 * Returns the parsed value or the default value if none was parsed
 * If the value is of different type than a boolean, false is returned.
 */
bool
option_get_bool(OptionValues *ovs, const char *name, bool def)
{
    size_t i;

    for (i = 0; i < ovs->n_options; i++) {
        if (!strcmp(name, ovs->options[i].name)) {
            if (ovs->options[i].type == OPT_TYPE_BOOLEAN)
                return ovs->options[i].u.boolean;
            return false;
        }
    }

    return def;
}

/*
 * Given the name of a mode_t (chmod) option, return the value it received when it
 * was parsed.
 * @ovs: The OptionValues
 * @name: the name of the option
 * @def: the default value
 *
 * Returns the parsed value or the default value if none was parsed
 * If the value is of different type than a mode_t, ~0 is returned.
 */
mode_t
option_get_mode_t(OptionValues *ovs, const char *name, mode_t def)
{
    size_t i;

    for (i = 0; i < ovs->n_options; i++) {
        if (!strcmp(name, ovs->options[i].name)) {
            if (ovs->options[i].type == OPT_TYPE_MODE_T)
                return ovs->options[i].u.mode;
            return ~0;
        }
    }

    return def;
}

/*
 * Given the name of a uid_t (chown) option, return the value it received when it
 * was parsed.
 * @ovs: The OptionValues
 * @name: the name of the option
 * @def: the default value
 *
 * Returns the parsed value or the default value if none was parsed
 * If the value is of different type than a uid_t, -1 is returned.
 */
uid_t
option_get_uid_t(OptionValues *ovs, const char *name, uid_t def)
{
    size_t i;

    for (i = 0; i < ovs->n_options; i++) {
        if (!strcmp(name, ovs->options[i].name)) {
            if (ovs->options[i].type == OPT_TYPE_UID_T)
                return ovs->options[i].u.uid;
            return -1;
        }
    }

    return def;
}

/*
 * Given the name of a gid_t (chown) option, return the value it received when it
 * was parsed.
 * @ovs: The OptionValues
 * @name: the name of the option
 * @def: the default value
 *
 * Returns the parsed value or the default value if none was parsed
 * If the value is of different type than a uid_t, -1 is returned.
 */
gid_t
option_get_gid_t(OptionValues *ovs, const char *name, gid_t def)
{
    size_t i;

    for (i = 0; i < ovs->n_options; i++) {
        if (!strcmp(name, ovs->options[i].name)) {
            if (ovs->options[i].type == OPT_TYPE_GID_T)
                return ovs->options[i].u.gid;
            return -1;
        }
    }

    return def;
}
