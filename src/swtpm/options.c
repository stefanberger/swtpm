/*
 * options.c -- Option parsing
 *
 * (c) Copyright IBM Corporation 2014.
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

#define _GNU_SOURCE
#include <features.h>

#include <limits.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>

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

static int
option_value_add(OptionValues *ovs, const OptionDesc optdesc, const char *val,
                 char **error)
{
    int ret = 0;
    char *endptr = NULL;
    long int li;
    
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
    case OPT_TYPE_BOOLEAN:
        if (!strcasecmp(val, "true") || !strcasecmp(val, "1")) {
            ovs->options[idx].u.boolean = true;
        } else {
            ovs->options[idx].u.boolean = false;
        }
        break;
    }

    return ret;
}

OptionValues *
options_parse(char *opts, const OptionDesc optdesc[], char **error)
{
    char *saveptr = NULL;
    char *tok;
    int i;
    OptionValues *ovs = calloc(sizeof(OptionValues), 1);
    bool found;

    if (!ovs) {
        option_error_set(error, "Out of memory.");
        return NULL;
    }

    tok = strtok_r(opts, ",", &saveptr);
    while (tok) {
        found = false;
        i = 0;
        while (optdesc[i].name) {
            size_t len = strlen(optdesc[i].name);
            if (tok[len] == '=' &&
                !strncmp(optdesc[i].name, tok, len)) {
                const char *v = &tok[len+1];
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

    return ovs;

error:
    option_values_free(ovs);
    return NULL;
}

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
        case OPT_TYPE_BOOLEAN:
            break;
        }
    }
    free(ovs->options);
    free(ovs);
}

const char *
option_get_string(OptionValues *ovs, const char *name)
{
    size_t i;

    for (i = 0; i < ovs->n_options; i++) {
        if (!strcmp(name, ovs->options[i].name)) {
            if (ovs->options[i].type == OPT_TYPE_STRING)
                return ovs->options[i].u.string;
            return NULL;
        }
    }

    return NULL;
}

int
option_get_int(OptionValues *ovs, const char *name)
{
    size_t i;

    for (i = 0; i < ovs->n_options; i++) {
        if (!strcmp(name, ovs->options[i].name)) {
            if (ovs->options[i].type == OPT_TYPE_INT)
                return ovs->options[i].u.integer;
            return -1;
        }
    }

    return -1;
}

bool
option_get_bool(OptionValues *ovs, const char *name)
{
    size_t i;

    for (i = 0; i < ovs->n_options; i++) {
        if (!strcmp(name, ovs->options[i].name)) {
            if (ovs->options[i].type == OPT_TYPE_BOOLEAN)
                return ovs->options[i].u.boolean;
            return false;
        }
    }

    return false;
}

