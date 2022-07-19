/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * profile.c: TPM 2 profile handling
 *
 * Author: Stefan Berger, stefanb@linux.ibm.com
 *
 * Copyright (c) IBM Corporation, 2022
 */

#include <stdio.h>
#include "config.h"

#include <json-glib/json-glib.h>

#include "profile.h"
#include "swtpm_utils.h"

/* Return the names of the supported profiles */
int get_profile_names(const gchar *swtpm_capabilities_json, gchar ***profile_names)
{
    g_autoptr(GError) error = NULL;
    JsonParser *jp = NULL;
    JsonReader *jr = NULL;
    JsonNode *root;
    gint i, num;
    int ret = 1;

    jp = json_parser_new();
    if (!json_parser_load_from_data(jp, swtpm_capabilities_json, -1, &error)) {
        logerr(gl_LOGFILE, "Could not parse capabilities JSON '%s': %s\n",
               swtpm_capabilities_json, error->message);
        goto error_unref_jp;
    }

    root = json_parser_get_root(jp);
    jr = json_reader_new(root);

    if (!json_reader_read_member(jr, "profiles")) {
        logerr(gl_LOGFILE, "Missing 'profiles' field: %s\n",
               swtpm_capabilities_json);
        goto error_unref_jr;
    }
    if (!json_reader_read_member(jr, "names")) {
        logerr(gl_LOGFILE, "Missing 'names' field under 'profiles': %s\n",
               swtpm_capabilities_json);
        goto error_unref_jr;
    }

    num = json_reader_count_elements(jr);
    if (num < 0) {
        logerr(gl_LOGFILE, "Number of profile names is bad (%d)\n",
               num);
        goto error_unref_jr;
    }

    *profile_names = g_malloc0((num + 1) * sizeof(char *));
    for (i = 0; i < num; i++) {
        if (!json_reader_read_element(jr, i)) {
            logerr(gl_LOGFILE, "Could not parse JSON list: %s\n", error->message);
            goto error_str_array_free;
        }
        (*profile_names)[i] = g_strdup(json_reader_get_string_value(jr));
        json_reader_end_element(jr);
    }
    ret = 0;


error_unref_jr:
    g_object_unref(jr);

error_unref_jp:
    g_object_unref(jp);

    return ret;

error_str_array_free:
    g_strfreev(*profile_names);

    goto error_unref_jr;
}

int check_json_profile(const gchar *swtpm_capabilities_json, const char *json_profile)
{
    gchar **profile_names = NULL;
    g_autofree gchar *name = NULL;
    int idx;
    int ret;

    ret = json_get_map_value(json_profile, "Name", &name);
    if (ret)
        return ret;

    ret = get_profile_names(swtpm_capabilities_json, &profile_names);
    if (ret)
        goto error;

    idx = strv_strcmp(profile_names, name);
    if (idx < 0) {
        logerr(gl_LOGFILE, "swtpm does not support a profile with name '%s'\n", name);
        ret = 1;
    }

error:
    g_strfreev(profile_names);

    return ret;
}
