/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * profile.c: TPM 2 profile handling
 *
 * Author: Stefan Berger, stefanb@linux.ibm.com
 *
 * Copyright (c) IBM Corporation, 2022
 */

#include "config.h"

#include <stdio.h>
#include <string.h>

#include <glib.h>
#include <glib/gstdio.h>

#include <json-glib/json-glib.h>

#include "profile.h"
#include "swtpm_conf.h"
#include "swtpm_utils.h"
#include "swtpm_setup_utils.h"
#include "compiler_dependencies.h"

#define DISTRO_PROFILES_DIR DATAROOTDIR "/swtpm/profiles"


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
    /* { "Name": null } does not lead to parser failure but return name = NULL */
    if (ret || name == NULL) {
        ret = 1;
        logerr(gl_LOGFILE, "Failed to get 'Name' from profile '%s'.\n",
               json_profile);
        return ret;
    }

    if (strlen(name) > 32) {
        logerr(gl_LOGFILE, "Profile name must not exceed 32 characters.\n");
        return 1;
    }

    /* 'custom:' prefix is accepted */
    if (!strncmp(name, "custom:", 7))
        return 0;

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

/* Create a path to the profile and check whether the file is accessible */
static int profile_path_from_dir(const gchar *dir,
                                 const gchar *profile_name,
                                 gchar **json_profile_file)
{
    *json_profile_file = g_strdup_printf("%s/%s.json",
                                         dir, profile_name);
    if (g_access(*json_profile_file, R_OK) != 0) {
        SWTPM_G_FREE(*json_profile_file);
        return -1;
    }
    return 0;
}

static int profile_path_local(gchar *const *config_file_lines,
                              const gchar *profile_name,
                              gchar **json_profile_file)
{
    g_autofree gchar *dir = NULL;

    dir = get_config_value(config_file_lines, "local_profiles_dir");
    if (dir == NULL || strlen(dir) == 0 )
        return -1;
    return profile_path_from_dir(dir, profile_name, json_profile_file);
}

static int profile_path_distro(gchar *const *config_file_lines SWTPM_ATTR_UNUSED,
                               const gchar *profile_name,
                               gchar **json_profile_file)
{
    return profile_path_from_dir(DISTRO_PROFILES_DIR,
                                 profile_name,
                                 json_profile_file);
}

static int profile_build_json(gchar *const *config_file_lines SWTPM_ATTR_UNUSED,
                              const gchar *profile_name,
                              gchar **json_profile)
{
    *json_profile = g_strdup_printf("{\"Name\":\"%s\"}", profile_name);
    return 0;
}

/*
 * Check whether the profile name is valid; especially avoid names with '/'
 * that would enable '../../etc/foo'.
 */
int profile_name_check(const gchar *profile_name)
{
    GMatchInfo *match_info;
    GRegex *regex;
    int ret = 0;

    regex = g_regex_new("^[A-Za-z0-9.\\-:]+$",
                        0 /* G_REGEX_DEFAULT */,
                        0 /* G_REGEX_MATCH_DEFAULT */,
                        NULL);
    g_regex_match(regex, profile_name, 0, &match_info);
    if (!g_match_info_matches(match_info)) {
        logerr(gl_LOGFILE,
               "Profile name '%s' contains unacceptable characters.\n",
               profile_name);
        ret = -1;
    }
    g_match_info_free(match_info);
    g_regex_unref(regex);

    return ret;
}

/*
 * Try to find the profile with the given name as a file (with added .json
 * suffix) in the local or distro files directories. If not found in either,
 * create the JSON for selecting a built-in profile.
 *
 * @config_file_lines: lines of the configuration file
 * @json_profile_name: the name of the profile to search for
 * @json_profile_file: pointer to set an available profile file's full path
 * @json_profile: pointer to set to the JSON string for built-in profile
 */
int profile_get_by_name(gchar *const *config_file_lines,
                        const gchar *json_profile_name,
                        gchar **json_profile_file,
                        gchar **json_profile)
{
    typedef int (*getter_t)(gchar *const *config_file_lines,
                            const gchar *name,
                            gchar **result);
    const struct {
        const char  *prefix;
        gboolean     filename; /* true: returns a filename */
        getter_t     getter;
    } prefixes[] = {
        { "local:",   TRUE,  profile_path_local},
        { "distro:",  TRUE,  profile_path_distro},
        { "builtin:", FALSE, profile_build_json},
        { NULL, },
    };
    size_t i, len;

    for (i = 0; prefixes[i].prefix; i++) {
        len = strlen(prefixes[i].prefix);
        if (!strncmp(prefixes[i].prefix, json_profile_name, len))
            return prefixes[i].getter(config_file_lines,
                                      &json_profile_name[len],
                                      prefixes[i].filename
                                         ? json_profile_file
                                         : json_profile);
    }
    /* no prefixes matched */
    for (i = 0; prefixes[i].prefix; i++) {
        if (prefixes[i].getter(config_file_lines,
                               json_profile_name,
                               prefixes[i].filename
                                  ? json_profile_file
                                  : json_profile) == 0)
            return 0;
    }
    return -1;
}

static int profile_replace_name(JsonObject *jo, const char *name)
{
    JsonNode *node;

    node = json_object_get_member(jo, "Name");
    if (!node || json_node_get_node_type(node) != JSON_NODE_VALUE)
        return -1;

    json_object_set_string_member(jo, "Name", name);

    return 0;
}

static JsonArray *profile_gather_dir(const char *dir)
{
    g_autofree gchar *fullpath = NULL;
    g_autoptr(JsonParser) jp = NULL;
    const gchar *filename;
    JsonNode *root;
    JsonObject *jo;
    JsonArray *ja;
    GDir *gdir;

    gdir = g_dir_open(dir, 0, NULL);
    if (!gdir)
        return NULL;

    jp = json_parser_new();
    ja = json_array_new();

    while ((filename = g_dir_read_name(gdir))) {
        size_t len = strlen(filename);
        if (len <= 5 || !g_str_has_suffix(filename, ".json"))
            continue;

        fullpath = g_strdup_printf("%s/%s", dir, filename);
        if (json_parser_load_from_file(jp, fullpath, NULL)) {
            root = json_parser_get_root(jp);
            if (json_node_get_node_type(root) == JSON_NODE_OBJECT) {
                /* remove suffix .json */
                g_autofree gchar *name = g_strndup(filename, len - 5);

                jo = json_node_dup_object(root);
                if (profile_replace_name(jo, name) == 0)
                    json_array_add_object_element(ja, jo);
                else
                    json_object_unref(jo);
            }
        }
        SWTPM_G_FREE(fullpath);
    }
    g_dir_close(gdir);

    return ja;
}

static JsonArray *profile_gather_local(gchar *const *config_file_lines)
{
    g_autofree gchar *dir = NULL;

    dir = get_config_value(config_file_lines, "local_profiles_dir");
    if (dir == NULL || strlen(dir) == 0 )
        return NULL;

    return profile_gather_dir(dir);
}

static JsonArray *profile_gather_builtin(const gchar **swtpm_prg_l)
{
    g_autofree gchar *standard_output = NULL;
    g_autofree const gchar **cmd = NULL;
    g_autoptr(JsonParser) jp = NULL;
    JsonNode *root, *arr;
    JsonArray *ja = NULL;
    JsonObject *jo;

    cmd = concat_arrays(swtpm_prg_l,
                        (const gchar*[]) {"--tpm2", "--print-profiles", NULL},
                        FALSE);

    if (!spawn_sync(NULL, cmd, NULL, G_SPAWN_STDERR_TO_DEV_NULL, NULL, NULL,
                    &standard_output, NULL, NULL, NULL))
        return NULL;

    jp  = json_parser_new();
    if (json_parser_load_from_data(jp, standard_output, -1, NULL)) {
        root = json_parser_get_root(jp);
        if (json_node_get_node_type(root) == JSON_NODE_OBJECT) {
            jo = json_node_get_object(root);
            arr = json_object_get_member(jo, "AvailableProfiles");
            if (arr && json_node_get_node_type(arr) == JSON_NODE_ARRAY)
                ja = json_node_dup_array(arr);
        }
    }
    return ja;
}

/*
 * Gather all local, distro, and built-in profiles in a JSON map and print
 * to stdout.
 *
 * @swtpm_prg_l: Array of strings to invoke swtpm (e.g., 'swtpm socket')
 * @config_file_line: Lines of the configuratin file
 *
 * Returns the number of bytes printed.
 */
int profile_printall(const gchar **swtpm_prg_l,
                     gchar *const *config_file_lines)
{
    g_autoptr(JsonGenerator) jg = NULL;
    g_autoptr(JsonObject) jo = NULL;
    g_autoptr(JsonNode) root = NULL;
    g_autofree gchar *out = NULL;
    JsonArray *ja;

    jo = json_object_new();

    ja = profile_gather_local(config_file_lines);
    if (ja)
        json_object_set_array_member(jo, "local", ja);

    ja = profile_gather_dir(DATAROOTDIR "swtpm/profiles");
    if (ja)
        json_object_set_array_member(jo, "distro", ja);

    ja = profile_gather_builtin(swtpm_prg_l);
    if (ja)
        json_object_set_array_member(jo, "builtin", ja);

    root = json_node_new(JSON_NODE_OBJECT);
    json_node_set_object(root, jo);

    jg = json_generator_new();
    json_generator_set_root(jg, root);

    out = json_generator_to_data(jg, NULL);
    return printf("%s\n", out);
}
