/* SPDX-License-Identifier: BSD-3-Clause */

/*
 * profile.c: Functions for handling profiles
 *
 * Author: Stefan Berger, stefanb@linux.ibm.com
 *
 * Copyright (c) IBM Corporation, 2024
 */

#include "config.h"

#include <stdio.h>

#include "profile.h"
#include "utils.h"
#include "swtpm_utils.h"
#include "check_algos.h"

/*
 * If the given profile is the 'custom' profile then remove algorithms and key
 * sizes disabled by FIPS (in OpenSSL).
 *
 * @json_profile: Pointer to the string with the JSON profile
 * @check: Whether to check wheter the 'candidate' algorithms are actually
 *         disabled and only remove from profile if disabled.
 *
 * Return values:
 * 0 : no error
 * 1 : fatal error
 * 2 : this is not the 'custom' profile
 */
int profile_remove_fips_disabled_algorithms(char **json_profile,
                                            gboolean force)
{
    g_autofree gchar *info_data = NULL;
    g_auto(GStrv) algorithms = NULL;
    g_auto(GStrv) attributes = NULL;
    g_autofree gchar *value = NULL;
    int ret;

    ret = json_get_map_key_value(*json_profile, "Name", &value);
    if (ret || !value || strcmp(value, "custom"))
        return 2;

    SWTPM_G_FREE(value);
    ret = json_get_map_key_value(*json_profile, "Algorithms", &value);
    if (ret == 1)
        return 1;

    if (ret == 2) {
        info_data = TPMLIB_GetInfo(TPMLIB_INFO_RUNTIME_ALGORITHMS);

        ret = json_get_submap_value(info_data, "RuntimeAlgorithms", "Implemented",
                                    &value);
        if (ret)
            return 1;
    }
    algorithms = g_strsplit(value, ",", -1);
    if (check_ossl_fips_disabled_remove_algorithms(&algorithms, force))
        return 1;

    g_free(value);
    value = g_strjoinv(",", algorithms);

    /* put algorithms into JSON */
    ret = json_set_map_key_value(json_profile, "Algorithms", value);
    if (ret)
        return 1;

    SWTPM_G_FREE(value);
    /* disable sha1 signature and unpadded encryption using Attributes */
    ret = json_get_map_key_value(*json_profile, "Attributes", &value);
    if (ret == 1)
        return 1;

    if (value)
        attributes = g_strsplit(value, ",", -1);

    if (check_ossl_fips_disabled_set_attributes(&attributes, force))
        return 1;

    g_free(value);
    if (attributes) {
        value = g_strjoinv(",", attributes);

        ret = json_set_map_key_value(json_profile, "Attributes", value);
        if (ret)
            return 1;
    }

    return 0;
}
