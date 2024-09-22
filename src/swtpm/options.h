/*
 * options.h -- Option parsing
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

#ifndef _SWTPM_OPTIONS_H
#define _SWTPM_OPTIONS_H


#include <stdbool.h>
#include <sys/stat.h> /* FreeBSD for mode_t */

enum OptionType {
    OPT_TYPE_STRING,
    OPT_TYPE_INT,
    OPT_TYPE_UINT,
    OPT_TYPE_BOOLEAN,
    OPT_TYPE_MODE_T,
    OPT_TYPE_UID_T,
    OPT_TYPE_GID_T,
};

typedef struct {
    enum OptionType type;
    const char *name;
    union {
        char *string;
        int integer;
        unsigned int uinteger;
        bool boolean;
        mode_t mode;
        uid_t uid;
        gid_t gid;
    }u;
} OptionValue;

typedef struct {
    size_t n_options;
    OptionValue *options;
} OptionValues;

typedef struct {
   const char *name;
   enum OptionType type;
} OptionDesc;

#define END_OPTION_DESC \
    { \
        .name = NULL, \
    }

OptionValues *options_parse(const char *opts, const OptionDesc optdesc[],
                            char **error);
void option_values_free(OptionValues *ov);
const char *option_get_string(OptionValues *ovs, const char *name,
                              const char *def);
int option_get_int(OptionValues *ovs, const char *name, int def);
unsigned int option_get_uint(OptionValues *ovs, const char *name, unsigned int def);
bool option_get_bool(OptionValues *ovs, const char *name, bool def);
mode_t option_get_mode_t(OptionValues *ovs, const char *name, mode_t def);
uid_t option_get_uid_t(OptionValues *ovs, const char *name, uid_t def);
gid_t option_get_gid_t(OptionValues *ovs, const char *name, gid_t def);

#endif /* _SWTPM_OPTIONS_H */
