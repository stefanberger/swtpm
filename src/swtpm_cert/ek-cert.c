/*
 * ek-cert.c
 *
 * Authors: Stefan Berger <stefanb@us.ibm.com>
 *
 * (c) Copyright IBM Corporation 2014, 2015, 2020.
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

/*
 * Note: The construction of the certificate follows the TCG Credential
 *       Profile for TPM Family 1.2; Level 2 Unified Trust Certificate
 *       in section 3.5
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/stat.h>

#include <arpa/inet.h>

#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>

#include <gmp.h>

#include "sys_dependencies.h"
#include "tpm_asn1.h"
#include "swtpm.h"
#include "compiler_dependencies.h"

enum cert_type_t {
    CERT_TYPE_EK = 1,
    CERT_TYPE_PLATFORM,
    CERT_TYPE_AIK,
    CERT_TYPE_IAK,
    CERT_TYPE_IDEVID,
};

/* some flags */
#define CERT_TYPE_TPM2_F 1
#define ALLOW_SIGNING_F  2 /* EK can be used for signing */
#define DECRYPTION_F     4 /* EK can be used for decryption; default */

extern const asn1_static_node tpm_asn1_tab[];

asn1_node _tpm_asn;

typedef struct tdTCG_PCCLIENT_STORED_CERT {
    uint16_t tag;
    uint8_t certType;
    uint16_t certSize;
} __attribute__((packed)) tdTCG_PCCLIENT_STORED_CERT;

typedef struct TCG_PCCLIENT_STORED_FULL_CERT_HEADER {
    tdTCG_PCCLIENT_STORED_CERT stored_cert;
    uint16_t tag;
} __attribute__((packed)) TCG_PCCLIENT_STORED_FULL_CERT_HEADER;

#define TCG_TAG_PCCLIENT_STORED_CERT 0x1001
#define TCG_TAG_PCCLIENT_FULL_CERT 0x1002

static void
versioninfo()
{
    fprintf(stdout,
        "TPM certificate tool version %d.%d.%d, Copyright (c) 2015 IBM Corp.\n"
        ,SWTPM_VER_MAJOR, SWTPM_VER_MINOR, SWTPM_VER_MICRO);
}

static void
usage(const char *prg)
{
    versioninfo();
    fprintf(stdout,
        "\nUsage: %s [options]\n"
        "\n"
        "Create TPM certificates without requiring the EK private key.\n"
        "\n"
        "The following options are supported:\n"
        "--pubkey <filename>       : PEM file for public key (EK)\n"
        "--signkey <filename>      : PEM file for CA signing key or GnuTLS TPM or\n"
        "                            PKCS11 URL\n"
        "--signkey-password <pass> : Password for the CA signing key\n"
        "--signkey-pwd <pwd>       : Alternative password option for CA signing key\n"
        "--parentkey-password <p>  : Password of parent key; SRK password of TPM\n"
        "--parentkey-pwd <pwd>     : Alternative password option for SRK password\n"
        "--issuercert <filename>   : PEM file with CA cert\n"
        "--out-cert <filename>     : Filename for certificate\n"
        "--modulus <hex string>    : The modulus of the public key\n"
        "--exponent <exponent>     : The exponent of the public key\n"
        "--ecc-x                   : ECC key x component\n"
        "--ecc-y                   : ECC key y component\n"
        "--ecc-curveid <id>        : ECC curve id; secp256r1, secp384r1, secp521r1\n"
        "                            default: secp256r1\n"
        "--serial <serial number>  : The certificate serial number\n"
        "--days <number>           : Number of days the cert is valid;\n"
        "                            -1 for no expiration\n"
        "--pem                     : Write certificate in PEM format; default is DER\n"
        "--type <platform|ek>      : The type of certificate to create; default is ek\n"
        "                            Other options are platform, iak, idevid\n"
        "--tpm-manufacturer <name> : The name of the TPM manufacturer\n"
        "--tpm-model <model>       : The TPM model (part number)\n"
        "--tpm-version <version>   : The TPM version (firmware version)\n"
        "--tpm-serial-num <s>      : The TPM serial number; required for IAK and IDevID\n"
        "--platform-manufacturer <name> : The name of the Platform manufacturer\n"
        "--platform-model <model>       : The Platform model (part number)\n"
        "--platform-version <version>   : The Platform version (firmware version)\n"
        "--tpm-spec-family <family>     : Specification family (string)\n"
        "--tpm-spec-level <level>       : Specification level (integer)\n"
        "--tpm-spec-revision <rev>      : Specification revision (integer)\n"
        "--subject <subject>       : Subject such as location in format\n"
        "                            C=US,ST=NY,L=NewYork; not used with TPM1.2\n"
        "--add-header              : Add the TCG certificate header describing\n"
        "                            a TCG_PCCLIENT_STORED_CERT for TPM1.2 NVRAM\n"
        "--tpm2                    : Issue a TPM 2 compliant certificate\n"
        "--allow-signing           : The EK of a TPM 2 allows signing;\n"
        "                            requires --tpm2\n"
        "--decryption              : The EK if a TPM 2 can be used for key\n"
        "                            encipherment; requires --tpm2\n"
        "--print-capabilities      : Print capabilities and exit\n"
        "--version                 : Display version and exit\n"
        "--help                    : Display this help screen and exit\n"
        "\n"
        "The following environment variables are supported:\n"
        "\n"
        "SWTPM_PKCS11_PIN              : PKCS11 PIN to use\n"
        "\n"
        "Password passed in 'pwd' options support the following formats:\n"
        "- <password>           : direct password\n"
        "- pass:<password>      : direct password\n"
        "- fd:<file descriptor> : read password from file descriptor\n"
        "- file:<filename>      : read password from filename\n"
        "- env:<env. varname>   : read from environment variable\n"
        , prg);
}

static char
hex_to_str(char digit) {
    char value = -1;

    if (digit >= '0' && digit <= '9') {
        value = digit - '0';
    } else if (digit >= 'a' && digit <= 'f') {
        value = digit - 'a' + 10;
    } else if (digit >= 'A' && digit <= 'F') {
        value = digit - 'A' + 10;
    }

    return value;
}

static unsigned char *
hex_str_to_bin(const char *hexstr, int *modulus_len)
{
    int len;
    unsigned char *result;
    int i = 0, j = 0;
    char val1, val2;

    len = strlen(hexstr);

    if ((len & 1) != 0) {
        fprintf(stderr, "Got an odd number of hex digits (%d).\n", len);
        fprintf(stderr, "    hex digits: %s\n", hexstr);
        return NULL;
    }

    result = malloc(len / 2);
    if (result == NULL) {
        fprintf(stderr, "Out of memory trying to allocated %d bytes.", len / 2);
        return NULL;
    }
    i = 0;
    j = 0;

    while (i < len) {
        val1 = hex_to_str(hexstr[i]);
        if (val1 < 0) {
            fprintf(stderr, "Illegal hex character '%c'.", hexstr[i]);
            free(result);
            return NULL;
        }
        i++;
        val2 = hex_to_str(hexstr[i]);
        if (val2 < 0) {
            fprintf(stderr, "Illegal hex character '%c'.", hexstr[i]);
            free(result);
            return NULL;
        }
        i++;
        result[j++] = (val1 << 4) | val2;
    }
    *modulus_len = j;

    return result;
}

static gnutls_pubkey_t
create_rsa_from_modulus(unsigned char *modulus, unsigned int modulus_len,
                        uint32_t exponent)
{
    unsigned char exp_array[4];
    uint32_t exponent_no = htonl(exponent);
    gnutls_pubkey_t rsa = NULL;
    gnutls_datum_t mod;
    gnutls_datum_t exp = {
        .data = exp_array,
        .size = sizeof(exp_array),
    };
    int err;

    memcpy(exp_array, &exponent_no, sizeof(exp_array));

    err = gnutls_pubkey_init(&rsa);
    if (err < 0) {
        fprintf(stderr, "Could not initialized public key structure : %s\n",
                gnutls_strerror(err));
        return NULL;
    }

    mod.data = modulus;
    mod.size = modulus_len;

    err = gnutls_pubkey_import_rsa_raw(rsa, &mod, &exp);
    if (err < 0) {
        fprintf(stderr, "Could not set modulus and exponent on RSA key : %s\n",
                gnutls_strerror(err));
        gnutls_pubkey_deinit(rsa);
        rsa = NULL;
    }

    return rsa;
}

static gnutls_pubkey_t
create_ecc_from_x_and_y(unsigned char *ecc_x, unsigned int ecc_x_len,
                        unsigned char *ecc_y, unsigned int ecc_y_len,
                        const char *ecc_curveid)
{
    gnutls_pubkey_t rsa = NULL;
    int err;
    gnutls_datum_t x = {
        .data = ecc_x,
        .size = ecc_x_len,
    };
    gnutls_datum_t y = {
        .data = ecc_y,
        .size = ecc_y_len,
    };
    gnutls_ecc_curve_t curve;

    err = gnutls_pubkey_init(&rsa);
    if (err < 0) {
        fprintf(stderr, "Could not initialized public key structure : %s\n",
                gnutls_strerror(err));
        return NULL;
    }

    if (ecc_curveid == NULL || !strcmp(ecc_curveid, "secp256r1")) {
        curve = GNUTLS_ECC_CURVE_SECP256R1;
    } else if (!strcmp(ecc_curveid, "secp384r1")) {
        curve = GNUTLS_ECC_CURVE_SECP384R1;
    } else if (!strcmp(ecc_curveid, "secp521r1")) {
        curve = GNUTLS_ECC_CURVE_SECP521R1;
    } else {
        fprintf(stderr, "Unsupported ECC curve id: %s\n", ecc_curveid);
        return NULL;
    }

    err = gnutls_pubkey_import_ecc_raw(rsa, curve, &x, &y);
    if (err < 0) {
        fprintf(stderr, "Could not set x and y on ECC key : %s\n",
                gnutls_strerror(err));
        gnutls_pubkey_deinit(rsa);
        rsa = NULL;
    }

    return rsa;
}

static int
asn_init()
{
    static bool inited;
    int err;

    if (inited)
        return ASN1_SUCCESS;

    err = asn1_array2tree(tpm_asn1_tab, &_tpm_asn, NULL);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "array2tree error: %d", err);
        goto cleanup;
    }

    inited = true;

cleanup:

    return err;
}

static void
asn_free(void)
{
    if (_tpm_asn)
        asn1_delete_structure(&_tpm_asn);
}

static int
encode_asn1(gnutls_datum_t *asn1, asn1_node at)
{
    int err;

    /* determine needed size of byte array */
    asn1->size = 0;
    err = asn1_der_coding(at, "", NULL, (int *)&asn1->size, NULL);
    if (err != ASN1_MEM_ERROR) {
        fprintf(stderr, "1. asn1_der_coding error: %d\n", err);
        return err;
    }

    asn1->data = gnutls_malloc(asn1->size + 16);
    if (!asn1->data) {
        fprintf(stderr, "2. Could not allocate memory\n");
        return ASN1_MEM_ERROR;
    }

    err = asn1_der_coding(at, "", asn1->data, (int *)&asn1->size, NULL);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "3. asn1_der_coding error: %d\n", err);
        gnutls_free(asn1->data);
        asn1->data = NULL;
    }
    return err;
}

static int
build_tpm_manufacturer_info(asn1_node *at,
                            const char *manufacturer,
                            const char *tpm_model,
                            const char *tpm_version)
{
    int err;

    err = asn1_create_element(_tpm_asn, "TPM.TPMManufacturerInfo", at);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "asn1_create_element error: %d\n", err);
        goto cleanup;
    }

    err = asn1_write_value(*at, "tpmManufacturerSet.tpmManufacturer.?LAST",
                           "NEW", 0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "1a. asn1_write_value error: %d\n", err);
        goto cleanup;
    }

    err = asn1_write_value(*at, "tpmManufacturerSet.tpmManufacturer.id",
                           "2.23.133.2.1", 0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "1b. asn1_write_value error: %d\n", err);
        goto cleanup;
    }

    err = asn1_write_value(*at,
                           "tpmManufacturerSet.tpmManufacturer.manufacturer",
                           manufacturer, 0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "2. asn1_write_value error: %d\n", err);
        goto cleanup;
    }

    err = asn1_write_value(*at, "tpmModelSet.tpmModel.?LAST", "NEW", 0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "3a. asn1_write_value error: %d\n", err);
        goto cleanup;
    }

    err = asn1_write_value(*at, "tpmModelSet.tpmModel.id", "2.23.133.2.2", 0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "3b. asn1_write_value error: %d\n", err);
        goto cleanup;
    }

    err = asn1_write_value(*at, "tpmModelSet.tpmModel.model", tpm_model, 0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "4. asn1_write_value error: %d\n", err);
        goto cleanup;
    }

    err = asn1_write_value(*at, "tpmVersionSet.tpmVersion.?LAST", "NEW", 0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "5a. asn1_write_value error: %d\n", err);
        goto cleanup;
    }

    err = asn1_write_value(*at, "tpmVersionSet.tpmVersion.id", "2.23.133.2.3",
                           0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "5b. asn1_write_value error: %d\n", err);
        goto cleanup;
    }

    err = asn1_write_value(*at, "tpmVersionSet.tpmVersion.version", tpm_version, 0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "6. asn1_write_value error: %d\n", err);
        goto cleanup;
    }

cleanup:
    return err;
}

static int
create_tpm_manufacturer_info(const char *manufacturer,
                             const char *tpm_model,
                             const char *tpm_version,
                             gnutls_datum_t *asn1)
{
    asn1_node at = NULL;
    int err;

    err = asn_init();
    if (err != ASN1_SUCCESS) {
        goto cleanup;
    }

    err = build_tpm_manufacturer_info(&at, manufacturer,
                                      tpm_model, tpm_version);
    if (err != ASN1_SUCCESS) {
        goto cleanup;
    }

    err = encode_asn1(asn1, at);

#if 0
    fprintf(stderr, "size=%d\n", asn1->size);
    unsigned int i = 0;
    for (i = 0; i < asn1->size; i++) {
        fprintf(stderr, "%02x ", asn1->data[i]);
    }
    fprintf(stderr, "\n");
#endif

 cleanup:
    asn1_delete_structure(&at);

    return err;
}

static int
build_platf_manufacturer_info(asn1_node *at,
                              const char *manufacturer,
                              const char *platf_model,
                              const char *platf_version,
                              bool forTPM2)
{
    int err;

    err = asn1_create_element(_tpm_asn, "TPM.PlatformManufacturerInfo", at);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "asn1_create_element error: %d\n", err);
        goto cleanup;
    }

    err = asn1_write_value(*at, "platformManufacturerSet.platformManufacturer.?LAST",
                           "NEW", 0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "b1a. asn1_write_value error: %d\n", err);
        goto cleanup;
    }

    err = asn1_write_value(*at, "platformManufacturerSet.platformManufacturer.id",
                           forTPM2 ? "2.23.133.5.1.1"
                                   : "2.23.133.2.4",
                           0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "b1b. asn1_write_value error: %d\n", err);
        goto cleanup;
    }

    err = asn1_write_value(*at, "platformManufacturerSet.platformManufacturer.manufacturer",
                           manufacturer, 0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "b2. asn1_write_value error: %d\n", err);
        goto cleanup;
    }

    err = asn1_write_value(*at, "platformModelSet.platformModel.?LAST",
                           "NEW", 0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "b3a. asn1_write_value error: %d\n", err);
        goto cleanup;
    }

    err = asn1_write_value(*at, "platformModelSet.platformModel.id",
                           forTPM2 ? "2.23.133.5.1.4"
                                   : "2.23.133.2.5",
                           0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "b3b. asn1_write_value error: %d\n", err);
        goto cleanup;
    }

    err = asn1_write_value(*at, "platformModelSet.platformModel.model",
                           platf_model, 0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "b4. asn1_write_value error: %d\n", err);
        goto cleanup;
    }

    err = asn1_write_value(*at, "platformVersionSet.platformVersion.?LAST",
                           "NEW", 0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "b5a. asn1_write_value error: %d\n", err);
        goto cleanup;
    }

    err = asn1_write_value(*at, "platformVersionSet.platformVersion.id",
                           forTPM2 ? "2.23.133.5.1.5"
                                   : "2.23.133.2.6",
                           0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "b5b. asn1_write_value error: %d\n", err);
        goto cleanup;
    }

    err = asn1_write_value(*at, "platformVersionSet.platformVersion.version",
                           platf_version, 0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "b6. asn1_write_value error: %d\n", err);
        goto cleanup;
    }

cleanup:
    return err;
}

static int
create_platf_manufacturer_info(const char *manufacturer,
                               const char *platf_model,
                               const char *platf_version,
                               gnutls_datum_t *asn1,
                               bool forTPM2)
{
    asn1_node at = NULL;
    int err;

    err = asn_init();
    if (err != ASN1_SUCCESS) {
        goto cleanup;
    }

    err = build_platf_manufacturer_info(&at, manufacturer,
                                        platf_model, platf_version,
                                        forTPM2);
    if (err != ASN1_SUCCESS) {
        goto cleanup;
    }

    err = encode_asn1(asn1, at);

#if 0
    fprintf(stderr, "size=%d\n", asn1->size);
    unsigned int i = 0;
    for (i = 0; i < asn1->size; i++) {
        fprintf(stderr, "%02x ", asn1->data[i]);
    }
    fprintf(stderr, "\n");
#endif

 cleanup:
    asn1_delete_structure(&at);

    return err;
}

static int
create_tpm_and_platform_manuf_info(
                               const char *tpm_manufacturer,
                               const char *tpm_model,
                               const char *tpm_version,
                               const char *platf_manufacturer,
                               const char *platf_model,
                               const char *platf_version,
                               gnutls_datum_t *asn1,
                               bool forTPM2)
{
    asn1_node at = NULL;
    asn1_node tpm_at = NULL;
    asn1_node platf_at = NULL;
    int err;
    gnutls_datum_t datum = {
        .data = NULL,
        .size = 0,
    };

    err = asn_init();
    if (err != ASN1_SUCCESS) {
        goto cleanup;
    }

    err = asn1_create_element(_tpm_asn, "TPM.PlatformCertificateSAN", &at);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "%s: %d:  asn1_create_element error: %s\n",
                __func__, __LINE__, asn1_strerror(err));
        goto cleanup;
    }

    /* build the TPM manufacturer data */
    err = build_tpm_manufacturer_info(&tpm_at, tpm_manufacturer,
                                      tpm_model, tpm_version);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "%s: %d: Could not build TPM manufacturer info: %s\n",
                __func__, __LINE__, asn1_strerror(err));
        goto cleanup;
    }

    err = encode_asn1(&datum, tpm_at);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "%s: %d: Could not encode TPM data as ASN.1: %s\n",
                __func__, __LINE__, asn1_strerror(err));
        goto cleanup;
    }

    err = asn1_write_value(at, "", "NEW", 1);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "%s: %d: Could not create a NEW element: %s\n",
                __func__, __LINE__, asn1_strerror(err));
        goto cleanup;
    }

    err = asn1_write_value(at, "?1", datum.data, datum.size);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "%s: %d: Could not write 1st element: %s!\n",
                __func__, __LINE__, asn1_strerror(err));
        goto cleanup;
    }
    gnutls_free(datum.data);
    datum.data = NULL;

    /* build the platform manufacturer data */
    err = build_platf_manufacturer_info(&platf_at, platf_manufacturer,
                                        platf_model, platf_version,
                                        forTPM2);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "%s: %d: Could not build platform manufacturer info: %s\n",
                __func__, __LINE__, asn1_strerror(err));
        goto cleanup;
    }

    err = encode_asn1(&datum, platf_at);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "%s: %d: Could not encode platform data as ASN.1: %s\n",
                __func__, __LINE__, asn1_strerror(err));
        goto cleanup;
    }

    err = asn1_write_value(at, "", "NEW", 1);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "%s: %d: Could not create a NEW element: %s\n",
                __func__, __LINE__, asn1_strerror(err));
        goto cleanup;
    }

    err = asn1_write_value(at, "?2", datum.data, datum.size);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "%s: %d: Could not write 2nd element: %s!\n",
                __func__, __LINE__, asn1_strerror(err));
        goto cleanup;
    }

    gnutls_free(datum.data);
    datum.data = NULL;

    err = encode_asn1(asn1, at);

#if 0
    fprintf(stderr, "size=%d\n", asn1->size);
    unsigned int i = 0;
    for (i = 0; i < asn1->size; i++) {
        fprintf(stderr, "%02x ", asn1->data[i]);
    }
    fprintf(stderr, "\n");
#endif

 cleanup:
    gnutls_free(datum.data);
    asn1_delete_structure(&at);
    asn1_delete_structure(&platf_at);
    asn1_delete_structure(&tpm_at);

    return err;
}

static int
create_tpm_specification_info(const char *spec_family,
                              unsigned int spec_level,
                              unsigned int spec_revision,
                              gnutls_datum_t *asn1)
{
    asn1_node at = NULL;
    int err;
    unsigned int bigendian;
    unsigned char twoscomp[1 + sizeof(bigendian)] = { 0, };

    err = asn_init();
    if (err != ASN1_SUCCESS) {
        goto cleanup;
    }

    err = asn1_create_element(_tpm_asn, "TPM.TPMSpecificationInfo", &at);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "asn1_create_element error: %d\n", err);
        goto cleanup;
    }

    err = asn1_write_value(at, "tpmSpecificationSeq.id", "2.23.133.2.16", 0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "c1b. asn1_write_value error: %d\n", err);
        goto cleanup;
    }

    err = asn1_write_value(at,
        "tpmSpecificationSeq.tpmSpecificationSet.tpmSpecification.family",
        spec_family, 0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "c1c. asn1_write_value error: %d\n", err);
        goto cleanup;
    }

    bigendian = htobe32(spec_level);
    memcpy(&twoscomp[1], &bigendian, sizeof(bigendian));

    err = asn1_write_value(at,
        "tpmSpecificationSeq.tpmSpecificationSet.tpmSpecification.level",
        twoscomp, sizeof(twoscomp));
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "c1d. asn1_write_value error: %d\n", err);
        goto cleanup;
    }

    bigendian = htobe32(spec_revision);
    memcpy(&twoscomp[1], &bigendian, sizeof(bigendian));

    err = asn1_write_value(at,
        "tpmSpecificationSeq.tpmSpecificationSet.tpmSpecification.revision",
        twoscomp, sizeof(twoscomp));
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "c1e. asn1_write_value error: %d\n", err);
        goto cleanup;
    }

    err = encode_asn1(asn1, at);

#if 0
    fprintf(stderr, "size=%d\n", asn1->size);
    unsigned int i = 0;
    for (i = 0; i < asn1->size; i++) {
        fprintf(stderr, "%02x ", asn1->data[i]);
    }
    fprintf(stderr, "\n");
#endif

 cleanup:
    asn1_delete_structure(&at);

    return err;
}

static int
create_iak_info(gnutls_datum_t *asn1,
                const char *hwSerialNum)
{
    asn1_node at = NULL;
    int err;

    err = asn_init();
    if (err != ASN1_SUCCESS) {
        goto cleanup;
    }

    err = asn1_create_element(_tpm_asn, "TPM.TPMIAKSanInfo", &at);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "1cia. asn1_create_element error: %d\n", err);
        goto cleanup;
    }

    err = asn1_write_value(at, "tpmIAKSanInfoSeq.id", "1.3.6.1.5.5.7.8.4", 0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "2cia. asn1_write_value error: %d\n", err);
        goto cleanup;
    }

    err = asn1_write_value(at, "tpmIAKSanInfoSeq.iakSanInfoSet.hwType", "2.23.133.1.2", 0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "3cia. asn1_write_value error: %d\n", err);
        goto cleanup;
    }

    err = asn1_write_value(at, "tpmIAKSanInfoSeq.iakSanInfoSet.hwSerialNum", hwSerialNum, 0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "4cia. asn1_write_value error: %d\n", err);
        goto cleanup;
    }

    err = encode_asn1(asn1, at);

#if 0
    fprintf(stderr, "size=%d\n", asn1->size);
    unsigned int i = 0;
    for (i = 0; i < asn1->size; i++) {
        fprintf(stderr, "%02x ", asn1->data[i]);
    }
    fprintf(stderr, "\n");
#endif

 cleanup:
    asn1_delete_structure(&at);
    return err;
}


static int
create_cert_extended_key_usage(const char *oid, gnutls_datum_t *asn1)
{
    asn1_node at = NULL;
    int err;

    err = asn_init();
    if (err != ASN1_SUCCESS) {
        goto cleanup;
    }

    err = asn1_create_element(_tpm_asn, "TPM.TPMEKCertExtendedKeyUsage", &at);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "asn1_create_element error: %d\n", err);
        goto cleanup;
    }

    err = asn1_write_value(at, "id", oid, 0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "d1. asn1_write_value error: %d\n", err);
        goto cleanup;
    }

    err = encode_asn1(asn1, at);

#if 0
    fprintf(stderr, "size=%d\n", asn1->size);
    unsigned int i = 0;
    for (i = 0; i < asn1->size; i++) {
        fprintf(stderr, "%02x ", asn1->data[i]);
    }
    fprintf(stderr, "\n");
#endif

 cleanup:
    asn1_delete_structure(&at);

    return err;
}

/*
 * prepend_san_asn1_header -- prepend a SAN ASN.1 header on the data
 *
 * This function with prepend something like this:
 *  0x30 <subsequent length> 0xa4 <subsequent length>
 */
static int prepend_san_asn1_header(gnutls_datum_t *datum)
{
    int err = GNUTLS_E_SUCCESS;
    unsigned char buffer[2 * (1 + 1 + sizeof(unsigned long))];
    unsigned i = sizeof(buffer);
    unsigned long size;
    unsigned char intlen;
    unsigned char *data = datum->data;

    /* write backwards */
    intlen = 0;
    size = datum->size;
    do {
        buffer[--i] = (size & 0xff);
        size >>= 8;
        intlen++;
    } while (size);
    /*
     * short form for values 0x00 .. 0x7f
     * long form for anything larger
     */
    if (intlen > 1 || buffer[i] & 0x80)
        buffer[--i] = intlen | 0x80;
    /* write equivalent of 0xa4 */
    buffer[--i] = ASN1_CLASS_CONTEXT_SPECIFIC | ASN1_CLASS_STRUCTURED |
                  ASN1_TAG_OCTET_STRING;

    size = datum->size + sizeof(buffer) - i;
    intlen = 0;
    do {
        buffer[--i] = (size & 0xff);
        size >>= 8;
        intlen++;
    } while (size);
    if (intlen > 1 || buffer[i] & 0x80)
        buffer[--i] = intlen | 0x80;
    /* write equivalent of 0x30 */
    buffer[--i] = ASN1_CLASS_STRUCTURED | ASN1_TAG_SEQUENCE;

    datum->data = gnutls_malloc(datum->size + sizeof(buffer) - i);
    if (datum->data == NULL) {
        err = GNUTLS_E_MEMORY_ERROR;
        goto exit;
    }

    memcpy(datum->data, &buffer[i], sizeof(buffer) - i);
    memcpy(&datum->data[sizeof(buffer) - i], data, datum->size);
    datum->size = sizeof(buffer) - i + datum->size;

exit:
    gnutls_free(data);
    return err;
}

static int mypinfunc(void *userdata SWTPM_ATTR_UNUSED,
                     int attempt SWTPM_ATTR_UNUSED,
                     const char *tokenurl SWTPM_ATTR_UNUSED,
                     const char *token_label SWTPM_ATTR_UNUSED,
                     unsigned int flags SWTPM_ATTR_UNUSED,
                     char *pin, size_t pin_max)
{
    const char *userpin = getenv("SWTPM_PKCS11_PIN");

    if (!userpin)
        return -1;

    strncpy(pin, userpin, pin_max - 1);
    pin[pin_max - 1] = 0;

    return 0;
}

/*
 * Get the password from the password parameter, which may have one of the
 * following formats:
 * <password>
 * pass:<password>
 * fd:<file descriptor>
 * file:<filename>
 * env:<environment variable>
 * Any password read from files must not exceed 256 bytes including
 * terminating 0 byte.
 */
static char *get_password(const char *password)
{
    char *result;
    char *endptr;
    int fd;
    char buffer[256];
    ssize_t n;
    const char *tocopy;

    if (!strncmp(password, "fd:", 3)) {
        errno = 0;
        fd = strtol(&password[3], &endptr, 10);
        if (errno != 0 || fd < 0 || endptr == &password[3] || *endptr != 0) {
            fprintf(stderr, "Bad file descriptor for password.\n");
            return NULL;
        }
        goto readfd;
    } else if (!strncmp(password, "file:", 5)) {
        fd = open(&password[5], O_RDONLY);
        if (fd < 0) {
            fprintf(stderr, "Could not open password file for reading: %s\n",
                    strerror(errno));
            return NULL;
        }
readfd:
        n = read(fd, buffer, sizeof(buffer) - 1);
        close(fd);
        if (n < 0) {
            fprintf(stderr, "Could not read password from file descriptor: %s\n",
                    strerror(errno));
            return NULL;
        }
        buffer[n] = 0;
        tocopy = buffer;
    } else if (!strncmp(password, "pass:", 5)) {
        tocopy = &password[5];
    } else if (!strncmp(password, "env:", 4)) {
        tocopy = getenv(&password[4]);
        if (tocopy == NULL) {
            fprintf(stderr, "Could not get password from environment variable\n");
            return NULL;
        }
    } else {
        tocopy = password;
    }

    result = strdup(tocopy);
    if (!result)
        fprintf(stderr, "Out of memory.\n");

    return result;
}

static void capabilities_print_json()
{
    fprintf(stdout,
            "{ "
            "\"type\": \"swtpm_cert\", "
            "\"features\": [ "
             "\"cmdarg-signkey-pwd\""
             ", \"cmdarg-parentkey-pwd\""
             ", \"cmdarg-tpm-serial-num\""
             ", \"supports-iak-idevid\""
            " ], "
            "\"version\": \"" VERSION "\" "
            "}\n");
}

int
main(int argc, char *argv[])
{
    int ret = 1;
    gnutls_pubkey_t pubkey = NULL;
    gnutls_x509_privkey_t sigkey = NULL;
    gnutls_x509_crt_t sigcert = NULL;
    gnutls_x509_crt_t crt = NULL;
    gnutls_privkey_t tpmkey = NULL, pkcs11key = NULL;
    const char *pubkey_filename = NULL;
    const char *sigkey_filename = NULL;
    const char *cert_filename = NULL;
    const char *issuercert_filename = NULL;
    unsigned char *modulus_bin = NULL;
    int modulus_len = 0;
    unsigned char *ecc_x_bin = NULL;
    int ecc_x_len = 0;
    unsigned char *ecc_y_bin = NULL;
    int ecc_y_len = 0;
    const char *ecc_curveid = NULL;
    gnutls_datum_t datum = { NULL, 0},  out = { NULL, 0};
    gnutls_digest_algorithm_t hashAlgo = GNUTLS_DIG_SHA1;
    mpz_t serial;
    time_t now;
    int err;
    int cert_file_fd;
    const char *subject = NULL;
    const char *error = NULL;
    int days = 365;
    time_t exp_time;
    char *sigkeypass = NULL;
    char *parentkeypass = NULL;
    unsigned char ser_number[21];
    size_t ser_number_len;
    long int exponent = 0x10001;
    bool write_pem = false;
    uint8_t id[512];
    size_t id_size = sizeof(id);
    enum cert_type_t certtype = CERT_TYPE_EK;
    const char *oid;
    unsigned int key_usage = 0;
    const char *tpm_manufacturer = NULL;
    const char *tpm_version = NULL;
    const char *tpm_model = NULL;
    const char *tpm_serial_num = NULL;
    const char *platf_manufacturer = NULL;
    const char *platf_version = NULL;
    const char *platf_model = NULL;
    bool add_header = false;
    const char *spec_family = NULL;
    long int spec_level = ~0;
    long int spec_revision = ~0;
    int flags = 0;
    bool is_ecc = false;
    static struct option long_options[] = {
        {"pubkey", required_argument, NULL, 'p'},
        {"modulus", required_argument, NULL, 'm'},
        {"ecc-x", required_argument, NULL, 'x'},
        {"ecc-y", required_argument, NULL, 'y'},
        {"ecc-curveid", required_argument, NULL, 'z'},
        {"exponent", required_argument, NULL, 'e'},
        {"signkey", required_argument, NULL, 's'},
        {"signkey-password", required_argument, NULL, 'S'},
        {"signkey-pwd", required_argument, NULL, 'T'},
        {"parentkey-passord", required_argument, NULL, 'P'},
        {"parentkey-pwd", required_argument, NULL, 'Q'},
        {"issuercert", required_argument, NULL, 'i'},
        {"out-cert", required_argument, NULL, 'o'},
        {"subject", required_argument, NULL, 'u'},
        {"days", required_argument, NULL, 'd'},
        {"serial", required_argument, NULL, 'r'},
        {"type", required_argument, NULL, 't'},
        {"tpm-manufacturer", required_argument, NULL, '1'},
        {"tpm-model", required_argument, NULL, '2'},
        {"tpm-version", required_argument, NULL, '3'},
        {"tpm-serial-num", required_argument, NULL, '0'},
        {"platform-manufacturer", required_argument, NULL, '4'},
        {"platform-model", required_argument, NULL, '5'},
        {"platform-version", required_argument, NULL, '6'},
        {"tpm-spec-family", required_argument, NULL, '7'},
        {"tpm-spec-level", required_argument, NULL, '8'},
        {"tpm-spec-revision", required_argument, NULL, '9'},
        {"pem", no_argument, NULL, 'M'},
        {"add-header", no_argument, NULL, 'a'},
        {"tpm2", no_argument, NULL, 'X'},
        {"allow-signing", no_argument, NULL, 'A'},
        {"decryption", no_argument, NULL, 'D'},
        {"print-capabilities", no_argument, NULL, 'c'},
        {"version", no_argument, NULL, 'v'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    int opt, option_index = 0;

    mpz_init(serial);
    mpz_set_ui(serial, 1);

#ifdef __NetBSD__
    while ((opt = getopt_long(argc, argv,
                    "p:m:x:y:z:e:s:S:T:P:Q:i:o:u:d:r:1:2:3:4:5:6:7:8:9:MaXADcvh",
                    long_options, &option_index)) != -1) {
#else
    while ((opt = getopt_long_only(argc, argv, "", long_options,
                                   &option_index)) != -1) {
#endif
        switch (opt) {
        case 'p': /* --pubkey */
            pubkey_filename = optarg;
            break;
        case 'm': /* --modulus */
            free(modulus_bin);
            if (!(modulus_bin = hex_str_to_bin(optarg, &modulus_len))) {
                goto cleanup;
            }
            break;
        case 'x': /* --ecc-x */
            free(ecc_x_bin);
            if (!(ecc_x_bin = hex_str_to_bin(optarg, &ecc_x_len))) {
                goto cleanup;
            }
            break;
        case 'y': /* --ecc-y */
            free(ecc_y_bin);
            if (!(ecc_y_bin = hex_str_to_bin(optarg, &ecc_y_len))) {
                goto cleanup;
            }
            break;
        case 'z': /* --ecc-curveid */
            ecc_curveid = optarg;
            break;
        case 'e': /* --exponent */
            exponent = strtol(optarg, NULL, 0);
            if (exponent == 0) {
                fprintf(stderr, "Exponent is wrong and cannot be 0.\n");
                goto cleanup;
            }
            if ((unsigned long int)exponent > UINT_MAX) {
                fprintf(stderr, "Exponent must fit into 32bits.\n");
                goto cleanup;
            }
            break;
        case 's': /* --signkey */
            sigkey_filename = optarg;
            break;
        case 'S': /* --signkey-password */
            free(sigkeypass);
            sigkeypass = strdup(optarg);
            if (!sigkeypass) {
                fprintf(stderr, "Out of memory.\n");
                goto cleanup;
            }
            break;
        case 'T': /* --signkey-pwd */
            free(sigkeypass);
            sigkeypass = get_password(optarg);
            if (!sigkeypass)
                goto cleanup;
            break;
        case 'P': /* --parentkey-password */
            free(parentkeypass);
            parentkeypass = strdup(optarg);
            if (!parentkeypass) {
                fprintf(stderr, "Out of memory.\n");
                goto cleanup;
            }
            break;
        case 'Q': /* --parentkey-pwd */
            free(parentkeypass);
            parentkeypass = get_password(optarg);
            if (!parentkeypass)
                goto cleanup;
            break;
        case 'i': /* --issuercert */
            issuercert_filename = optarg;
            break;
        case 'o': /* --out-cert */
            cert_filename = optarg;
            break;
        case 'u': /* --subject */
            subject = optarg;
            break;
        case 'd': /* --days */
            days = atoi(optarg);
            break;
        case 'r': /* --serial */
            if (gmp_sscanf(optarg, "%Zd", serial) != 1) {
                fprintf(stderr, "Serial number is invalid.\n");
                goto cleanup;
            }
            break;
        case 't': /* --type */
            if (!strcasecmp(optarg, "ek")) {
                certtype = CERT_TYPE_EK;
            } else if (!strcasecmp(optarg, "platform")) {
                certtype = CERT_TYPE_PLATFORM;
            } else if (!strcasecmp(optarg, "iak")) {
                certtype = CERT_TYPE_IAK;
            } else if (!strcasecmp(optarg, "idevid")) {
                certtype = CERT_TYPE_IDEVID;
            } else {
                fprintf(stderr, "Unknown certificate type '%s'.\n",
                        optarg);
                goto cleanup;
            }
            break;
        case '1': /* --tpm-manufacturer */
            tpm_manufacturer = optarg;
            break;
        case '2': /* --tpm-model */
            tpm_model = optarg;
            break;
        case '3': /* --tpm-version */
            tpm_version = optarg;
            break;
        case '0': /* --tpm-serial-num */
            tpm_serial_num = optarg;
            break;
        case '4': /* --platform-manufacturer */
            platf_manufacturer = optarg;
            break;
        case '5': /* --platform-model */
            platf_model = optarg;
            break;
        case '6': /* --platform-version */
            platf_version = optarg;
            break;
        case '7': /* --tpm-spec-family */
            spec_family = optarg;
            break;
        case '8': /* --tpm-spec-level */
            spec_level = strtol(optarg, NULL, 0);
            if (spec_level < 0) {
                fprintf(stderr, "--tpm-spec-level must pass a positive number.\n");
                goto cleanup;
            }
            break;
        case '9': /* --tpm-spec-revision */
            spec_revision = strtol(optarg, NULL, 0);
            if (spec_revision < 0) {
                fprintf(stderr, "--tpm-spec-revision must pass a positive number.\n");
                goto cleanup;
            }
            break;
        case 'M': /* --pem */
            write_pem = true;
            break;
        case 'a': /* --add-header */
            add_header = true;
            break;
        case 'X': /* --tpm2 */
            flags |= CERT_TYPE_TPM2_F;
            break;
        case 'A': /* --allow-signing */
            flags |= ALLOW_SIGNING_F;
            break;
        case 'D': /* --decryption */
            flags |= DECRYPTION_F;
            break;
        case 'c': /* --print-capabilities */
            capabilities_print_json();
            exit(0);
        case 'v': /* --version */
            versioninfo();
            exit(0);
        case 'h': /* --help */
            usage(argv[0]);
            exit(0);
        default:
            usage(argv[0]);
            exit(1);
        }
    }

    if (flags & CERT_TYPE_TPM2_F)
        hashAlgo = GNUTLS_DIG_SHA256;

    if ((mpz_sizeinbase(serial, 2) + 7) / 8 > sizeof(ser_number) - 1) {
        fprintf(stderr, "Serial number is too large.\n");
        goto cleanup;
    }
    mpz_export(ser_number, &ser_number_len, 1, 1, 1, 0, serial);
    if (ser_number_len > sizeof(ser_number) - 1) {
        fprintf(stderr, "Serial number is too large.\n");
        goto cleanup;
    }
    /* serial number's highest bit must not indicate negative number */
    if (ser_number[0] & 0x7f) {
        memmove(&ser_number[1], &ser_number[0], ser_number_len);
        ser_number[0] = 0;
        ser_number_len++;
    }

    if (modulus_bin && (ecc_x_bin || ecc_y_bin)) {
        fprintf(stderr, "RSA modulus and ECC parameters cannot both be "
                "given.\n");
        goto cleanup;
    }

    if ((ecc_x_bin && !ecc_y_bin) || (ecc_y_bin && !ecc_x_bin)) {
        fprintf(stderr, "ECC x and y parameters must both be given.\n");
        goto cleanup;
    }

    if (pubkey_filename == NULL && !modulus_bin && !ecc_x_bin) {
        fprintf(stderr, "Missing public EK file and modulus or ECC "
                "parameters.\n");
        usage(argv[0]);
        goto cleanup;
    }

    if (issuercert_filename == NULL) {
        fprintf(stderr, "The issuer certificate name is required.\n");
        goto cleanup;
    }

    switch (certtype) {
    case CERT_TYPE_EK:
    case CERT_TYPE_PLATFORM:
        if (tpm_manufacturer == NULL ||
            tpm_model == NULL ||
            tpm_version == NULL) {
            fprintf(stderr, "--tpm-manufacturer and --tpm-model and "
                            "--tpm version "
                            "must all be provided\n");
            goto cleanup;
        }
        break;
    case CERT_TYPE_AIK:
        break;
    case CERT_TYPE_IAK:
    case CERT_TYPE_IDEVID:
        if (tpm_serial_num == NULL) {
            fprintf(stderr, "--tpm-serial-num must be provided\n");
            goto cleanup;
        }
        break;
    }

    switch (certtype) {
    case CERT_TYPE_PLATFORM:
        if (platf_manufacturer == NULL ||
            platf_model == NULL ||
            platf_version == NULL) {
            fprintf(stderr, "--platform-manufacturer and --platform-model and "
                            "--platform version "
                            "must all be provided\n");
            goto cleanup;
        }
        break;
    case CERT_TYPE_EK:
        if (spec_family == NULL ||
            spec_level == ~0 ||
            spec_revision == ~0) {
            fprintf(stderr, "--tpm-spec-family and --tpm-spec-level and "
                            "--tpm-spec-revision must all be provided\n");
            goto cleanup;
        }
        break;
    case CERT_TYPE_AIK:
    case CERT_TYPE_IAK:
    case CERT_TYPE_IDEVID:
        break;
    }

    err = gnutls_global_init();
    if (err < 0) {
            fprintf(stderr, "gnutls_global_init failed.\n");
            goto cleanup;
    }
    if (pubkey_filename) {
        gnutls_pubkey_init(&pubkey);

        err = gnutls_load_file(pubkey_filename, &datum);
        if (err != GNUTLS_E_SUCCESS) {
            fprintf(stderr, "Could not open file for EK public key: %s\n",
                strerror(errno));
            goto cleanup;
        }

        err = gnutls_pubkey_import(pubkey, &datum, GNUTLS_X509_FMT_PEM);
        gnutls_free(datum.data);
        datum.data = NULL;
        if (err != GNUTLS_E_SUCCESS) {
            fprintf(stderr, "Could not import EK.\n");
            goto cleanup;
        }
    } else {
        if (modulus_bin) {
            pubkey = create_rsa_from_modulus(modulus_bin, modulus_len,
                                             exponent);
            free(modulus_bin);
            modulus_bin = NULL;
        } else if (ecc_x_bin) {
            pubkey = create_ecc_from_x_and_y(ecc_x_bin, ecc_x_len,
                                             ecc_y_bin, ecc_y_len,
                                             ecc_curveid);
            free(ecc_x_bin);
            ecc_x_bin = NULL;
            free(ecc_y_bin);
            ecc_y_bin = NULL;

            is_ecc = true;
        }

        if (pubkey == NULL)
            goto cleanup;
    }

    /* all types of keys must have pubkey set now otherwise the signing
       will not work */

    if (sigkey_filename == NULL) {
        fprintf(stderr, "Missing signature key.\n");
        usage(argv[0]);
        exit(1);
    }

#define CHECK_GNUTLS_ERROR(_err, _msg, ...) \
if (_err != GNUTLS_E_SUCCESS) {             \
    fprintf(stderr, _msg, __VA_ARGS__);     \
    goto cleanup;                           \
}

    if (strstr(sigkey_filename, "tpmkey:uuid=") == sigkey_filename ||
        strstr(sigkey_filename, "tpmkey:file=") == sigkey_filename) {
        /* GnuTLS TPM 1.2 key URL */
        err = gnutls_privkey_init(&tpmkey);
        CHECK_GNUTLS_ERROR(err, "Could not initialize tpmkey: %s\n",
                           gnutls_strerror(err));
        err = gnutls_privkey_import_tpm_url(tpmkey, sigkey_filename,
                                            parentkeypass, sigkeypass, 0);
        CHECK_GNUTLS_ERROR(err, "Could not import tpmkey %s: %s\n",
                           sigkey_filename, gnutls_strerror(err));
    } else if (strstr(sigkey_filename, "pkcs11:") == sigkey_filename) {
        gnutls_pkcs11_set_pin_function(mypinfunc, NULL);
        /* GnuTLS PKCS11 key URI */
        err = gnutls_privkey_init(&pkcs11key);
        CHECK_GNUTLS_ERROR(err, "Could not initialize tpmkey: %s\n",
                           gnutls_strerror(err));
        err = gnutls_privkey_import_url(pkcs11key, sigkey_filename, 0);
        CHECK_GNUTLS_ERROR(err, "Could not import pkcs11 key %s: %s\n",
                           sigkey_filename, gnutls_strerror(err));
    } else {
        err = gnutls_x509_privkey_init(&sigkey);
        CHECK_GNUTLS_ERROR(err, "Could not initialize sigkey: %s\n",
                           gnutls_strerror(err));

        err = gnutls_load_file(sigkey_filename, &datum);
        CHECK_GNUTLS_ERROR(err, "Could not read signing key from file %s: %s\n",
                           sigkey_filename, gnutls_strerror(err));

        if (sigkeypass) {
            err = gnutls_x509_privkey_import2(sigkey, &datum, GNUTLS_X509_FMT_PEM,
                                              sigkeypass, 0);
        } else {
            err = gnutls_x509_privkey_import(sigkey, &datum, GNUTLS_X509_FMT_PEM);
        }
    }
    gnutls_free(datum.data);
    datum.data = NULL;
    CHECK_GNUTLS_ERROR(err, "Could not import signing key : %s\n",
                       gnutls_strerror(err));

    err = gnutls_load_file(issuercert_filename, &datum);
    CHECK_GNUTLS_ERROR(err, "Could not read certificate from file %s : %s\n",
                       issuercert_filename, gnutls_strerror(err));

    gnutls_x509_crt_init(&sigcert);

    err = gnutls_x509_crt_import(sigcert, &datum, GNUTLS_X509_FMT_PEM);
    gnutls_free(datum.data);
    datum.data = NULL;
    datum.size = 0;

    CHECK_GNUTLS_ERROR(err, "Could not import issuer certificate: %s\n",
                       gnutls_strerror(err));

    err = gnutls_x509_crt_init(&crt);
    CHECK_GNUTLS_ERROR(err, "CRT init failed: %s\n", gnutls_strerror(err))

    /* 3.5.1 Version */
    err = gnutls_x509_crt_set_version(crt, 3);
    CHECK_GNUTLS_ERROR(err, "Could not set version on CRT: %s\n",
                       gnutls_strerror(err))

    /* 3.5.2 Serial Number */
    err = gnutls_x509_crt_set_serial(crt, ser_number, ser_number_len);
    CHECK_GNUTLS_ERROR(err, "Could not set serial on CRT: %s\n",
                       gnutls_strerror(err))

    /* 3.5.5 Validity */
    now = time(NULL);
    err = gnutls_x509_crt_set_activation_time(crt, now);
    CHECK_GNUTLS_ERROR(err, "Could not set activation time on CRT: %s\n",
                       gnutls_strerror(err))

    exp_time = (days < 0) ? -1 : now + (time_t)days * 24 * 60 * 60;
    err = gnutls_x509_crt_set_expiration_time(crt, exp_time);
    CHECK_GNUTLS_ERROR(err, "Could not set expiration time on CRT: %s\n",
                       gnutls_strerror(err))

    /* 3.5.6 Subject -- must be empty for TPM 1.2 */
    if (subject && (flags & CERT_TYPE_TPM2_F)) {
        err = gnutls_x509_crt_set_dn(crt, subject, &error);
        CHECK_GNUTLS_ERROR(err,
                           "Could not set DN on CRT: %s\n"
                           "DN '%s must be fault after %s\n.'",
                           gnutls_strerror(err),
                           subject, error)
    }

    /* 3.5.7 Public Key Info */
    switch (certtype) {
    case CERT_TYPE_EK:
        oid = "1.2.840.113549.1.1.7";
        break;
    case CERT_TYPE_PLATFORM:
        oid = NULL;
        break;
    case CERT_TYPE_AIK:
        oid = "1.2.840.113549.1.1.1";
        break;
    case CERT_TYPE_IAK:
    case CERT_TYPE_IDEVID:
        oid = NULL;
        break;
    default:
        fprintf(stderr, "Internal error: unhandle case in line %d\n",
                __LINE__);
        goto cleanup;
    }
    if (oid) {
        err = gnutls_x509_crt_set_key_purpose_oid(crt, oid, 0);
        CHECK_GNUTLS_ERROR(err, "Could not set key purpose on CRT: %s\n",
                           gnutls_strerror(err))
    }

    /* 3.5.8 Certificate Policies -- skip since not mandated */
    /* 3.5.9 Subject Alternative Names */
    switch (certtype) {
    case CERT_TYPE_EK:
        err = create_tpm_manufacturer_info(tpm_manufacturer, tpm_model,
                                           tpm_version, &datum);
        if (err) {
            fprintf(stderr, "Could not create TPM manufacturer info");
            goto cleanup;
        }
        break;
    case CERT_TYPE_PLATFORM:
        if (flags & CERT_TYPE_TPM2_F) {
            err = create_platf_manufacturer_info(platf_manufacturer,
                                                 platf_model,
                                                 platf_version,
                                                 &datum, true);
            if (err) {
                fprintf(stderr, "Could not create platform manufacturer "
                        "info");
                goto cleanup;
            }
        } else {
            err = create_tpm_and_platform_manuf_info(tpm_manufacturer,
                                                     tpm_model,
                                                     tpm_version,
                                                     platf_manufacturer,
                                                     platf_model,
                                                     platf_version,
                                                     &datum, false);
            if (err) {
                fprintf(stderr, "Could not create TPM and platform "
                        "manufacturer info");
                goto cleanup;
            }
        }
        break;
    case CERT_TYPE_AIK:
        break;
    case CERT_TYPE_IAK:
    case CERT_TYPE_IDEVID:
        err = create_iak_info(&datum, tpm_serial_num);
        if (err) {
            fprintf(stderr, "Could not create IAK info");
            goto cleanup;
        }
        break;
    default:
        fprintf(stderr, "Internal error: unhandle case in line %d\n",
                __LINE__);
        goto cleanup;
    }

    if (datum.size > 0) {
        switch (certtype) {
        case CERT_TYPE_EK:
        case CERT_TYPE_PLATFORM:
            err = prepend_san_asn1_header(&datum);
            CHECK_GNUTLS_ERROR(err, "Could not prepend SAN ASN.1 header: %s\n",
                               gnutls_strerror(err))
            break;
        case CERT_TYPE_AIK:
        case CERT_TYPE_IAK:
        case CERT_TYPE_IDEVID:
            break;
        }

        err = gnutls_x509_crt_set_extension_by_oid(crt, GNUTLS_X509EXT_OID_SAN,
                                                   datum.data, datum.size,
                                                   1);
        CHECK_GNUTLS_ERROR(err, "Could not set subject alt name: %s\n",
                           gnutls_strerror(err))
    }
    gnutls_free(datum.data);
    datum.data = NULL;
    datum.size = 0;

    /* 3.5.10 Basic Constraints */
    err = gnutls_x509_crt_set_basic_constraints(crt, 0, -1);
    CHECK_GNUTLS_ERROR(err, "Could not set key usage id: %s\n",
                       gnutls_strerror(err))

    /* 3.5.11 Subject Directory Attributes */
    switch (certtype) {
    case CERT_TYPE_EK:
        err = create_tpm_specification_info(spec_family, spec_level,
                                            spec_revision, &datum);
        if (err) {
            fprintf(stderr, "Could not create TPMSpecification\n");
            goto cleanup;
        }
        break;
    case CERT_TYPE_PLATFORM:
    case CERT_TYPE_AIK:
    case CERT_TYPE_IAK:
    case CERT_TYPE_IDEVID:
        break;
    default:
        fprintf(stderr, "Internal error: unhandled case in line %d\n",
                __LINE__);
        goto cleanup;
    }

    if (!err && datum.size > 0) {
        err = gnutls_x509_crt_set_extension_by_oid(crt, "2.5.29.9",
                                                   datum.data, datum.size,
                                                   0);
        CHECK_GNUTLS_ERROR(err, "Could not set subject directory attributes: "
                           "%s\n", gnutls_strerror(err))
    }
    gnutls_free(datum.data);
    datum.data = NULL;

    /* 3.5.12 Authority Key Id */
    err = gnutls_x509_crt_get_subject_key_id(sigcert, id, &id_size, NULL);
    if (err == GNUTLS_E_SUCCESS && id_size > 0) {
        err = gnutls_x509_crt_set_authority_key_id(crt, id, id_size);
        CHECK_GNUTLS_ERROR(err, "Could not set the authority key id: %s\n",
                           gnutls_strerror(err))
    } else {
        CHECK_GNUTLS_ERROR(err, "Could not get the authority key id from the cert: %s\n",
                           gnutls_strerror(err))
    }
    /* 3.5.13 Authority Info Access -- may be omitted */
    /* 3.5.14 CRL Distribution -- missing  */

    /* 3.5.15 Key Usage */
    switch (certtype) {
    case CERT_TYPE_EK:
    case CERT_TYPE_PLATFORM:
        if (flags & CERT_TYPE_TPM2_F) {
            /* support 'User Device TPM' and 'Non-User Device TPM' in spec */
            if (flags & ALLOW_SIGNING_F) {
                key_usage |= GNUTLS_KEY_DIGITAL_SIGNATURE;
            }
            if ((flags & (ALLOW_SIGNING_F | DECRYPTION_F)) == 0 ||
                (flags & DECRYPTION_F) == DECRYPTION_F) {
                if (is_ecc) {
                    key_usage |= GNUTLS_KEY_KEY_AGREEMENT;
                } else {
                    key_usage |= GNUTLS_KEY_KEY_ENCIPHERMENT;
                }
            }
        } else {
            key_usage = GNUTLS_KEY_KEY_ENCIPHERMENT;
        }
        break;
    case CERT_TYPE_AIK:
    case CERT_TYPE_IAK:
    case CERT_TYPE_IDEVID:
        key_usage = GNUTLS_KEY_DIGITAL_SIGNATURE;
        break;
    default:
        fprintf(stderr, "Internal error: unhandle case in line %d\n",
                __LINE__);
        goto cleanup;
    }
    err = gnutls_x509_crt_set_key_usage(crt, key_usage);
    CHECK_GNUTLS_ERROR(err, "Could not set key usage id: %s\n",
                       gnutls_strerror(err))

    /* 3.5.16 Extended Key Usage */
    oid = NULL;

    switch (certtype) {
    case CERT_TYPE_EK:
        oid = "2.23.133.8.1";
        break;
    case CERT_TYPE_PLATFORM:
        oid = "2.23.133.8.2";
        break;
    case CERT_TYPE_AIK:
    case CERT_TYPE_IAK:
    case CERT_TYPE_IDEVID:
        break;
    default:
        fprintf(stderr, "Internal error: unhandled case in line %d\n",
                __LINE__);
        goto cleanup;
    }

    if (oid) {
        err = create_cert_extended_key_usage(oid, &datum);
        if (err) {
            fprintf(stderr, "Could not create ASN.1 for extended key usage\n");
            goto cleanup;
        }

        err = gnutls_x509_crt_set_extension_by_oid(crt,
            GNUTLS_X509EXT_OID_EXTENDED_KEY_USAGE,
            datum.data, datum.size, 0);
        CHECK_GNUTLS_ERROR(err, "Could not set extended key usage by oid: %s\n",
                           gnutls_strerror(err))

        gnutls_free(datum.data);
        datum.data = NULL;
    }

    /* 3.5.17 Subject Key Id -- should not be included */
    /* 3.5.18 Issuer Alt. Name -- should not be included */
    /* 3.5.19 FreshestCRL -- should not be included */
    /* 3.5.20 Subject Info. Access -- should not be included */
    /* 3.5.21 Subject and Issued Unique Ids -- must be omitted */
    /* 3.5.22 Virtualized Platform Attestation Service -- missing */
    /* 3.5.23 Migration Controller Attestation Service -- missing */
    /* 3.5.24 Migration Controller Registration Service -- missing */
    /* 3.5.25 Virtual Platform Backup Service -- missing */

    /* set public key */
    err = gnutls_x509_crt_set_pubkey(crt, pubkey);
    CHECK_GNUTLS_ERROR(err, "Could not set public EK on CRT: %s\n",
                       gnutls_strerror(err))

    /* sign cert */
    if (sigkey) {
        err = gnutls_x509_crt_sign2(crt, sigcert, sigkey, hashAlgo, 0);
    } else if (pkcs11key) {
        err = gnutls_x509_crt_privkey_sign(crt, sigcert, pkcs11key,
                                           hashAlgo, 0);
    } else {
        /* TPM 1.2 signs cert for a TPM 1.2 (SHA1) or TPM 2 (SHA256) */
        err = gnutls_x509_crt_privkey_sign(crt, sigcert, tpmkey,
                                           hashAlgo, 0);
    }
    CHECK_GNUTLS_ERROR(err, "Could not sign the CRT: %s [%s]\n",
                       gnutls_strerror(err), sigkey_filename)

    /* write cert to file; either PEM or DER */
    gnutls_x509_crt_export2(crt,
                            (write_pem)
                            ? GNUTLS_X509_FMT_PEM
                            : GNUTLS_X509_FMT_DER, &out);
    if (cert_filename) {
        cert_file_fd = open(cert_filename, O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW,
                            S_IRUSR|S_IWUSR);
        if (cert_file_fd < 0) {
            fprintf(stderr, "Could not open %s for writing the certificate: %s\n",
                    cert_filename,
                    strerror(errno));
            goto cleanup;
        }
        if (add_header) {
            TCG_PCCLIENT_STORED_FULL_CERT_HEADER hdr = {
                .stored_cert = {
                    .tag = htobe16(TCG_TAG_PCCLIENT_STORED_CERT),
                    .certType = 0,
                    .certSize = htobe16(out.size + 2),
                },
                .tag = htobe16(TCG_TAG_PCCLIENT_FULL_CERT),
            };
            if (sizeof(hdr) != write(cert_file_fd, &hdr, sizeof(hdr))) {
                fprintf(stderr, "Could not write certificate header: %s\n",
                        strerror(errno));
                close(cert_file_fd);
                unlink(cert_filename);
                goto cleanup;
            }
        }
        if ((ssize_t)out.size != write(cert_file_fd, out.data, out.size)) {
            fprintf(stderr, "Could not write certificate into file: %s\n",
                    strerror(errno));
            close(cert_file_fd);
            unlink(cert_filename);
            goto cleanup;
        }
        close(cert_file_fd);
    } else {
        fprintf(stdout, "%s\n", out.data);
    }

    ret = 0;

cleanup:
    mpz_clear(serial);

    gnutls_free(out.data);

    gnutls_x509_crt_deinit(crt);
    gnutls_x509_crt_deinit(sigcert);
    gnutls_x509_privkey_deinit(sigkey);
    gnutls_pubkey_deinit(pubkey);
    gnutls_privkey_deinit(tpmkey);
    gnutls_privkey_deinit(pkcs11key);

    gnutls_global_deinit();

    free(sigkeypass);
    free(parentkeypass);
    free(modulus_bin);
    free(ecc_x_bin);
    free(ecc_y_bin);
    asn_free();

    return ret;
}
