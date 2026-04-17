/*
 * ek-cert.c
 *
 * Authors: Stefan Berger <stefanb@us.ibm.com>
 *
 * (c) Copyright IBM Corporation 2014, 2015, 2020, 2026
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
#include <ctype.h>

#include <arpa/inet.h>

#include <glib.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/ui.h>
#include <openssl/store.h>

#include <gmp.h>

#include "sys_dependencies.h"
#include "tpm_asn1.h"
#include "swtpm.h"
#include "compiler_dependencies.h"

#define MAX_PASSWORD_SIZE 256
#define MAX_HEX_STRING_SIZE (10 * 1024)
#define UNSET_VALUE (-1)

#define BITS_TO_BYTES(NUM_BITS) (((NUM_BITS) + 7) / 8)

typedef struct datum {
    unsigned char *data;
    unsigned int size;
} datum_t;

static void free_datum(struct datum *d)
{
    free(d->data);
    d->data = NULL;
    d->size = 0;
}

enum cert_type_t {
    CERT_TYPE_EK = 1,
    CERT_TYPE_PLATFORM,
    CERT_TYPE_AIK,
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

#define FCLOSE(filp)	\
    do {		\
        fclose(filp);	\
        filp = NULL;	\
    } while (0)

/*
 * All errors from libtasn1 lead to display of an error message after a jump to
 * cleanup.
 */
#define ASN1_CHECK_ERROR(ERR, MSG)	\
    if (ERR != ASN1_SUCCESS) {		\
        err_line = __LINE__;		\
        err_msg = MSG;			\
        goto cleanup;			\
    }

/*
 * All errors from OpenSSL lead to display of error message and a
 * jump to cleanup.
 */
#define CHECK_OSSL_NULLPTR1(ptr, _msg)	\
    if (!ptr) {				\
        fprintf(stderr, _msg);		\
        ERR_print_errors_fp(stderr);	\
        goto cleanup;			\
    }

#define CHECK_OSSL_NULLPTR(ptr, _msg, ...)	\
    if (!ptr) {					\
        fprintf(stderr, _msg, __VA_ARGS__);	\
        ERR_print_errors_fp(stderr);		\
        goto cleanup;				\
    }

#define CHECK_OSSL_RETURN1(TEST, _msg)	\
    if (TEST) {				\
        fprintf(stderr, _msg);		\
        ERR_print_errors_fp(stderr);	\
        goto cleanup;			\
    }

#define CHECK_OSSL_RETURN(TEST, _msg, ...)	\
    if (TEST) {					\
        fprintf(stderr, _msg, __VA_ARGS__);	\
        ERR_print_errors_fp(stderr);		\
        goto cleanup;				\
    }

static void versioninfo(void)
{
    fprintf(stdout,
        "TPM certificate tool version %d.%d.%d, Copyright (c) 2015 IBM Corp.\n"
        ,SWTPM_VER_MAJOR, SWTPM_VER_MINOR, SWTPM_VER_MICRO);
}

static void usage(const char *prg)
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
        "--issuercert <filename>   : PEM file with CA cert\n"
        "--out-cert <filename>     : Filename for certificate\n"
        "--modulus <hex string>    : The modulus of the public key\n"
        "--exponent <exponent>     : The exponent of the public key\n"
        "--ecc-x <hex string>      : ECC key x component\n"
        "--ecc-y <hex string>      : ECC key y component\n"
        "--ecc-curveid <id>        : ECC curve id; secp256r1, secp384r1, secp521r1\n"
        "                            default: secp256r1\n"
        "--serial <serial number>  : The certificate serial number\n"
        "--days <number>           : Number of days the cert is valid;\n"
        "                            -1 for no expiration\n"
        "--pem                     : Write certificate in PEM format; default is DER\n"
        "--type <platform|ek>      : The type of certificate to create; default is ek\n"
        "--tpm-manufacturer <name> : The name of the TPM manufacturer\n"
        "--tpm-model <model>       : The TPM model (part number)\n"
        "--tpm-version <version>   : The TPM version (firmware version)\n"
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
        "--decryption              : The EK of a TPM 2 can be used for key\n"
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

static char hex_to_str(char digit)
{
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

static unsigned char *hex_str_to_bin(const char *hexstr, int *modulus_len)
{
    int len;
    unsigned char *result;
    int i = 0, j = 0;
    char val1, val2;

    len = strlen(hexstr);
    if (len > MAX_HEX_STRING_SIZE) {
        fprintf(stderr, "Unreasonably long hex string of %d bytes.\n", len);
        return NULL;
    }

    if ((len & 1) != 0) {
        fprintf(stderr, "Got an odd number of hex digits (%d).\n", len);
        fprintf(stderr, "    hex digits: %s\n", hexstr);
        return NULL;
    }

    result = malloc(len / 2);
    if (result == NULL) {
        fprintf(stderr, "Out of memory trying to allocate %d bytes.\n", len / 2);
        return NULL;
    }
    i = 0;
    j = 0;

    while (i < len) {
        val1 = hex_to_str(hexstr[i]);
        if (val1 < 0) {
            fprintf(stderr, "Illegal hex character '%c'.\n", hexstr[i]);
            free(result);
            return NULL;
        }
        i++;
        val2 = hex_to_str(hexstr[i]);
        if (val2 < 0) {
            fprintf(stderr, "Illegal hex character '%c'.\n", hexstr[i]);
            free(result);
            return NULL;
        }
        i++;
        result[j++] = (val1 << 4) | val2;
    }
    *modulus_len = j;

    return result;
}

static EVP_PKEY *
create_rsa_from_modulus(unsigned char *modulus, unsigned int modulus_len,
                        uint32_t exponent)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    EVP_PKEY *pubkey = NULL;
    OSSL_PARAM *params = NULL;
    BIGNUM *n = BN_bin2bn(modulus, modulus_len, NULL);
    BIGNUM *e = BN_new();

    CHECK_OSSL_NULLPTR1(ctx, "Could not create pkey context for RSA key.\n");
    if (!bld || !e || !n) {
        fprintf(stderr, "Out of memory.\n");
        goto cleanup;
    }

    CHECK_OSSL_RETURN1(!BN_set_word(e, exponent),
                       "Could not set exponent.\n");

    CHECK_OSSL_RETURN1(
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e),
        "Could not push BN.\n");

    CHECK_OSSL_RETURN1(
        (params = OSSL_PARAM_BLD_to_param(bld)) == NULL ||
        EVP_PKEY_fromdata_init(ctx) != 1 ||
        EVP_PKEY_fromdata(ctx, &pubkey,
                          EVP_PKEY_PUBLIC_KEY, params) != 1,
        "Could not create RSA public key.\n");

cleanup:
    BN_free(e);
    BN_free(n);
    OSSL_PARAM_BLD_free(bld);
    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(ctx);

    return pubkey;
}

static EVP_PKEY *
create_ecc_from_x_and_y(unsigned char *ecc_x, unsigned int ecc_x_len,
                        unsigned char *ecc_y, unsigned int ecc_y_len,
                        const char *ecc_curveid)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    g_autofree unsigned char *buffer = NULL;
    g_autofree char *curve = NULL;
    EVP_PKEY *pubkey = NULL;
    OSSL_PARAM *params = NULL;
    size_t exp_len;

    CHECK_OSSL_NULLPTR1(ctx, "Could not create pkey context for EC key.\n");
    CHECK_OSSL_NULLPTR1(bld, "Out of memory.\n");

    if (ecc_curveid == NULL || !strcmp(ecc_curveid, "secp256r1")) {
        curve = g_strdup("prime256v1");
        exp_len = BITS_TO_BYTES(256);
    } else if (!strcmp(ecc_curveid, "secp384r1")) {
        curve = g_strdup("secp384r1");
        exp_len = BITS_TO_BYTES(384);
    } else if (!strcmp(ecc_curveid, "secp521r1")) {
        curve = g_strdup("secp521r1");
        exp_len = BITS_TO_BYTES(521);
    } else {
        fprintf(stderr, "Unsupported ECC curve id: %s\n", ecc_curveid);
        goto cleanup;
    }
    if (ecc_x_len > exp_len || ecc_y_len > exp_len) {
        fprintf(stderr,
                "EC X or Y parameter exceeds expected size of %zu bytes\n",
                exp_len);
        goto cleanup;
    }
    buffer = g_malloc0(1 + 2 * exp_len);
    buffer[0] = 0x4;
    memcpy(&buffer[1 + exp_len - ecc_x_len], ecc_x, ecc_x_len);
    memcpy(&buffer[1 + 2 * exp_len - ecc_y_len], ecc_y, ecc_y_len);

    CHECK_OSSL_RETURN1(
        !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                          buffer, 1 + 2 * exp_len) ||
        !OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                         curve, 0),
        "Could not push string.\n");

    CHECK_OSSL_RETURN(
        (params = OSSL_PARAM_BLD_to_param(bld)) == NULL ||
        EVP_PKEY_fromdata_init(ctx) != 1 ||
        EVP_PKEY_fromdata(ctx, &pubkey, EVP_PKEY_PUBLIC_KEY, params) != 1,
        "Could not create %s key\n", curve);

cleanup:
    OSSL_PARAM_BLD_free(bld);
    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(ctx);

    return pubkey;
}

static int
asn_init(void)
{
    static bool initialized;
    unsigned int err_line;
    const char *err_msg;
    int err;

    if (initialized)
        return ASN1_SUCCESS;

    err = asn1_array2tree(tpm_asn1_tab, &_tpm_asn, NULL);
    ASN1_CHECK_ERROR(err, "array2tree");

    initialized = true;

cleanup:
    if (err)
        fprintf(stderr, "%s @ %u: Error: %s : %s\n",
                __func__, err_line, err_msg, asn1_strerror(err));

    return err;
}

static void
asn_free(void)
{
    if (_tpm_asn)
        asn1_delete_structure(&_tpm_asn);
}

static int
encode_asn1(datum_t *asn1, asn1_node at)
{
    int err;

    /* determine needed size of byte array */
    asn1->size = 0;
    err = asn1_der_coding(at, "", NULL, (int *)&asn1->size, NULL);
    if (err != ASN1_MEM_ERROR) {
        fprintf(stderr, "%s @ %u: Error: asn1_der_coding: %s\n",
                __func__, __LINE__, asn1_strerror(err));
        return err;
    }

    asn1->data = malloc(asn1->size + 16);
    if (!asn1->data) {
        fprintf(stderr, "Out of memory.\n");
        return ASN1_MEM_ERROR;
    }

    err = asn1_der_coding(at, "", asn1->data, (int *)&asn1->size, NULL);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "%s @ %u: Error: asn1_der_coding: %s\n",
                __func__, __LINE__, asn1_strerror(err));
        free(asn1->data);
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
    unsigned int err_line;
    const char *err_msg;
    int err;

    err = asn1_create_element(_tpm_asn, "TPM.TPMManufacturerInfo", at);
    ASN1_CHECK_ERROR(err, "asn1_create_element");

    err = asn1_write_value(*at, "tpmManufacturerSet.tpmManufacturer.?LAST",
                           "NEW", 0);
    ASN1_CHECK_ERROR(err, "asn1_write_value");

    err = asn1_write_value(*at, "tpmManufacturerSet.tpmManufacturer.id",
                           "2.23.133.2.1", 0);
    ASN1_CHECK_ERROR(err, "asn1_write_value");

    err = asn1_write_value(*at,
                           "tpmManufacturerSet.tpmManufacturer.manufacturer",
                           manufacturer, 0);
    ASN1_CHECK_ERROR(err, "asn1_write_value");

    err = asn1_write_value(*at, "tpmModelSet.tpmModel.?LAST", "NEW", 0);
    ASN1_CHECK_ERROR(err, "asn1_write_value");

    err = asn1_write_value(*at, "tpmModelSet.tpmModel.id", "2.23.133.2.2", 0);
    ASN1_CHECK_ERROR(err, "asn1_write_value");

    err = asn1_write_value(*at, "tpmModelSet.tpmModel.model", tpm_model, 0);
    ASN1_CHECK_ERROR(err, "asn1_write_value");

    err = asn1_write_value(*at, "tpmVersionSet.tpmVersion.?LAST", "NEW", 0);
    ASN1_CHECK_ERROR(err, "asn1_write_value");

    err = asn1_write_value(*at, "tpmVersionSet.tpmVersion.id", "2.23.133.2.3",
                           0);
    ASN1_CHECK_ERROR(err, "asn1_write_value");

    err = asn1_write_value(*at, "tpmVersionSet.tpmVersion.version", tpm_version, 0);
    ASN1_CHECK_ERROR(err, "asn1_write_value");

cleanup:
    if (err)
        fprintf(stderr, "%s @ %u: Error: %s : %s\n",
                __func__, err_line, err_msg, asn1_strerror(err));

    return err;
}

static int
create_tpm_manufacturer_info(const char *manufacturer,
                             const char *tpm_model,
                             const char *tpm_version,
                             datum_t *asn1)
{
    asn1_node at = NULL;
    int err;

    err = asn_init();
    if (err != ASN1_SUCCESS)
        goto cleanup;

    err = build_tpm_manufacturer_info(&at, manufacturer,
                                      tpm_model, tpm_version);
    if (err != ASN1_SUCCESS)
        goto cleanup;

    err = encode_asn1(asn1, at);

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
    unsigned int err_line;
    const char *err_msg;
    int err;

    err = asn1_create_element(_tpm_asn, "TPM.PlatformManufacturerInfo", at);
    ASN1_CHECK_ERROR(err, "asn1_create_element");

    err = asn1_write_value(*at, "platformManufacturerSet.platformManufacturer.?LAST",
                           "NEW", 0);
    ASN1_CHECK_ERROR(err, "asn1_write_value");

    err = asn1_write_value(*at, "platformManufacturerSet.platformManufacturer.id",
                           forTPM2 ? "2.23.133.5.1.1"
                                   : "2.23.133.2.4",
                           0);
    ASN1_CHECK_ERROR(err, "asn1_write_value");

    err = asn1_write_value(*at, "platformManufacturerSet.platformManufacturer.manufacturer",
                           manufacturer, 0);
    ASN1_CHECK_ERROR(err, "asn1_write_value");

    err = asn1_write_value(*at, "platformModelSet.platformModel.?LAST",
                           "NEW", 0);
    ASN1_CHECK_ERROR(err, "asn1_write_value");

    err = asn1_write_value(*at, "platformModelSet.platformModel.id",
                           forTPM2 ? "2.23.133.5.1.4"
                                   : "2.23.133.2.5",
                           0);
    ASN1_CHECK_ERROR(err, "asn1_write_value");

    err = asn1_write_value(*at, "platformModelSet.platformModel.model",
                           platf_model, 0);
    ASN1_CHECK_ERROR(err, "asn1_write_value");

    err = asn1_write_value(*at, "platformVersionSet.platformVersion.?LAST",
                           "NEW", 0);
    ASN1_CHECK_ERROR(err, "asn1_write_value");

    err = asn1_write_value(*at, "platformVersionSet.platformVersion.id",
                           forTPM2 ? "2.23.133.5.1.5"
                                   : "2.23.133.2.6",
                           0);
    ASN1_CHECK_ERROR(err, "asn1_write_value");

    err = asn1_write_value(*at, "platformVersionSet.platformVersion.version",
                           platf_version, 0);
    ASN1_CHECK_ERROR(err, "asn1_write_value");

cleanup:
    if (err)
        fprintf(stderr, "%s @ %u: Error: %s : %s\n",
                __func__, err_line, err_msg, asn1_strerror(err));

    return err;
}

static int
create_platf_manufacturer_info(const char *manufacturer,
                               const char *platf_model,
                               const char *platf_version,
                               datum_t *asn1,
                               bool forTPM2)
{
    asn1_node at = NULL;
    int err;

    err = asn_init();
    if (err != ASN1_SUCCESS)
        goto cleanup;

    err = build_platf_manufacturer_info(&at, manufacturer,
                                        platf_model, platf_version,
                                        forTPM2);
    if (err != ASN1_SUCCESS)
        goto cleanup;

    err = encode_asn1(asn1, at);

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
                               datum_t *asn1,
                               bool forTPM2)
{
    asn1_node platf_at = NULL;
    unsigned int err_line = 0;
    asn1_node tpm_at = NULL;
    asn1_node at = NULL;
    const char *err_msg;
    datum_t datum = {
        .data = NULL,
        .size = 0,
    };
    int err;

    err = asn_init();
    if (err != ASN1_SUCCESS)
        goto cleanup;

    err = asn1_create_element(_tpm_asn, "TPM.PlatformCertificateSAN", &at);
    ASN1_CHECK_ERROR(err, "asn1_create_element");

    /* build the TPM manufacturer data */
    err = build_tpm_manufacturer_info(&tpm_at, tpm_manufacturer,
                                      tpm_model, tpm_version);
    ASN1_CHECK_ERROR(err, "Could not build TPM manufacturer info");

    err = encode_asn1(&datum, tpm_at);
    ASN1_CHECK_ERROR(err, "Could not encode TPM data as ASN.1");

    err = asn1_write_value(at, "", "NEW", 1);
    ASN1_CHECK_ERROR(err, "Could not create a NEW element");

    err = asn1_write_value(at, "?1", datum.data, datum.size);
    ASN1_CHECK_ERROR(err, "Could not write 1st element");

    free_datum(&datum);

    /* build the platform manufacturer data */
    err = build_platf_manufacturer_info(&platf_at, platf_manufacturer,
                                        platf_model, platf_version,
                                        forTPM2);
    ASN1_CHECK_ERROR(err, "Could not build platform manufacturer info");

    err = encode_asn1(&datum, platf_at);
    ASN1_CHECK_ERROR(err, "Could not encode platform data as ASN.1");

    err = asn1_write_value(at, "", "NEW", 1);
    ASN1_CHECK_ERROR(err, "Could not create a NEW element");

    err = asn1_write_value(at, "?2", datum.data, datum.size);
    ASN1_CHECK_ERROR(err, "Could not write 2nd element");

    free_datum(&datum);

    err = encode_asn1(asn1, at);

cleanup:
    if (err && err_line)
        fprintf(stderr, "%s @ %u: Error: %s : %s\n",
                __func__, err_line, err_msg, asn1_strerror(err));

    free_datum(&datum);
    asn1_delete_structure(&at);
    asn1_delete_structure(&platf_at);
    asn1_delete_structure(&tpm_at);

    return err;
}

static int
create_tpm_specification_info(const char *spec_family,
                              unsigned int spec_level,
                              unsigned int spec_revision,
                              datum_t *asn1)
{
    unsigned int bigendian;
    unsigned char twoscomp[1 + sizeof(bigendian)] = { 0, };
    unsigned int err_line = 0;
    const char *err_msg;
    asn1_node at = NULL;
    int err;

    err = asn_init();
    if (err != ASN1_SUCCESS)
        goto cleanup;

    err = asn1_create_element(_tpm_asn, "TPM.TPMSpecificationInfo", &at);
    ASN1_CHECK_ERROR(err, "asn1_create_element");

    err = asn1_write_value(at, "tpmSpecificationSeq.id", "2.23.133.2.16", 0);
    ASN1_CHECK_ERROR(err, "asn1_write_value");

    err = asn1_write_value(at,
        "tpmSpecificationSeq.tpmSpecificationSet.tpmSpecification.family",
        spec_family, 0);
    ASN1_CHECK_ERROR(err, "asn1_write_value");

    bigendian = htobe32(spec_level);
    memcpy(&twoscomp[1], &bigendian, sizeof(bigendian));

    err = asn1_write_value(at,
        "tpmSpecificationSeq.tpmSpecificationSet.tpmSpecification.level",
        twoscomp, sizeof(twoscomp));
    ASN1_CHECK_ERROR(err, "asn1_write_value");

    bigendian = htobe32(spec_revision);
    memcpy(&twoscomp[1], &bigendian, sizeof(bigendian));

    err = asn1_write_value(at,
        "tpmSpecificationSeq.tpmSpecificationSet.tpmSpecification.revision",
        twoscomp, sizeof(twoscomp));
    ASN1_CHECK_ERROR(err, "asn1_write_value");

    err = encode_asn1(asn1, at);

cleanup:
    if (err && err_line)
        fprintf(stderr, "%s @ %u: Error: %s : %s\n",
                __func__, err_line, err_msg, asn1_strerror(err));

    asn1_delete_structure(&at);

    return err;
}

static int
create_cert_extended_key_usage(const char *oid, datum_t *asn1)
{
    unsigned int err_line = 0;
    const char *err_msg;
    asn1_node at = NULL;
    int err;

    err = asn_init();
    if (err != ASN1_SUCCESS)
        goto cleanup;

    err = asn1_create_element(_tpm_asn, "TPM.TPMEKCertExtendedKeyUsage", &at);
    ASN1_CHECK_ERROR(err, "asn1_create_element");

    err = asn1_write_value(at, "id", oid, 0);
    ASN1_CHECK_ERROR(err, "asn1_write_value");

    err = encode_asn1(asn1, at);

cleanup:
    if (err && err_line)
        fprintf(stderr, "%s @ %u: Error: %s : %s\n",
                __func__, err_line, err_msg, asn1_strerror(err));

    asn1_delete_structure(&at);

    return err;
}

/*
 * prepend_san_asn1_header -- prepend a SAN ASN.1 header on the data
 *
 * This function will prepend something like this:
 *  0x30 <subsequent length> 0xa4 <subsequent length>
 */
static bool prepend_san_asn1_header(datum_t *datum)
{
    unsigned char buffer[2 * (1 + 1 + sizeof(unsigned long))];
    unsigned i = sizeof(buffer);
    unsigned long size;
    unsigned char intlen;
    unsigned char *data = datum->data;
    bool success = true;

    if (!data)
        return false;
    datum->data = NULL;

    /* write backwards */
    intlen = 0;
    size = datum->size; /* datum->size is only 4 bytes */
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

    datum->data = malloc(datum->size + sizeof(buffer) - i);
    if (datum->data == NULL) {
        fprintf(stderr, "Out of memory.\n");
        success = false;
        goto exit;
    }

    memcpy(datum->data, &buffer[i], sizeof(buffer) - i);
    memcpy(&datum->data[sizeof(buffer) - i], data, datum->size);
    datum->size = sizeof(buffer) - i + datum->size;

exit:
    free(data);
    return success;
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
    char buffer[MAX_PASSWORD_SIZE];
    const char *tocopy;
    char *result;
    char *endptr;
    ssize_t n;
    int fd;

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
            fprintf(stderr, "Could not get password from environment variable.\n");
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

static int password_cb(char *buf, int buflen, int rwflag, void *userdata)
{
    size_t to_copy = strlen(userdata);
    if (buflen < 0 || to_copy > (size_t)buflen)
        return 0;

    memcpy(buf, userdata, to_copy);

    return (int)to_copy;
}

static int ui_get_pin(UI *ui, UI_STRING *uis)
{
    if (UI_set_result(ui, uis, UI_get0_user_data(ui)) != 0)
        return 0;
    return 1;
}

static EVP_PKEY *get_key_pkcs11(OSSL_PROVIDER *provider, const char *pkcs11uri)
{
    OSSL_STORE_CTX *store = NULL;
    UI_METHOD *ui_method = NULL;
    EVP_PKEY *sigkey = NULL;
    OSSL_STORE_INFO *info;

    if (getenv("SWTPM_PKCS11_PIN")) {
        ui_method = UI_create_method("PIN reader");
        CHECK_OSSL_NULLPTR1(ui_method, "Could not create the PIN reader.\n");

        CHECK_OSSL_RETURN1(UI_method_set_reader(ui_method, ui_get_pin) != 0,
                           "Could not set the PIN reader.\n");
    }
    store = OSSL_STORE_open_ex(pkcs11uri, NULL, "provider=pkcs11", ui_method,
                               getenv("SWTPM_PKCS11_PIN"), NULL, NULL, NULL);
    CHECK_OSSL_NULLPTR1(store, "Could not open store for pkcs11 provider.\n");

    while (!OSSL_STORE_eof(store)) {
        info = OSSL_STORE_load(store);
        if (!info)
            continue;

        switch (OSSL_STORE_INFO_get_type(info)) {
        case OSSL_STORE_INFO_PKEY:
           sigkey = OSSL_STORE_INFO_get1_PKEY(info);
           break;
        }
        OSSL_STORE_INFO_free(info);
        if (sigkey)
            break;
    }

    if (!sigkey) {
        fprintf(stderr, "Could not get access to private key %s.\n",
                pkcs11uri);
    }

cleanup:
    OSSL_STORE_close(store);
    UI_destroy_method(ui_method);

    return sigkey;
}

static const EVP_MD *get_hashalg_for_signing(EVP_PKEY *signingkey)
{
    int bits = EVP_PKEY_get_bits(signingkey);
    const EVP_MD *md;

    if (EVP_PKEY_is_a(signingkey, "RSA")) {
        switch (bits) {
        case 2048:
            md = EVP_sha256();
            break;
        default:
            md = EVP_sha384();
            break;
        }
    } else if (EVP_PKEY_is_a(signingkey, "EC")) {
        if (bits >= 512)
            md = EVP_sha512();
        else if (bits >= 384)
            md = EVP_sha384();
        else
            md = EVP_sha256();
    } else {
        md = EVP_sha256();
    }
    return md;
}

static void capabilities_print_json(void)
{
    fprintf(stdout,
            "{ "
            "\"type\": \"swtpm_cert\", "
            "\"features\": [ "
             "\"cmdarg-signkey-pwd\""
            " ], "
            "\"version\": \"" VERSION "\" "
            "}\n");
}

int
main(int argc, char *argv[])
{
    int ret = 1;
    EVP_PKEY *pubkey = NULL;
    EVP_PKEY *sigkey = NULL;
    BIO *bp = NULL;
    FILE *fp = NULL;
    X509 *sigcert = NULL;
    X509 *crt = NULL;
    BIGNUM *bn_serial = NULL;
    ASN1_INTEGER *asn1_serial = NULL;
    ASN1_TIME *asn1_time = NULL;
    ASN1_OCTET_STRING *oct = NULL;
    X509_EXTENSION *ext = NULL;
    const X509_NAME *issuer_name = NULL;
    X509V3_CTX x509v3_ctx;
    OSSL_PROVIDER *provider = NULL;
    const EVP_MD *md = EVP_sha1();
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
    datum_t datum = { NULL, 0 }, out = { NULL, 0 };
    mpz_t serial;
    time_t now;
    int err;
    int cert_file_fd;
    const char *subject = NULL;
    long days = 365;
    char *sigkeypass = NULL;
    unsigned char ser_number[20];
    size_t ser_number_len;
    long int exponent = 0x10001;
    bool write_pem = false;
    enum cert_type_t certtype = CERT_TYPE_EK;
    const char *oid;
    GString *key_usage = g_string_new("critical");
    const char *tpm_manufacturer = NULL;
    const char *tpm_version = NULL;
    const char *tpm_model = NULL;
    const char *platf_manufacturer = NULL;
    const char *platf_version = NULL;
    const char *platf_model = NULL;
    bool add_header = false;
    const char *spec_family = NULL;
    long int spec_level = UNSET_VALUE;
    long int spec_revision = UNSET_VALUE;
    int flags = 0;
    bool is_ecc = false;
    char *endptr;
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
        {"issuercert", required_argument, NULL, 'i'},
        {"out-cert", required_argument, NULL, 'o'},
        {"subject", required_argument, NULL, 'u'},
        {"days", required_argument, NULL, 'd'},
        {"serial", required_argument, NULL, 'r'},
        {"type", required_argument, NULL, 't'},
        {"tpm-manufacturer", required_argument, NULL, '1'},
        {"tpm-model", required_argument, NULL, '2'},
        {"tpm-version", required_argument, NULL, '3'},
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
                    "p:m:x:y:z:e:s:S:T:i:o:u:d:r:1:2:3:4:5:6:7:8:9:MaXADcvh",
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
            errno = 0;
            exponent = strtol(optarg, &endptr, 0);
            if (errno || endptr == optarg || *endptr != '\0') {
                fprintf(stderr, "Could not parse the exponent '%s'.\n",
                        optarg);
                goto cleanup;
            }
            if (exponent <= 0) {
                fprintf(stderr, "Exponent is wrong and cannot be <= 0.\n");
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
            errno = 0;
            days = strtol(optarg, &endptr, 0);
            if (errno || endptr == optarg || *endptr != '\0') {
                fprintf(stderr, "Could not parse the number of days '%s'.\n",
                        optarg);
                goto cleanup;
            }
            if (days > INT_MAX) {
                fprintf(stderr, "Days value of '%s' is outside valid range.\n",
                        optarg);
                goto cleanup;
            }
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
            errno = 0;
            spec_level = strtol(optarg, &endptr, 0);
            if (errno || endptr == optarg || *endptr != '\0') {
                fprintf(stderr, "Could not parse the spec level '%s'.\n",
                        optarg);
                goto cleanup;
            }
            if (spec_level < 0) {
                fprintf(stderr, "--tpm-spec-level must pass a positive number.\n");
                goto cleanup;
            }
            if (spec_level > UINT_MAX) {
                fprintf(stderr, "--tpm-spec-level is outside valid range.\n");
                goto cleanup;
            }
            break;
        case '9': /* --tpm-spec-revision */
            errno = 0;
            spec_revision = strtol(optarg, &endptr, 0);
            if (errno || endptr == optarg || *endptr != '\0') {
                fprintf(stderr, "Could not parse the spec revision '%s'.\n",
                        optarg);
                goto cleanup;
            }
            if (spec_revision < 0) {
                fprintf(stderr, "--tpm-spec-revision must pass a positive number.\n");
                goto cleanup;
            }
            if (spec_revision > UINT_MAX) {
                fprintf(stderr, "--tpm-spec-revision is outside valid range.\n");
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
            ret = 0;
            goto cleanup;
        case 'v': /* --version */
            versioninfo();
            ret = 0;
            goto cleanup;
        case 'h': /* --help */
            usage(argv[0]);
            ret = 0;
            goto cleanup;
        default:
            usage(argv[0]);
            goto cleanup;
        }
    }

    if (BITS_TO_BYTES(mpz_sizeinbase(serial, 2)) > sizeof(ser_number)) {
        fprintf(stderr, "Serial number is too large.\n");
        goto cleanup;
    }
    mpz_export(ser_number, &ser_number_len, 1, 1, 1, 0, serial);
    if (ser_number_len > sizeof(ser_number)) {
        fprintf(stderr, "Serial number is too large.\n");
        goto cleanup;
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
                            "--tpm-version must all be provided.\n");
            goto cleanup;
        }
        break;
    case CERT_TYPE_AIK:
        break;
    }

    switch (certtype) {
    case CERT_TYPE_PLATFORM:
        if (platf_manufacturer == NULL ||
            platf_model == NULL ||
            platf_version == NULL) {
            fprintf(stderr, "--platform-manufacturer and --platform-model and "
                            "--platform-version must all be provided.\n");
            goto cleanup;
        }
        break;
    case CERT_TYPE_EK:
        if (spec_family == NULL ||
            spec_level == UNSET_VALUE ||
            spec_revision == UNSET_VALUE) {
            fprintf(stderr, "--tpm-spec-family and --tpm-spec-level and "
                            "--tpm-spec-revision must all be provided.\n");
            goto cleanup;
        }
        break;
    case CERT_TYPE_AIK:
        break;
    }

    if (pubkey_filename) {
        if (!(fp = fopen(pubkey_filename, "r"))) {
            fprintf(stderr, "Could not open public key file: %s\n",
                    strerror(errno));
            goto cleanup;
        }
        pubkey = PEM_read_PUBKEY(fp, NULL, NULL, 0);
        CHECK_OSSL_NULLPTR(pubkey,
                           "Could not read PEM public key from %s.\n",
                           pubkey_filename);
        FCLOSE(fp);
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
        goto cleanup;
    }

    if (strstr(sigkey_filename, "pkcs11:") == sigkey_filename) {
        provider = OSSL_PROVIDER_try_load(NULL, "pkcs11", 1);
        CHECK_OSSL_NULLPTR1(provider, "Could not load provider 'pkcs11'.\n");

        if (!(sigkey = get_key_pkcs11(provider, sigkey_filename)))
            goto cleanup;
    } else {
        if (!(fp = fopen(sigkey_filename, "r"))) {
            fprintf(stderr, "Could not open signing key file: %s\n",
                    strerror(errno));
            goto cleanup;
        }
        sigkey = PEM_read_PrivateKey(fp, NULL, password_cb, sigkeypass);
        CHECK_OSSL_NULLPTR(sigkey,
                           "Could not read PEM signing key from %s.\n",
                           sigkey_filename);
        FCLOSE(fp);
    }

    /* The signing hash algorithm depends on the key */
    if (flags & CERT_TYPE_TPM2_F) {
        if (!(md = get_hashalg_for_signing(sigkey)))
            goto cleanup;
    }

    if (!(fp = fopen(issuercert_filename, "r"))) {
        fprintf(stderr, "Could not open issuer cert file: %s\n",
                strerror(errno));
        goto cleanup;
    }
    sigcert = PEM_read_X509(fp, NULL, NULL, NULL);
    CHECK_OSSL_NULLPTR(sigcert,
                       "Could not read certificate from %s.\n",
                       issuercert_filename);
    FCLOSE(fp);

    /* Build the certificate */
    crt = X509_new_ex(NULL, NULL);
    CHECK_OSSL_NULLPTR1(crt, "Out of memory.\n");

    oct = ASN1_OCTET_STRING_new();
    CHECK_OSSL_NULLPTR1(oct, "Out of memory.\n");

    /* Version */
    CHECK_OSSL_RETURN1(X509_set_version(crt, X509_VERSION_3) != 1,
                       "Could not set version on CRT.\n");

    /* Serial Number */
    bn_serial = BN_bin2bn(ser_number, ser_number_len, NULL);
    CHECK_OSSL_NULLPTR1(bn_serial, "Out of memory.\n");

    asn1_serial = BN_to_ASN1_INTEGER(bn_serial, NULL);
    CHECK_OSSL_NULLPTR1(asn1_serial, "Out of memory.\n");

    CHECK_OSSL_RETURN1(X509_set_serialNumber(crt, asn1_serial) != 1,
                       "Could not set serial on CRT.\n");

    /* Issuer */
    issuer_name = X509_get_subject_name(sigcert);
    CHECK_OSSL_NULLPTR1(issuer_name,
                        "Could not get subject name from signer cert.\n");

    CHECK_OSSL_RETURN1(!X509_set_issuer_name(crt, issuer_name),
                       "Could not set issuer name on CRT.\n");

    /* Validity */
    now = time(NULL);
    asn1_time = X509_time_adj(NULL, 0, &now);
    CHECK_OSSL_NULLPTR1(asn1_time, "Out of memory.\n");

    CHECK_OSSL_RETURN1(X509_set1_notBefore(crt, asn1_time) != 1,
                       "Could not set activation time on CRT.\n");
    if (days < 0) {
        ASN1_TIME_set_string(asn1_time, "99991231235959Z");
    } else {
        asn1_time = X509_time_adj_ex(asn1_time, days, 0, &now);
        CHECK_OSSL_NULLPTR1(asn1_time, "Out of memory.\n");
    }
    CHECK_OSSL_RETURN1(X509_set1_notAfter(crt, asn1_time) != 1,
                       "Could not set expiration time on CRT.\n");

    /* Subject -- must be empty for TPM 1.2 */
    if (subject && (flags & CERT_TYPE_TPM2_F)) {
        g_autofree char *s = g_strdup(subject);
        X509_NAME *name = X509_NAME_new();
        char *token, *equal;

        token = strtok(s, ",");
        do {
            while (isspace((int)*token))
                token++;
            equal = strchr(token, '=');
            if (equal) {
                g_autofree char *attr = g_strndup(token, equal - token);
                g_autofree char *val = g_strdup(&equal[1]);

                g_strchomp(attr);
                g_strstrip(val);
                CHECK_OSSL_RETURN1(
                    X509_NAME_add_entry_by_txt(name, attr, MBSTRING_ASC,
                                               (unsigned char *)val, -1, -1, 0) != 1,
                    "X509_NAME_add_entry_by_txt failed.\n");
            }
            token = strtok(NULL, ",");
        } while (token);

        CHECK_OSSL_RETURN1(X509_set_subject_name(crt, name) != 1,
                           "Could not set subject name.\n");
        X509_NAME_free(name);
    }

    /* Subject Public Key Info */

    /* Certificate Policies -- skip since not mandated */
    /* Subject Alternative Names */
    switch (certtype) {
    case CERT_TYPE_EK:
        err = create_tpm_manufacturer_info(tpm_manufacturer, tpm_model,
                                           tpm_version, &datum);
        if (err) {
            fprintf(stderr, "Could not create TPM manufacturer info.\n");
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
                fprintf(stderr, "Could not create platform manufacturer info.\n");
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
                fprintf(stderr, "Could not create TPM and platform manufacturer info.\n");
                goto cleanup;
            }
        }
        break;
    case CERT_TYPE_AIK:
        break;
    default:
        fprintf(stderr, "Internal error: unhandled case in line %d\n",
                __LINE__);
        goto cleanup;
    }

    if (datum.size > 0) {
        if (!prepend_san_asn1_header(&datum)) {
            fprintf(stderr, "Could not prepend SAN ASN.1 header.\n");
            goto cleanup;
        }
        ASN1_OCTET_STRING_set(oct, datum.data, datum.size);

        ext = X509_EXTENSION_create_by_NID(NULL, NID_subject_alt_name, 1, oct);
        CHECK_OSSL_NULLPTR1(ext,
                            "Could not create subject alternative name extension.\n");
        CHECK_OSSL_RETURN1(X509_add_ext(crt, ext, -1) != 1,
                           "Could not add extension to CRT.\n");
        X509_EXTENSION_free(ext);
        ext = NULL;
    }
    free_datum(&datum);

    /* Basic Constraints */
    ext = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, "critical, CA:FALSE");
    CHECK_OSSL_NULLPTR1(ext, "Out of memory.\n");

    CHECK_OSSL_RETURN1(X509_add_ext(crt, ext, -1) != 1,
                       "Could not add extension to CRT.\n");
    X509_EXTENSION_free(ext);
    ext = NULL;

    /* Subject Directory Attributes */
    switch (certtype) {
    case CERT_TYPE_EK:
        err = create_tpm_specification_info(spec_family, spec_level,
                                            spec_revision, &datum);
        if (err) {
            fprintf(stderr, "Could not create TPMSpecification.\n");
            goto cleanup;
        }
        break;
    case CERT_TYPE_PLATFORM:
    case CERT_TYPE_AIK:
        break;
    default:
        fprintf(stderr, "Internal error: unhandled case in line %d\n",
                __LINE__);
        goto cleanup;
    }

    if (datum.size > 0) {
        ASN1_OCTET_STRING_set(oct, datum.data, datum.size);

        ext = X509_EXTENSION_create_by_NID(NULL, NID_subject_directory_attributes, 0, oct);
        CHECK_OSSL_NULLPTR1(ext,
                            "Could not create subject directory attributes extension.\n");
        CHECK_OSSL_RETURN1(X509_add_ext(crt, ext, -1) != 1,
                           "Could not add extension to CRT.\n");
        X509_EXTENSION_free(ext);
        ext = NULL;
    }
    free_datum(&datum);

    /* Authority Key Id */
    X509V3_set_ctx_nodb(&x509v3_ctx);
    X509V3_set_ctx(&x509v3_ctx, sigcert, NULL, NULL, NULL, 0);
    ext = X509V3_EXT_conf_nid(NULL, &x509v3_ctx,
                              NID_authority_key_identifier, "keyid");
    CHECK_OSSL_NULLPTR1(ext, "Out of memory.\n");

    CHECK_OSSL_RETURN1(X509_add_ext(crt, ext, -1) != 1,
                       "Could not add extension to CRT.\n");
    X509_EXTENSION_free(ext);
    ext = NULL;

    /* Authority Info Access -- may be omitted */
    /* CRL Distribution -- missing  */

    /* Key Usage */
    switch (certtype) {
    case CERT_TYPE_EK:
    case CERT_TYPE_PLATFORM:
        if (flags & CERT_TYPE_TPM2_F) {
            /* support 'User Device TPM' and 'Non-User Device TPM' in spec */
            if (flags & ALLOW_SIGNING_F) {
                g_string_append(key_usage, ", digitalSignature");
            }
            if ((flags & (ALLOW_SIGNING_F | DECRYPTION_F)) == 0 ||
                (flags & DECRYPTION_F) == DECRYPTION_F) {
                if (is_ecc) {
                    g_string_append(key_usage, ", keyAgreement");
                } else {
                    g_string_append(key_usage, ", keyEncipherment");
                }
            }
        } else {
            g_string_append(key_usage, ", keyEncipherment");
        }
        break;
    case CERT_TYPE_AIK:
        g_string_append(key_usage, ", digitalSignature");
        break;
    default:
        fprintf(stderr, "Internal error: unhandled case in line %d\n",
                __LINE__);
        goto cleanup;
    }

    ext = X509V3_EXT_conf_nid(NULL, &x509v3_ctx, NID_key_usage, key_usage->str);
    CHECK_OSSL_NULLPTR1(ext, "Could not create key usage extension.\n");

    CHECK_OSSL_RETURN1(X509_add_ext(crt, ext, -1) != 1,
                       "Could not add extension to CRT.\n");
    X509_EXTENSION_free(ext);
    ext = NULL;

    /* Extended Key Usage */
    oid = NULL;

    switch (certtype) {
    case CERT_TYPE_EK:
        oid = "2.23.133.8.1";
        break;
    case CERT_TYPE_PLATFORM:
        oid = "2.23.133.8.2";
        break;
    case CERT_TYPE_AIK:
        break;
    default:
        fprintf(stderr, "Internal error: unhandled case in line %d\n",
                __LINE__);
        goto cleanup;
    }

    if (oid) {
        err = create_cert_extended_key_usage(oid, &datum);
        if (err) {
            fprintf(stderr, "Could not create ASN.1 for extended key usage.\n");
            goto cleanup;
        }
        ASN1_OCTET_STRING_set(oct, datum.data, datum.size);

        ext = X509_EXTENSION_create_by_NID(NULL, NID_ext_key_usage, 0, oct);
        CHECK_OSSL_NULLPTR1(ext, "Could not set extended key usage.\n");

        CHECK_OSSL_RETURN1(X509_add_ext(crt, ext, -1) != 1,
                           "Could not add extension to CRT.\n");

        X509_EXTENSION_free(ext);
        ext = NULL;

        free_datum(&datum);
    }

    /* Subject Key Id -- may be included */

    /* set public key */
    CHECK_OSSL_RETURN1(X509_set_pubkey(crt, pubkey) != 1,
                       "Could not set public EK on CRT.\n");

    /* sign cert */
    if (md == EVP_sha1())
        setenv("OPENSSL_ENABLE_SHA1_SIGNATURES", "1", 1);
    if (sigkey)
        CHECK_OSSL_RETURN1(X509_sign(crt, sigkey, md) == 0,
                           "Could not sign the certificate.\n");

    /* write the certificate */
    bp = BIO_new(BIO_s_mem());
    CHECK_OSSL_NULLPTR1(bp, "Out of memory.\n");

    if (write_pem) {
        CHECK_OSSL_RETURN1(!PEM_write_bio_X509(bp, crt),
                           "Could not write PEM certificate to buffer BIO.\n");
    } else {
        CHECK_OSSL_RETURN1(i2d_X509_bio(bp, crt) != 1,
                           "Could not write DER certificate to buffer BIO.\n");
    }

    out.size = BIO_get_mem_data(bp, &out.data);
    if (!out.data || !out.size) {
        fprintf(stderr, "The BIO did not have any data.\n");
        goto cleanup;
    }

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
    } else if (write_pem) {
        fprintf(stdout, "%.*s\n", out.size, out.data);
    }

    ret = 0;

cleanup:
    mpz_clear(serial);

    EVP_PKEY_free(pubkey);
    BIO_free(bp);
    ASN1_INTEGER_free(asn1_serial);
    ASN1_TIME_free(asn1_time);
    ASN1_OCTET_STRING_free(oct);
    BN_free(bn_serial);
    EVP_PKEY_free(sigkey);
    X509_EXTENSION_free(ext);
    X509_free(sigcert);
    X509_free(crt);
    OSSL_PROVIDER_unload(provider);
    if (fp)
        fclose(fp);

    g_string_free(key_usage, TRUE);
    free(sigkeypass);
    free(modulus_bin);
    free(ecc_x_bin);
    free(ecc_y_bin);
    asn_free();

    return ret;
}
