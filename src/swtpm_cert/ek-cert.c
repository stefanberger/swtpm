/*
 * ek-cert.c
 *
 * Authors: Stefan Berger <stefanb@us.ibm.com>
 *
 * (c) Copyright IBM Corporation 2014, 2015.
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

#include <arpa/inet.h>

#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>

#include "tpm_asn1.h"
#include "swtpm.h"

enum cert_type_t {
    CERT_TYPE_EK = 1,
    CERT_TYPE_PLATFORM,
    CERT_TYPE_AIK,
};

extern const ASN1_ARRAY_TYPE tpm_asn1_tab[];

ASN1_TYPE _tpm_asn;

static void
versioninfo(const char *prg)
{
    fprintf(stdout,
        "TPM certificate tool version %d.%d.%d, Copyright (c) 2015 IBM Corp.\n"
        ,SWTPM_VER_MAJOR, SWTPM_VER_MINOR, SWTPM_VER_MICRO);
}

static void
usage(const char *prg)
{
    versioninfo(prg);
    fprintf(stdout,
        "\nUsage: %s [options]\n"
        "\n"
        "Create TPM certificates without requiring the EK private key.\n"
        "\n"
        "The following options are supported:\n"
        "--pubkey <filename>       : PEM file for public key (EK)\n"
        "--signkey <filename>      : PEM file for CA signing key\n"
        "--signkey-password <pass> : Password for the CA signing key\n"
        "--issuercert <filename>   : PEM file with CA cert\n"
        "--out-cert <filename>     : Filename for certificate\n"
        "--modulus <hex string>    : The modulus of the public key\n"
        "--exponent <exponent>     : The exponent of the public key\n"
        "--serial <serial number>  : The certificate serial number\n"
        "--days <number>           : Number of days the cert is valid\n"
        "--pem                     : Write certificate in PEM format; default is DER\n"
        "--type <platform|ek>      : The type of certificate to create; default is ek\n"
        "--tpm-manufacturer <name> : The name of the TPM manufacturer\n"
        "--tpm-model <model>       : The TPM model (part number)\n"
        "--tpm-version <version>   : The TPM version (firmware version)\n"
        "--platform-manufacturer <name> : The name of the Platform manufacturer\n"
        "--platfrom-model <model>       : The Platform model (part number)\n"
        "--platform-version <version>   : The Platform version (firmware version)\n"
        "--subject <subject>       : Subject such as location in format\n"
        "                            C=US,ST=NY,L=NewYork\n"
        "--version                 : Display version and exit\n"
        "--help                    : Display this help screen and exit\n"
        "\n",
        prg);
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
        return NULL;
    }

    result = malloc(len / 2);
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

static int
create_tpm_manufacturer_info(const char *manufacturer,
                             const char *tpm_model,
                             const char *tpm_version,
                             gnutls_datum_t *asn1)
{
    ASN1_TYPE at = ASN1_TYPE_EMPTY;
    int err;

    err = asn_init();
    if (err != ASN1_SUCCESS) {
        goto cleanup;
    }

    err = asn1_create_element(_tpm_asn, "TPM.TPMManufacturerInfo", &at);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "asn1_create_element error: %d\n", err);
        goto cleanup;
    }

    err = asn1_write_value(at, "tpmManufacturer.id", "2.23.133.2.1", 0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "1. asn1_write_value error: %d\n", err);
        goto cleanup;
    }

    err = asn1_write_value(at, "tpmManufacturer.manufacturer",
                           manufacturer, 0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "2. asn1_write_value error: %d\n", err);
        goto cleanup;
    }
    
    err = asn1_write_value(at, "tpmModel.id", "2.23.133.2.2", 0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "3. asn1_write_value error: %d\n", err);
        goto cleanup;
    }

    err = asn1_write_value(at, "tpmModel.model", manufacturer, 0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "4. asn1_write_value error: %d\n", err);
        goto cleanup;
    }
    
    err = asn1_write_value(at, "tpmVersion.id", "2.23.133.2.3", 0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "5. asn1_write_value error: %d\n", err);
        goto cleanup;
    }

    err = asn1_write_value(at, "tpmVersion.version", manufacturer, 0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "6. asn1_write_value error: %d\n", err);
        goto cleanup;
    }
    
    /* determine needed size of byte array */
    asn1->size = 0;
    err = asn1_der_coding(at, "", NULL, (int *)&asn1->size, NULL);
    if (err != ASN1_MEM_ERROR) {
        fprintf(stderr, "1. asn1_der_coding error: %d\n", err);
        goto cleanup;
    }
    //fprintf(stderr, "size=%d\n", asn1->size);
    asn1->data = gnutls_malloc(asn1->size + 16);
    err = asn1_der_coding(at, "", asn1->data, (int *)&asn1->size, NULL);

    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "2. asn1_der_coding error: %d\n", err);
        gnutls_free(asn1->data);
        asn1->data = NULL;
        goto cleanup;
    }

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
create_platf_manufacturer_info(const char *manufacturer,
                               const char *platf_model,
                               const char *platf_version,
                               gnutls_datum_t *asn1)
{
    ASN1_TYPE at = ASN1_TYPE_EMPTY;
    int err;

    err = asn_init();
    if (err != ASN1_SUCCESS) {
        goto cleanup;
    }

    err = asn1_create_element(_tpm_asn, "TPM.PlatformManufacturerInfo", &at);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "asn1_create_element error: %d\n", err);
        goto cleanup;
    }

    err = asn1_write_value(at, "platformManufacturer.id", "2.23.133.2.4", 0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "b1. asn1_write_value error: %d\n", err);
        goto cleanup;
    }

    err = asn1_write_value(at, "platformManufacturer.manufacturer",
                           manufacturer, 0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "b2. asn1_write_value error: %d\n", err);
        goto cleanup;
    }
    
    err = asn1_write_value(at, "platformModel.id", "2.23.133.2.5", 0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "b3. asn1_write_value error: %d\n", err);
        goto cleanup;
    }

    err = asn1_write_value(at, "platformModel.model", manufacturer, 0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "b4. asn1_write_value error: %d\n", err);
        goto cleanup;
    }
    
    err = asn1_write_value(at, "platformVersion.id", "2.23.133.2.6", 0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "b5. asn1_write_value error: %d\n", err);
        goto cleanup;
    }

    err = asn1_write_value(at, "platformVersion.version", manufacturer, 0);
    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "b6. asn1_write_value error: %d\n", err);
        goto cleanup;
    }
    
    /* determine needed size of byte array */
    asn1->size = 0;
    err = asn1_der_coding(at, "", NULL, (int *)&asn1->size, NULL);
    if (err != ASN1_MEM_ERROR) {
        fprintf(stderr, "b1. asn1_der_coding error: %d\n", err);
        goto cleanup;
    }
    //fprintf(stderr, "size=%d\n", asn1->size);
    asn1->data = gnutls_malloc(asn1->size + 16);
    err = asn1_der_coding(at, "", asn1->data, (int *)&asn1->size, NULL);

    if (err != ASN1_SUCCESS) {
        fprintf(stderr, "b2. asn1_der_coding error: %d\n", err);
        gnutls_free(asn1->data);
        asn1->data = NULL;
        goto cleanup;
    }

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


int
main(int argc, char *argv[])
{
    int ret = 1;
    int i;
    gnutls_pubkey_t pubkey = NULL;
    gnutls_x509_privkey_t sigkey = NULL;
    gnutls_x509_crt_t sigcert = NULL;
    gnutls_x509_crt_t crt = NULL;
    const char *pubkey_filename = NULL;
    const char *sigkey_filename = NULL;
    const char *cert_filename = NULL;
    const char *modulus_str = NULL;
    const char *issuercert_filename = NULL;
    unsigned char *modulus_bin = NULL;
    int modulus_len = 0;
    gnutls_datum_t datum = { NULL, 0},  out = { NULL, 0};
    int serial = 1;
    time_t now;
    int err;
    FILE *cert_file;
    char *subject = NULL;
    const char *error = NULL;
    int days = 365;
    char *sigkeypass = NULL;
    uint32_t ser_number;
    long int exponent = 0x10001;
    bool write_pem = false;
    uint8_t id[512];
    size_t id_size = sizeof(id);
    enum cert_type_t certtype = CERT_TYPE_EK;
    const char *oid;
    unsigned int key_usage;
    char *tpm_manufacturer = NULL;
    char *tpm_version = NULL;
    char *tpm_model = NULL;
    char *platf_manufacturer = NULL;
    char *platf_version = NULL;
    char *platf_model = NULL;

    i = 1;
    while (i < argc) {
        if (!strcmp(argv[i], "--pubkey")) {
            i++;
            if (i == argc) {
                fprintf(stderr, "Missing argument for --pubkey.\n");
                goto cleanup;
            }
            pubkey_filename = argv[i];
        } else if (!strcmp(argv[i], "--modulus")) {
            i++;
            if (i == argc) {
                fprintf(stderr, "Missing argument for --modulus.\n");
                goto cleanup;
            }
            modulus_str = argv[i];
            if (!(modulus_bin = hex_str_to_bin(modulus_str, &modulus_len))) {
                goto cleanup;
            }
        } else if (!strcmp(argv[i], "--exponent")) {
            i++;
            if (i == argc) {
                fprintf(stderr, "Missing argument for --exponent.\n");
                goto cleanup;
            }
            exponent = strtol(argv[i], NULL, 0);
            if (exponent == 0) {
                fprintf(stderr, "Exponent is wrong and cannot be 0.\n");
                goto cleanup;
            }
            if (exponent > UINT_MAX) {
                fprintf(stderr, "Exponent must fit into 32bits.\n");
                goto cleanup;
            }
        } else if (!strcmp(argv[i], "--signkey")) {
            i++;
            if (i == argc) {
                fprintf(stderr, "Missing argument for --signkey.\n");
                goto cleanup;
            }
            sigkey_filename = argv[i];
        } else if (!strcmp(argv[i], "--signkey-password")) {
            i++;
            if (i == argc) {
                fprintf(stderr, "Missing argument for --signkey-password.\n");
                goto cleanup;
            }
            sigkeypass = argv[i];
        } else if (!strcmp(argv[i], "--issuercert")) {
            i++;
            if (i == argc) {
                fprintf(stderr, "Missing argument for --issuercert.\n");
                goto cleanup;
            }
            issuercert_filename = argv[i];
        } else if (!strcmp(argv[i], "--out-cert")) {
            i++;
            if (i == argc) {
                fprintf(stderr, "Missing argument for --out-cert.\n");
                goto cleanup;
            }
            cert_filename = argv[i];
        } else if (!strcmp(argv[i], "--subject")) {
            i++;
            if (i == argc) {
                fprintf(stderr, "Missing argument for --subject.\n");
                goto cleanup;
            }
            subject = argv[i];
        } else if (!strcmp(argv[i], "--days")) {
            i++;
            if (i == argc) {
                fprintf(stderr, "Missing argument for --days.\n");
                goto cleanup;
            }
            days = atoi(argv[i]);
        } else if (!strcmp(argv[i], "--serial")) {
            i++;
            if (i == argc) {
                fprintf(stderr, "Missing argument for --serial.\n");
                goto cleanup;
            }
            serial = atoi(argv[i]);
        } else if (!strcmp(argv[i], "--type")) {
            i++;
            if (i == argc) {
                fprintf(stderr, "Missing argument for --type.\n");
                goto cleanup;
            }
            if (!strcasecmp(argv[i], "ek")) {
                certtype = CERT_TYPE_EK;
            } else if (!strcasecmp(argv[i], "platform")) {
                certtype = CERT_TYPE_PLATFORM;
//            } else if (!strcasecmp(argv[i], "aik")) {
//                /* AIK cert needs EK cert as input */
//                certtype = CERT_TYPE_AIK;
            } else {
                fprintf(stderr, "Unknown certificate type '%s'.\n",
                        argv[i]);
                goto cleanup;
            }
        } else if (!strcmp(argv[i], "--tpm-manufacturer")) {
            i++;
            if (i == argc) {
                fprintf(stderr, "Missing argument for --tpm-manufacturer.\n");
                goto cleanup;
            }
            tpm_manufacturer = argv[i];
        } else if (!strcmp(argv[i], "--tpm-model")) {
            i++;
            if (i == argc) {
                fprintf(stderr, "Missing argument for --tpm-model.\n");
                goto cleanup;
            }
            tpm_model = argv[i];
        } else if (!strcmp(argv[i], "--tpm-version")) {
            i++;
            if (i == argc) {
                fprintf(stderr, "Missing argument for --tpm-version.\n");
                goto cleanup;
            }
            tpm_version = argv[i];
        } else if (!strcmp(argv[i], "--platform-manufacturer")) {
            i++;
            if (i == argc) {
                fprintf(stderr, "Missing argument for --platform-manufacturer.\n");
                goto cleanup;
            }
            platf_manufacturer = argv[i];
        } else if (!strcmp(argv[i], "--platform-model")) {
            i++;
            if (i == argc) {
                fprintf(stderr, "Missing argument for --platform-model.\n");
                goto cleanup;
            }
            platf_model = argv[i];
        } else if (!strcmp(argv[i], "--platform-version")) {
            i++;
            if (i == argc) {
                fprintf(stderr, "Missing argument for --platform-version.\n");
                goto cleanup;
            }
            platf_version = argv[i];
        } else if (!strcmp(argv[i], "--pem")) {
            write_pem = true;
        } else if (!strcmp(argv[i], "--version")) {
            versioninfo(argv[0]);
            exit(0);
        } else if (!strcmp(argv[i], "--help")) {
            usage(argv[0]);
            exit(0);
        } else {
            fprintf(stderr, "Unknown command line parameter '%s'.\n", argv[i]);
            usage(argv[0]);
            exit(1);
        }
        i++;
    }
    
    ser_number = htonl(serial);

    if (pubkey_filename == NULL && modulus_bin == NULL) {
        fprintf(stderr, "Missing public EK file and modulus.\n");
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
    case CERT_TYPE_AIK:
        break;
    }

    err = gnutls_global_init();
    if (err < 0) {
            fprintf(stderr, "gnutls_global_init failed.\n");
            goto cleanup;
    }
    gnutls_x509_privkey_init(&sigkey);

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
        pubkey = create_rsa_from_modulus(modulus_bin, modulus_len,
                                         exponent);
        free(modulus_bin);
        modulus_bin = NULL;

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

    err = gnutls_load_file(sigkey_filename, &datum);
    CHECK_GNUTLS_ERROR(err, "Could not read signing key from file %s: %s\n",
                       sigkey_filename, gnutls_strerror(err));

    if (sigkeypass) {
        err = gnutls_x509_privkey_import2(sigkey, &datum, GNUTLS_X509_FMT_PEM,
                                          sigkeypass, 0);
    } else {
        err = gnutls_x509_privkey_import(sigkey, &datum, GNUTLS_X509_FMT_PEM);
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
    CHECK_GNUTLS_ERROR(err, "Could not import issuer certificate: %s\n",
                       gnutls_strerror(err));

    err = gnutls_x509_crt_init(&crt);
    CHECK_GNUTLS_ERROR(err, "CRT init failed: %s\n", gnutls_strerror(err))

    /* 3.5.1 Version */
    err = gnutls_x509_crt_set_version(crt, 3);
    CHECK_GNUTLS_ERROR(err, "Could not set version on CRT: %s\n",
                       gnutls_strerror(err))

    /* 3.5.2 Serial Number */
    err = gnutls_x509_crt_set_serial(crt, &ser_number, sizeof(ser_number));
    CHECK_GNUTLS_ERROR(err, "Could not set serial on CRT: %s\n",
                       gnutls_strerror(err))

    /* 3.5.5 Validity */
    now = time(NULL);
    err = gnutls_x509_crt_set_activation_time(crt, now);
    CHECK_GNUTLS_ERROR(err, "Could not set activation time on CRT: %s\n",
                       gnutls_strerror(err))

    err = gnutls_x509_crt_set_expiration_time(crt,
             now + (time_t)days * 24 * 60 * 60);
    CHECK_GNUTLS_ERROR(err, "Could not set expiration time on CRT: %s\n",
                       gnutls_strerror(err))

    /* 3.5.6 Subject -- should be empty, but we allow it anyway */
    if (subject) {
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
    /* 3.5.9 Subject Alternative Names -- missing code */
    err = create_tpm_manufacturer_info(tpm_manufacturer, tpm_model,
                                       tpm_version, &datum);
    if (!err && datum.size > 0) {
        /*
         * GNUTLS's write_new_general_name can only handle a few GNUTLS_SAN_*
         * -> we have to use GNUTLS_SAN_URI
         */
        err = gnutls_x509_crt_set_subject_alt_name(crt,
                                                   GNUTLS_SAN_URI,
                                                   datum.data, datum.size,
                                                   GNUTLS_FSAN_SET);
        CHECK_GNUTLS_ERROR(err, "Could not set subject alt name: %s\n",
                           gnutls_strerror(err))
    }
    gnutls_free(datum.data);
    datum.data = NULL;
    datum.size = 0;

    switch (certtype) {
    case CERT_TYPE_PLATFORM:
        err = create_platf_manufacturer_info(platf_manufacturer, platf_model,
                                             platf_version, &datum);
        break;
    case CERT_TYPE_AIK:
    case CERT_TYPE_EK:
        break;
    default:
        fprintf(stderr, "Internal error: unhandle case in line %d\n",
                __LINE__);
        goto cleanup;
    }

    if (!err && datum.size > 0) {
        /*
         * GNUTLS's write_new_general_name can only handle a few GNUTLS_SAN_*
         * -> we have to use GNUTLS_SAN_URI
         */
        err = gnutls_x509_crt_set_subject_alt_name(crt,
                                                   GNUTLS_SAN_URI,
                                                   datum.data, datum.size,
                                                   GNUTLS_FSAN_APPEND);
        CHECK_GNUTLS_ERROR(err, "Could not append to subject alt name: %s\n",
                           gnutls_strerror(err))
    }
    gnutls_free(datum.data);
    datum.data = NULL;

    /* 3.5.10 Basic Constraints */
    err = gnutls_x509_crt_set_basic_constraints(crt, 0, -1);
    CHECK_GNUTLS_ERROR(err, "Could not set key usage id: %s\n",
                       gnutls_strerror(err))
    /* 3.5.11 Subject Directory Attributes -- missing */

    /* 3.5.12 Authority Key Id */
    err = gnutls_x509_crt_get_key_id(sigcert, 0, id, &id_size);
    if (err == GNUTLS_E_SUCCESS && id_size > 0) {
        err = gnutls_x509_crt_set_authority_key_id(crt, id, id_size);
        CHECK_GNUTLS_ERROR(err, "Could not set the authority key id: %s\n",
                           gnutls_strerror(err))
    }
    /* 3.5.13 Authority Info Access -- may be omitted */
    /* 3.5.14 CRL Distribution -- missing  */

    /* 3.5.15 Key Usage */
    switch (certtype) {
    case CERT_TYPE_EK:
    case CERT_TYPE_PLATFORM:
        key_usage = GNUTLS_KEY_KEY_ENCIPHERMENT;
        break;
    case CERT_TYPE_AIK:
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

    /* 3.5.16 Extended Key Usage -- missing */
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
    err = gnutls_x509_crt_sign(crt, sigcert, sigkey);
    CHECK_GNUTLS_ERROR(err, "Could not sign the CRT: %s\n",
                       gnutls_strerror(err))

    /* write cert to file; either PEM or DER */
    gnutls_x509_crt_export2(crt,
                            (write_pem)
                            ? GNUTLS_X509_FMT_PEM
                            : GNUTLS_X509_FMT_DER, &out);
    if (cert_filename) {
        cert_file = fopen(cert_filename, "wb");
        if (cert_file == NULL) {
            fprintf(stderr, "Could not open %s for writing the certificate: %s\n",
                    cert_filename,
                    strerror(errno));
            goto cleanup;
        }
        if (out.size != fwrite(out.data, 1, out.size, cert_file)) {
            fprintf(stderr, "Could not write certificate into file: %s\n",
                    strerror(errno));
            fclose(cert_file);
            goto cleanup;
        }
        fclose(cert_file);
    } else {
        fprintf(stdout, "%s\n", out.data);
    }

    ret = 0;

cleanup:
    gnutls_free(out.data);

    gnutls_x509_crt_deinit(crt);
    gnutls_x509_crt_deinit(sigcert);
    gnutls_x509_privkey_deinit(sigkey);
    gnutls_pubkey_deinit(pubkey);

    gnutls_global_deinit();

    return ret;
}
