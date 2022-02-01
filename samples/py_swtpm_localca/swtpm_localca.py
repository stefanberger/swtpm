#!/usr/bin/env python3
""" swtpm_localca.py

A tool for creating TPM 1.2 and TPM 2 certificates localy or using pkcs11
"""

# Disable a couple of warnings:
# R0911: Too many return statements (10/6) (too-many-return-statements)
# R0912: Too many branches (15/12) (too-many-branches)
# R0913: Too many arguments (14/5) (too-many-arguments)
# R0914: Too many local variables (21/15) (too-many-locals)
# R0915: Too many statements (57/50) (too-many-statements)
# W0703: Catching too general exception Exception (broad-except)
# pylint: disable=W0703,R0911,R0912,R0913,R0914,R0915

#
# swtpm_localca.py
#
# Authors: Stefan Berger <stefanb@linux.ibm.com>
#
# (c) Copyright IBM Corporation 2020
#

import codecs
import fcntl
import getopt
import getpass
import os
import re
import stat
import subprocess
import sys
import tempfile

from py_swtpm_localca.swtpm_localca_conf import SYSCONFDIR
from py_swtpm_localca.swtpm_utils import logit, logerr

# Some flags
SETUP_TPM2_F = 1
# for TPM 2 EK
ALLOW_SIGNING_F = 2
DECRYPTION_F = 4


XCH = os.getenv("XDG_CONFIG_HOME")
HOME = os.getenv("HOME")

LOCALCA_OPTIONS = "swtpm-localca.options"
if XCH and os.access(os.path.join(XCH, LOCALCA_OPTIONS), os.R_OK):
    DEFAULT_LOCALCA_OPTIONS = os.path.join(XCH, LOCALCA_OPTIONS)
elif HOME and os.access(os.path.join(HOME, ".config", LOCALCA_OPTIONS), os.R_OK):
    DEFAULT_LOCALCA_OPTIONS = os.path.join(HOME, ".config", LOCALCA_OPTIONS)
else:
    DEFAULT_LOCALCA_OPTIONS = os.path.join(os.sep + SYSCONFDIR, LOCALCA_OPTIONS)

LOCALCA_CONFIG = "swtpm-localca.conf"
if XCH and os.access(os.path.join(XCH, LOCALCA_CONFIG), os.R_OK):
    DEFAULT_LOCALCA_CONFIG = os.path.join(XCH, LOCALCA_CONFIG)
elif HOME and os.access(os.path.join(HOME, ".config", LOCALCA_CONFIG), os.R_OK):
    DEFAULT_LOCALCA_CONFIG = os.path.join(HOME, ".config", LOCALCA_CONFIG)
else:
    DEFAULT_LOCALCA_CONFIG = os.path.join(os.sep + SYSCONFDIR, LOCALCA_CONFIG)

# Default logging goes to stderr
LOGFILE = ""

def resolve_string(inp):
    """ resolve environment variables in a string """
    result = ""
    sidx = 0

    while True:
        idx = inp.find("${", sidx)
        if idx < 0:
            if sidx == 0:
                return inp
            result += inp[sidx:]
            return result

        result += inp[sidx:idx]
        eidx = inp.find("}", idx + 2)
        if eidx < 0:
            result += inp[idx:]
            return result

        result += os.getenv(inp[idx + 2:eidx], '')
        sidx = eidx + 1


def get_config_value(lines, configname, default=None):
    """ Get a config value from a list of strings """
    regex = r'^' + configname + r"\s*=\s*([^#\n]*).*"
    for line in lines:
        match = re.match(regex, line)
        if match:
            return resolve_string(match.groups()[0])
    return default


def get_config_envvars(lines):
    """ Extract all environment variables from the config file and return a map.
        Environment variable lines must start with 'env:' and must not contain
        trailing spaces or a comment starting with '#' """
    res = {}

    regex = r"^env:([a-zA-Z_][a-zA-Z_0-9]*)\s*=\s*([^\n]*).*"
    for line in lines:
        match = re.match(regex, line)
        if match:
            try:
                encoded = codecs.encode(match.group(2), "latin-1", "backslashreplace")
                res[match.group(1)] = codecs.decode(encoded, "unicode_escape")
            except Exception as err:
                logerr(LOGFILE, "Invalid character in value of %s environment variable: %s\n" %
                       (match.group(1), str(err)))
                return {}, 1

    return res, 0


def write_file(filename, text):
    """ Write some text to a file """
    try:
        fileobj = open(filename, "w")
        fileobj.write(text)
        fileobj.close()
        return 0
    except Exception as err:
        logerr(LOGFILE, "Could not write to file %s: %s\n" % (filename, str(err)))
        return 1


def read_file(filename):
    """ read contents from a file """
    try:
        fobj = open(filename, mode='rb')
        result = fobj.read()
        fobj.close()
        return result, 0
    except Exception as err:
        logerr(LOGFILE, "Could not read from file %s: %s\n" % (filename, str(err)))
        return "", 1


def read_file_lines(filename):
    """ Read the lines from a file and return a list of the lines """
    try:
        fobj = open(filename, 'r')
        lines = fobj.readlines()
        fobj.close()
        return lines, 0
    except Exception as err:
        logerr(LOGFILE, "Could not read from file %s : %s\n" & (filename, str(err)))
        return [], 1


def makedir(dirname, purpose):
    """ Create a directory if it does not exist """
    if not os.path.exists(dirname):
        logit(LOGFILE, "Creating swtpm-local dir '%s'.\n" % dirname)
        try:
            os.makedirs(dirname)
        except OSError as err:
            logerr(LOGFILE, "Could not create directory for '%s': %s\n" % (purpose, str(err)))
            return 1
    return 0


def remove_file(filename, verbose=True):
    """ remove a file """
    if not os.path.exists(filename):
        return 0
    try:
        os.remove(filename)
        return 0
    except Exception as err:
        if verbose:
            logerr(LOGFILE, "Could not remove file %s: %s\n" % (filename, str(err)))
        return 1


def remove_files(filename_list):
    """ remove files in a list of filenames """
    for filename in filename_list:
        remove_file(filename, verbose=False)


def get_certtool():
    """ Get the name of the certtool to use """
    if os.uname().sysname == "Darwin":
        return "gnutls-certtool"
    return "certtool"


def create_localca_cert(lockfile, statedir, signkey, signkey_password, issuercert):
    """ Create the local CA's certificate if it doesn't already exist. """
    try:
        filedes = os.open(lockfile, os.O_RDWR|os.O_CREAT)
    except Exception as err:
        logerr(LOGFILE, "Could not open lockfile %s: %s\n" % (lockfile, str(err)))
        return 1

    try:
        fcntl.flock(filedes, fcntl.LOCK_EX)

        if not os.path.exists(statedir):
            if makedir(statedir, "statedir") != 0:
                return 1
        if not os.access(signkey, os.R_OK) or not os.access(issuercert, os.R_OK):
            directory = os.path.dirname(signkey)
            cakey = os.path.join(directory, "swtpm-localca-rootca-privkey.pem")
            cacert = os.path.join(directory, "swtpm-localca-rootca-cert.pem")

            swtpm_rootca_password = os.getenv("SWTPM_ROOTCA_PASSWORD")
            certtool = get_certtool()

            # First the root CA
            cmd = [certtool, "--generate-privkey", "--outfile", cakey]
            if swtpm_rootca_password:
                # neither env. variable nor template file work...
                cmd.extend(["--password", swtpm_rootca_password])

            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                output = proc.communicate()[0]
                if proc.returncode:
                    logerr(LOGFILE, "Could not create root-CA key %s\n" % cakey)
                    logerr(LOGFILE, "%s" % output.decode())
                    return 1
            except Exception as err:
                logerr(LOGFILE, "Could not create root-CA key %s: %s\n" % (cakey, str(err)))
                return 1

            os.chmod(cakey, stat.S_IRUSR|stat.S_IWUSR|stat.S_IRGRP)

            temp = tempfile.NamedTemporaryFile()
            try:
                filecontent = \
                    "cn=swtpm-localca-rootca\n" \
                    "ca\n" \
                    "cert_signing_key\n" \
                    "expiration_days = 3650\n"
                temp.write(filecontent.encode())
                temp.seek(0)
                cmd = [certtool,
                       "--generate-self-signed",
                       "--template", temp.name,
                       "--outfile", cacert,
                       "--load-privkey", cakey]

                certtool_env = {
                    "PATH": os.getenv("PATH")
                }
                if swtpm_rootca_password:
                    certtool_env["GNUTLS_PIN"] = swtpm_rootca_password

                try:
                    proc = subprocess.Popen(cmd, env=certtool_env,
                                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                    output = proc.communicate()[0]
                    if proc.returncode:
                        logerr(LOGFILE, "Could not create root-CA\n")
                        logerr(LOGFILE, "%s" % output.decode())
                        remove_files([cakey, cacert])
                        return 1
                except Exception as err:
                    logerr(LOGFILE, "Could not create root-CA: %s\n" % str(err))
                    remove_files([cakey, cacert])
                    return 1
            finally:
                temp.close()

            # intermediate CA
            cmd = [certtool, "--generate-privkey", "--outfile", signkey]
            if signkey_password:
                cmd.extend(["--password", signkey_password])

            try:
                proc = subprocess.Popen(cmd,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                output = proc.communicate()[0]
                if proc.returncode:
                    logerr(LOGFILE, "Could not create local-CA key %s\n" % signkey)
                    logerr(LOGFILE, "certtool failed: %s\n" % output.decode())
                    remove_files([cakey, cacert, signkey])
                    return 1
            except Exception as err:
                logerr(LOGFILE, "Could not create local-CA key %s: %s\n" % (signkey, str(err)))
                remove_files([cakey, cacert, signkey])
                return 1

            os.chmod(signkey, stat.S_IRUSR|stat.S_IWUSR|stat.S_IRGRP)

            temp = tempfile.NamedTemporaryFile()
            try:
                filecontent = \
                    "cn=swtpm-localca\n" \
                    "ca\n" \
                    "cert_signing_key\n" \
                    "expiration_days = 3650\n"
                if swtpm_rootca_password and signkey_password:
                    filecontent += "password = %s\n" % swtpm_rootca_password
                temp.write(filecontent.encode())
                temp.seek(0)

                cmd = [certtool,
                       "--generate-certificate",
                       "--template", temp.name,
                       "--outfile", issuercert,
                       "--load-privkey", signkey,
                       "--load-ca-privkey", cakey,
                       "--load-ca-certificate", cacert]

                certtool_env = {
                    "PATH": os.getenv("PATH")
                }
                if signkey_password:
                    certtool_env["GNUTLS_PIN"] = signkey_password
                elif swtpm_rootca_password:
                    certtool_env["GNUTLS_PIN"] = swtpm_rootca_password

                try:
                    proc = subprocess.Popen(cmd, env=certtool_env,
                                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                    output = proc.communicate()[0]
                    if proc.returncode:
                        logerr(LOGFILE, "Could not create local CA\n")
                        logerr(LOGFILE, "%s" % output.decode())
                        remove_files([cakey, cacert, signkey, issuercert])
                        return 1
                except Exception as err:
                    logerr(LOGFILE, "Could not create local CA: %s\n" % str(err))
                    remove_files([cakey, cacert, signkey, issuercert])
                    return 1
            finally:
                temp.close()
    finally:
        os.close(filedes)

    return 0


def get_next_cert_serial(certserial, lockfile):
    """ Get the next serial number for a certificate """
    try:
        filedes = os.open(lockfile, os.O_RDWR|os.O_CREAT)
    except Exception as err:
        logerr(LOGFILE, "Could not open lockfile %s: %s\n" % (lockfile, str(err)))
        return 1

    try:
        fcntl.flock(filedes, fcntl.LOCK_EX)

        if not os.access(certserial, os.R_OK):
            _ = write_file(certserial, "1")
        serial, ret = read_file(certserial)
        if ret != 0:
            return "", 1
        if not serial.decode().isnumeric():
            serial_n = 1
        else:
            serial_n = int(serial) + 1
        ret = write_file(certserial, "%d" % serial_n)
        if ret != 0:
            return "", 1
    finally:
        os.close(filedes)

    return "%d" % serial_n, 0


def create_cert(flags, typ, directory, ekparams, vmid, tpm_spec_params, tpm_attr_params,
                signkey, signkey_password, issuercert, parentkey_password, swtpm_cert_env,
                certserial, lockfile, optsfile):
    """ Create the certificate """
    serial, ret = get_next_cert_serial(certserial, lockfile)
    if ret != 0:
        return 1

    options = []
    lines, _ = read_file_lines(optsfile)
    for line in lines:
        if not line.strip():
            continue
        options.extend([x.strip() for x in line.split(" ", 1)])

    if vmid:
        subj = "CN=%s" % vmid
    else:
        subj = "CN=unknown"

    if flags & SETUP_TPM2_F:
        options.append("--tpm2")
    else:
        options.append("--add-header")

    if typ == "ek":
        if flags & ALLOW_SIGNING_F:
            options.append("--allow-signing")
        if flags & DECRYPTION_F:
            options.append("--decryption")

    match = re.search(r'x=([0-9A-Fa-f]+),y=([0-9A-Fa-f]+)(,id=([^,]+))?', ekparams)
    if match:
        keyparams = ["--ecc-x", match.group(1), "--ecc-y", match.group(2)]
        if match.group(4):
            keyparams.extend(["--ecc-curveid", match.group(4)])
    else:
        keyparams = ["--modulus", ekparams]

    cmd = ["swtpm_cert",
           "--subject", subj]
    cmd.extend(options)

    temp1 = None
    temp2 = None

    if signkey_password:
        temp1 = tempfile.NamedTemporaryFile()
        temp1.write(signkey_password.encode())
        temp1.seek(0)
        cmd.extend(["--signkey-pwd", "file:%s" % temp1.name])

    if parentkey_password:
        temp2 = tempfile.NamedTemporaryFile()
        temp2.write(parentkey_password.encode())
        temp2.seek(0)
        cmd.extend(["--parentkey-pwd", "file:%s" % temp2.name])

    if typ == "ek":
        cmd.extend(tpm_spec_params)

    cmd.extend(tpm_attr_params)

    if typ == "platform":
        cmd.extend(["--type", "platform",
                    "--out-cert", os.path.join(directory, "platform.cert")])
    else:
        cmd.extend(["--out-cert", os.path.join(directory, "ek.cert")])

    cmd.extend(keyparams)
    cmd.extend(["--signkey", signkey,
                "--issuercert", issuercert,
                "--days", "3650",
                "--serial", serial])

    if typ == "ek":
        certtype = "EK"
    else:
        certtype = "platform"

    try:
        proc = subprocess.Popen(cmd, env=swtpm_cert_env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output = proc.communicate()[0]
        if proc.returncode:
            logerr(LOGFILE, "Could not create %s certificate locally\n" % certtype)
            logerr(LOGFILE, "%s" % output.decode())
            return 1
    except Exception as err:
        logerr(LOGFILE, "Could not run swtpm_cert: %s\n" % str(err))
        return 1
    finally:
        if temp1:
            temp1.close()
        if temp2:
            temp2.close()

    logit(LOGFILE, "Successfully created %s certificate locally.\n" % certtype)

    return 0


def usage(prgname):
    """ Display usage """
    print(
        "Usage: {prgname} [options]\n"
        "\n"
        "The following options are supported:\n"
        "\n"
        "--type type           The type of certificate to create: 'ek' or 'platform'\n"
        "--ek key-param        The modulus of an RSA key or x=...,y=,... for an EC key\n"
        "--dir directory       The directory to write the resulting certificate into\n"
        "--vmid vmid           The ID of the virtual machine\n"
        "--optsfile file       A file containing options to pass to swtpm_cert\n"
        "--configfile file     A file containing configuration parameters for directory,\n"
        "                      signing key and password and certificate to use\n"
        "--logfile file        A file to write a log into\n"
        "--tpm-spec-family s   The implemented spec family, e.g., '2.0'\n"
        "--tpm-spec-revision i The spec revision of the TPM as integer; e.g., 146\n"
        "--tpm-spec-level i    The spec level of the TPM; must be an integer; e.g. 0\n"
        "--tpm-manufacturer s  The manufacturer of the TPM; e.g., id:00001014\n"
        "--tpm-model s         The model of the TPM; e.g., 'swtpm'\n"
        "--tpm-version i       The (firmware) version of the TPM; e.g., id:20160511\n"
        "--tpm2                Generate a certificate for a TPM 2\n"
        "--allow-signing       The TPM 2's EK can be used for signing\n"
        "--decryption          The TPM 2's EK can be used for decryption\n"
        "--help, -h, -?        Display this help screen and exit\n"
        "\n"
        "\n"
        "The following environment variables are supported:\n"
        "\n"
        "SWTPM_ROOTCA_PASSWORD  The root CA's private key password\n"
        "\n".format_map({
            'prgname': prgname,
        }))


def main():
    """ main function - parses command line parameters and low level dealing with them """
    global LOGFILE # pylint: disable=W0603

    try:
        opts, _ = getopt.getopt(sys.argv[1:], "h?",
                                ["type=",
                                 "ek=",
                                 "dir=",
                                 "vmid=",
                                 "optsfile=",
                                 "configfile=",
                                 "logfile=",
                                 "tpm-spec-family=",
                                 "tpm-spec-revision=",
                                 "tpm-spec-level=",
                                 "tpm-manufacturer=",
                                 "tpm-model=",
                                 "tpm-version=",
                                 "tpm2",
                                 "allow-signing",
                                 "decryption",
                                 "help"])
    except getopt.GetoptError as err:
        print(err)
        usage(sys.argv[0])
        sys.exit(1)

    flags = 0
    typ = ""
    ekparams = ""
    directory = ""
    vmid = ""
    optsfile = DEFAULT_LOCALCA_OPTIONS
    configfile = DEFAULT_LOCALCA_CONFIG
    tpm_spec_params = []
    tpm_attr_params = []

    for opt, arg in opts:
        if opt == '--type':
            typ = arg
        elif opt == '--ek':
            ekparams = arg
        elif opt == '--dir':
            directory = arg
        elif opt == '--vmid':
            vmid = arg
        elif opt == '--optsfile':
            optsfile = arg
        elif opt == '--configfile':
            configfile = arg
        elif opt == '--logfile':
            LOGFILE = arg
        elif opt in ['--tpm-spec-family', '--tpm-spec-revision', '--tpm-spec-level']:
            tpm_spec_params.extend([opt, arg])
        elif opt in ['--tpm-manufacturer', '--tpm-model', '--tpm-version']:
            tpm_attr_params.extend([opt, arg])
        elif opt == '--tpm2':
            flags |= SETUP_TPM2_F
        elif opt == '--allow-signing':
            flags |= ALLOW_SIGNING_F
        elif opt == '--decryption':
            flags |= DECRYPTION_F
        elif opt in ['--help', '-h', '-?']:
            usage(sys.argv[0])
            sys.exit(0)

    if len(LOGFILE) > 0:
        if os.path.islink(LOGFILE):
            sys.stderr.write("Logfile must not be a symlink.\n")
            sys.exit(1)
        try:
            fobj = open(LOGFILE, "a") # do not truncate
            fobj.close()
        except PermissionError:
            sys.stderr.write("Cannot write to logfile %s.\n", LOGFILE)
            sys.exit(1)

    if not os.access(optsfile, os.R_OK):
        logerr(LOGFILE, "Need read rights on options file %s for user %s.\n" %
               (optsfile, getpass.getuser()))
        sys.exit(1)

    if not os.access(configfile, os.R_OK):
        logerr(LOGFILE, "Need read rights on options file %s for user %s.\n" %
               (configfile, getpass.getuser()))
        sys.exit(1)

    lines, ret = read_file_lines(configfile)
    if ret != 0:
        sys.exit(1)

    statedir = get_config_value(lines, "statedir")
    if not statedir:
        logerr(LOGFILE, "Missing 'statedir' config value in config file %s.\n" % configfile)
        sys.exit(1)
    if not os.access(statedir, os.W_OK | os.R_OK):
        logerr(LOGFILE, "Need read/write rights on statedir %s for user %s.\n" %
               (statedir, getpass.getuser()))
    if makedir(statedir, "statedir") != 0:
        sys.exit(1)

    lockfile = os.path.join(statedir, ".lock.swtpm-localca")
    if os.path.exists(lockfile) and not os.access(lockfile, os.W_OK | os.R_OK):
        logerr(LOGFILE, "Need read/write rights on %s for user %s.\n" %
               (lockfile, getpass.getuser()))
        sys.exit(1)

    signkey = get_config_value(lines, "signingkey")
    if not signkey:
        logerr(LOGFILE, "Missing 'signingkey' config value in config file %s.\n" % configfile)
        sys.exit(1)

    # SIGNKEY may be a GNUTLS url like tpmkey:file= or tpmkey:uuid=
    if not signkey.startswith("tpmkey:file=") and \
       not signkey.startswith("tpmkey:uuid=") and \
       not signkey.startswith("pkcs11:"):
        if makedir(os.path.dirname(signkey), "signkey") != 0:
            sys.exit(1)

    signkey_password = get_config_value(lines, "signingkey_password")
    parentkey_password = get_config_value(lines, "parentkey_password")

    issuercert = get_config_value(lines, 'issuercert')
    if not issuercert:
        logerr(LOGFILE, "Missing 'issuercert' config value in config file %s.\n" % configfile)
        sys.exit(1)
    if makedir(os.path.dirname(issuercert), "issuercert") != 0:
        sys.exit(1)

    # environment needed for calling swtpm_cert
    swtpm_cert_env = os.environ

    # TPM keys are GNUTLS URIs...
    if signkey.startswith("tpmkey:file=") or signkey.startswith("tpmkey:uuid="):
        tss_tcsd_hostname = get_config_value(lines, "TSS_TCSD_HOSTNAME", "localhost")
        tss_tcsd_port = get_config_value(lines, "TSS_TCSD_PORT", 30003)
        swtpm_cert_env["TSS_TCSD_HOSTNAME"] = tss_tcsd_hostname
        swtpm_cert_env["TSS_TCSD_PORT"] = tss_tcsd_port

        logit(LOGFILE, "CA uses a GnuTLS TPM key; using TSS_TCSD_HOSTNAME=%s " \
			"TSS_TCSD_PORT=%s\n" % (tss_tcsd_hostname, tss_tcsd_port))
    elif signkey.startswith("pkcs11:"):
        signkey = signkey.replace(r"\;", ";")
        if signkey_password:
            swtpm_cert_env["SWTPM_PKCS11_PIN"] = signkey_password
            logit(LOGFILE, "CA uses a PKCS#11 key; using password from 'signingkey_password'\n")
        else:
            swtpm_pkcs11_pin = get_config_value(lines, "SWTPM_PKCS11_PIN", "swtpm-tpmca")
            swtpm_cert_env["SWTPM_PKCS11_PIN"] = swtpm_pkcs11_pin
            logit(LOGFILE, "CA uses a PKCS#11 key; using SWTPM_PKCS11_PIN\n")
        # Get additional environment variables pkcs11 modules may need
        envvars, ret = get_config_envvars(lines)
        if ret != 0:
            sys.exit(1)
        swtpm_cert_env.update(envvars)
    else:
        create_certs = False
        # create certificate if either the signing key or issuer cert are missing
        if not os.access(signkey, os.R_OK):
            if os.path.exists(signkey):
                logerr(LOGFILE, "Need read rights on signing key %s for user %s.\n" %
                       (signkey, getpass.getuser()))
                sys.exit(1)
            create_certs = True

        if not os.access(issuercert, os.R_OK):
            if os.path.exists(issuercert):
                logerr(LOGFILE, "Need read rights on issuer certficate %s for user %s.\n" %
                       (issuercert, getpass.getuser()))
                sys.exit(1)
            create_certs = True

        if create_certs:
            logit(LOGFILE, "Creating root CA and a local CA's signing key and issuer cert.\n")
            if create_localca_cert(lockfile, statedir, signkey, signkey_password,
                                   issuercert) != 0:
                logerr(LOGFILE, "Error creating local CA's signing key and cert.\n")
                sys.exit(1)

            if not os.access(signkey, os.R_OK):
                logerr(LOGFILE, "Need read rights on signing key %s for user %s.\n" %
                       (signkey, getpass.getuser()))
                sys.exit(1)

    if not os.access(issuercert, os.R_OK):
        logerr(LOGFILE, "Need read rights on issuer certificate %s for user %s.\n" %
               (issuercert, getpass.getuser()))
        sys.exit(1)

    certserial = get_config_value(lines, "certserial", os.path.join(statedir, "certserial"))
    if makedir(os.path.dirname(certserial), "certserial") != 0:
        sys.exit(1)

    ret = create_cert(flags, typ, directory, ekparams, vmid, tpm_spec_params, tpm_attr_params,
                      signkey, signkey_password, issuercert, parentkey_password, swtpm_cert_env,
                      certserial, lockfile, optsfile)

    sys.exit(ret)


if __name__ == "__main__":
    main()
