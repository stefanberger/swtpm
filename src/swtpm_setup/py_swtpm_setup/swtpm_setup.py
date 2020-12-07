#!/usr/bin/env python3
""" swtpm_setup.py

A tool for simulating the manufacturing of a TPM 1.2 or 2.0
"""

# Disable a couple of warnings:
# 0912: Too many branches (15/12) (too-many-branches)
# R0913: Too many arguments (6/5) (too-many-arguments)
# R0914: Too many local variables (21/15) (too-many-locals)
# R0101: Too many nested blocks (6/5) (too-many-nested-blocks)
# W0703: Catching too general exception Exception (broad-except)
# C0302: Too many lines in module (1032/1000) (too-many-lines)
# pylint: disable=W0703,R0913,R0914,R0912,R0101,C0302

#
# swtpm_setup.py
#
# Authors: Stefan Berger <stefanb@linux.ibm.com>
#
# (c) Copyright IBM Corporation 2020
#

import datetime
import distutils.spawn
import getopt
import getpass
import glob
import grp
import json
import os
import pwd
import re
import subprocess
import sys

from py_swtpm_setup.swtpm_utils import logit, logerr, sha1
from py_swtpm_setup.swtpm_setup_conf import SWTPM_VER_MAJOR, SWTPM_VER_MINOR, \
                                            SWTPM_VER_MICRO, SYSCONFDIR
from py_swtpm_setup.swtpm import Swtpm2, Swtpm12

# default values for passwords
DEFAULT_OWNER_PASSWORD = "ooo"
DEFAULT_SRK_PASSWORD = "sss"

SETUP_CREATE_EK_F = 1
SETUP_TAKEOWN_F = 2
SETUP_EK_CERT_F = 4
SETUP_PLATFORM_CERT_F = 8
SETUP_LOCK_NVRAM_F = 16
SETUP_SRKPASS_ZEROS_F = 32
SETUP_OWNERPASS_ZEROS_F = 64
SETUP_STATE_OVERWRITE_F = 128
SETUP_STATE_NOT_OVERWRITE_F = 256
SETUP_TPM2_F = 512
SETUP_ALLOW_SIGNING_F = 1024
SETUP_TPM2_ECC_F = 2048
SETUP_CREATE_SPK_F = 4096
SETUP_DISPLAY_RESULTS_F = 8192
SETUP_DECRYPTION_F = 16384

# default configuration file
SWTPM_SETUP_CONF = "swtpm_setup.conf"

XCH = os.getenv('XDG_CONFIG_HOME')
HOME = os.getenv('HOME')
if XCH and os.access(os.path.join(XCH, SWTPM_SETUP_CONF), os.R_OK):
    DEFAULT_CONFIG_FILE = os.path.join(XCH, SWTPM_SETUP_CONF)
elif HOME and os.access(os.path.join(HOME, ".config", SWTPM_SETUP_CONF), os.R_OK):
    DEFAULT_CONFIG_FILE = os.path.join(HOME, ".config", SWTPM_SETUP_CONF)
else:
    DEFAULT_CONFIG_FILE = os.path.join(os.sep + SYSCONFDIR, SWTPM_SETUP_CONF)

# default PCR banks to activate for TPM 2
DEFAULT_PCR_BANKS = "sha1,sha256"

# Default logging goes to stderr
LOGFILE = ""

DEFAULT_RSA_KEYSIZE = 2048


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


def get_config_value(lines, configname):
    """ Get a config value from a list of strings """
    regex = r'^' + configname + r"\s*=\s*([^#\n]*).*"
    for line in lines:
        match = re.match(regex, line)
        if match:
            return resolve_string(match.groups()[0])
    return None


def read_file(filename):
    """ read contents from a file """
    try:
        fobj = open(filename, mode='rb')
        result = fobj.read()
        fobj.close()
        return result, 0
    except Exception as err:
        logerr(LOGFILE, "Could not read from file %s: %s\n" % \
               (filename, str(err)))
        return "", 1


def read_file_lines(filename):
    """ Read the lines from a file and return a list of the lines """
    try:
        fobj = open(filename, 'r')
        lines = fobj.readlines()
        fobj.close()
        return lines, 0
    except Exception as err:
        logerr(LOGFILE, "Could not access %s to get name of certificate tool "
               "to invoke: %s\n" % (filename, str(err)))
        return [], 1


def remove_file(filename):
    """ remove a file """
    try:
        os.remove(filename)
        return 0
    except Exception as err:
        logerr(LOGFILE, "Could not remove file %s: %s\n" % \
               (filename, str(err)))
        return 1


def tpm_get_specs_and_attributes(swtpm):
    """ Get the TPM specification and attribute parameters """

    res, ret = swtpm.ctrl_get_tpm_specs_and_attrs()
    if ret != 0:
        logerr(LOGFILE, "Could not get the TPM spec and attribute parameters.\n")
        return [], 1

    res = res.replace(":00,", ":0,") # needed for libtpms <= 0.7.x
    try:
        tpm_param = json.loads(res)
    except json.decoder.JSONDecodeError as err:
        logerr(LOGFILE, "Internal error: Could not parse '%s' as JSON: %s\n" %
               (res, str(err)))
        return [], 1

    params = ["--tpm-spec-family", tpm_param["TPMSpecification"]["family"],
              "--tpm-spec-level", str(tpm_param["TPMSpecification"]["level"]),
              "--tpm-spec-revision", str(tpm_param["TPMSpecification"]["revision"]),
              "--tpm-manufacturer", str(tpm_param["TPMAttributes"]["manufacturer"]),
              "--tpm-model", str(tpm_param["TPMAttributes"]["model"]),
              "--tpm-version", str(tpm_param["TPMAttributes"]["version"])]
    return params, 0


def call_create_certs(flags, config_file, certsdir, ekparam, vmid, swtpm):
    """ Call an external tool to create the certificates """

    params, ret = tpm_get_specs_and_attributes(swtpm)
    if ret != 0:
        return 1

    lines, ret = read_file_lines(config_file)
    if ret != 0:
        return ret

    create_certs_tool = get_config_value(lines, "create_certs_tool")
    create_certs_tool_config = get_config_value(lines, "create_certs_tool_config")
    create_certs_tool_options = get_config_value(lines, "create_certs_tool_options")

    ret = 0

    if create_certs_tool:
        ret = 1
        if flags & SETUP_TPM2_F:
            params.extend(["--tpm2"])

        cmd = [create_certs_tool,
               "--type", "_",
               "--ek", ekparam,
               "--dir", certsdir]
        if len(LOGFILE) > 0:
            cmd.extend(["--logfile", LOGFILE])
        if len(vmid) > 0:
            cmd.extend(["--vmid", vmid])
        cmd.extend(params)
        if create_certs_tool_config:
            cmd.extend(["--configfile", create_certs_tool_config])
        if create_certs_tool_options:
            cmd.extend(["--optsfile", create_certs_tool_options])

        try:
            i = create_certs_tool.rindex(os.sep)
            prgname = create_certs_tool[i + 1:]
        except ValueError:
            prgname = create_certs_tool

        for entry in [(SETUP_EK_CERT_F, "ek"), (SETUP_PLATFORM_CERT_F, "platform")]:
            if flags & entry[0]:
                try:
                    cmd[2] = entry[1]
                    logit(LOGFILE, "  Invoking %s\n" % (" ".join(cmd)))
                    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                    stdout, _ = proc.communicate(timeout=30)
                    for line in stdout.decode().split("\n"):
                        if len(line) > 0:
                            logit(LOGFILE, "%s: %s\n" % (prgname, line))
                    ret = proc.returncode
                    if ret != 0:
                        logerr(LOGFILE, "Error returned from command\n")
                        return 1
                except FileNotFoundError as err:
                    logerr(LOGFILE, "Could not execute %s: %s\n" % (create_certs_tool, str(err)))
                    return 1
                except subprocess.TimeoutExpired as err:
                    logerr(LOGFILE, "%s did not finish in time: %s\n" %
                           (create_certs_tool, str(err)))
                    return 1
                except Exception as err:
                    logerr(LOGFILE, "An error occurred running %s: %s\n" %
                           (create_certs_tool, str(err)))

    return ret


def tpm2_create_ek_and_cert(flags, config_file, certsdir, vmid, rsa_keysize, swtpm):
    """ Create either an RSA or ECC EK and certificate """

    if flags & SETUP_CREATE_EK_F:
        ekparam, ret = swtpm.create_ek(flags & SETUP_TPM2_ECC_F, rsa_keysize,
                                       flags & SETUP_ALLOW_SIGNING_F, flags & SETUP_DECRYPTION_F,
                                       flags & SETUP_LOCK_NVRAM_F)
        if ret != 0:
            return ret

    if flags & (SETUP_EK_CERT_F | SETUP_PLATFORM_CERT_F):
        ret = call_create_certs(flags, config_file, certsdir, ekparam, vmid, swtpm)
        if ret != 0:
            return ret

        for entry in [(SETUP_EK_CERT_F, "ek.cert"), (SETUP_PLATFORM_CERT_F, "platform.cert")]:
            if flags & entry[0]:
                certfile = os.path.join(certsdir, entry[1])
                data, ret = read_file(certfile)
                if ret != 0:
                    logerr(LOGFILE, "%s file could not be read\n" % certfile)
                    return ret
                if entry[0] == SETUP_EK_CERT_F:
                    ret = swtpm.write_ek_cert_nvram(flags & SETUP_TPM2_ECC_F, rsa_keysize,
                                                    flags & SETUP_LOCK_NVRAM_F, data)
                else:
                    ret = swtpm.write_platform_cert_nvram(flags & SETUP_LOCK_NVRAM_F, data)
                remove_file(certfile)
                if ret != 0:
                    return ret

    return 0


def tpm2_create_eks_and_certs(flags, config_file, certsdir, vmid, rsa_keysize, swtpm):
    """ Create RSA and ECC EKs and certificates """

    # 1st key will be RSA
    flags = flags & ~SETUP_TPM2_ECC_F
    ret = tpm2_create_ek_and_cert(flags, config_file, certsdir, vmid, rsa_keysize, swtpm)
    if ret != 0:
        return 1

    # 2nd key will be an ECC; no more platform cert
    flags = (flags & ~SETUP_PLATFORM_CERT_F) | SETUP_TPM2_ECC_F
    return tpm2_create_ek_and_cert(flags, config_file, certsdir, vmid, rsa_keysize, swtpm)


def init_tpm2(flags, swtpm_prg_l, config_file, tpm2_state_path, vmid, pcr_banks, swtpm_keyopt,
              fds_to_pass, rsa_keysize):
    """ Initialize a TPM 2.0: create keys and certificate """
    certsdir = tpm2_state_path

    swtpm = Swtpm2(swtpm_prg_l.copy(), tpm2_state_path, swtpm_keyopt, LOGFILE, fds_to_pass)

    ret = swtpm.start()
    if ret != 0:
        logerr(LOGFILE, "Could not start the TPM 2.\n")
        return 1

    if ret == 0:
        ret = swtpm.run_swtpm_bios()

    if ret == 0 and flags & SETUP_CREATE_SPK_F:
        ret = swtpm.create_spk(flags & SETUP_TPM2_ECC_F, rsa_keysize)

    if ret == 0:
        ret = tpm2_create_eks_and_certs(flags, config_file, certsdir, vmid, rsa_keysize, swtpm)

    if ret == 0 and pcr_banks != "-":
        all_pcr_banks, ret = swtpm.get_all_pcr_banks()
        if ret == 0:
            active_pcr_banks, ret = swtpm.set_active_pcr_banks(pcr_banks.split(","), all_pcr_banks)
        if ret == 0:
            logit(LOGFILE, "Successfully activated PCR banks %s among %s.\n" %
                  (",".join(active_pcr_banks),
                   ",".join(all_pcr_banks)))

    if ret == 0:
        swtpm.shutdown()

    swtpm.destroy()

    return ret


def tpm12_get_ownerpass_digest(flags, ownerpass):
    """ Get the owner password digest given the flags and possible owner password """
    if not ownerpass:
        if flags & SETUP_OWNERPASS_ZEROS_F:
            ownerpass = ('\0' * 20)
        else:
            ownerpass = DEFAULT_OWNER_PASSWORD
    #print("Using owner password: %s\n" % ownerpass)
    return sha1(ownerpass.encode())


def tpm12_get_srkpass_digest(flags, srkpass):
    """ Get the SRK password digest given the flags and possible SRK password """
    if not srkpass:
        if flags & SETUP_SRKPASS_ZEROS_F:
            srkpass = ('\0' * 20)
        else:
            srkpass = DEFAULT_SRK_PASSWORD
    #print("Using SRK password: %s\n" % srkpass)
    return sha1(srkpass.encode())


def tpm12_take_ownership(flags, ownerpass, srkpass, pubek, swtpm):
    """ Take ownership of the TPM 1.2; prepare the passwords """

    return swtpm.take_ownership(tpm12_get_ownerpass_digest(flags, ownerpass),
                                tpm12_get_srkpass_digest(flags, srkpass), pubek)


def tpm12_ownerclear(flags, ownerpass, swtpm):
    """ Clear ownership of the TPM 1.2; prepare the password """
    return swtpm.ownerclear(tpm12_get_ownerpass_digest(flags, ownerpass))


def tpm12_create_certs(flags, config_file, certsdir, ekparam, vmid, swtpm):
    """ Create certificates for the TPM 1.2 and write them into NVRAM """
    ret = call_create_certs(flags, config_file, certsdir, ekparam, vmid, swtpm)
    if ret != 0:
        return 1

    for entry in [(SETUP_EK_CERT_F, "ek.cert"), (SETUP_PLATFORM_CERT_F, "platform.cert")]:
        if flags & entry[0]:
            certfile = os.path.join(certsdir, entry[1])
            data, ret = read_file(certfile)
            if ret != 0:
                logerr(LOGFILE, "%s file could not be read\n" % certfile)
                return 1
            if entry[0] == SETUP_EK_CERT_F:
                ret = swtpm.write_ek_cert_nvram(data)
                if ret == 0:
                    logit(LOGFILE, "Successfully created NVRAM area for EK certificate.\n")
            else:
                ret = swtpm.write_platform_cert_nvram(data)
                if ret == 0:
                    logit(LOGFILE, "Successfully created NVRAM area for Platform certificate.\n")
            remove_file(certfile)
            if ret != 0:
                return 1

    return 0


def init_tpm(flags, swtpm_prg_l, config_file, tpm_state_path, ownerpass, srkpass, vmid,
             swtpm_keyopt, fds_to_pass):
    """ Initialize a TPM 1.2: create keys and certificate and take ownership """
    certsdir = tpm_state_path

    swtpm = Swtpm12(swtpm_prg_l.copy(), tpm_state_path, swtpm_keyopt, LOGFILE, fds_to_pass)

    ret = swtpm.start()
    if ret != 0:
        logerr(LOGFILE, "Could not start the TPM 2.\n")
        return 1
    # We will have to call swtpm.destroy() at the end

    if ret == 0:
        ret = swtpm.run_swtpm_bios()

    if ret == 0 and flags & SETUP_CREATE_EK_F:
        pubek, ret = swtpm.create_endorsement_key_pair()
        if ret == 0:
            logit(LOGFILE, "Successfully created EK.\n")

    if ret == 0 and flags & SETUP_TAKEOWN_F:
        ret = tpm12_take_ownership(flags, ownerpass, srkpass, pubek, swtpm)
        if ret == 0:
            logit(LOGFILE, "Successfully took ownership of the TPM.\n")

    if ret == 0 and flags & SETUP_EK_CERT_F:
        ekparam = pubek.hex()
        ret = tpm12_create_certs(flags, config_file, certsdir, ekparam, vmid, swtpm)

    if ret == 0 and flags & SETUP_LOCK_NVRAM_F:
        ret = swtpm.nv_lock()
        if ret == 0:
            logit(LOGFILE, "Successfully locked NVRAM access.\n")

    swtpm.destroy()

    return ret


def check_state_overwrite(flags, tpm_state_path):
    """ Check whether we are allowed to overwrite existing state """
    if flags & SETUP_TPM2_F:
        statefile = "tpm2-00.permall"
    else:
        statefile = "tpm-00.permall"

    if os.access(os.path.join(tpm_state_path, statefile), os.R_OK|os.W_OK):
        if flags & SETUP_STATE_NOT_OVERWRITE_F:
            logit(LOGFILE, "Not overwriting existing state file.\n")
            return 2
        if flags & SETUP_STATE_OVERWRITE_F:
            return 0
        logerr(LOGFILE, "Found existing TPM state file %s.\n" % statefile)
        return 1

    return 0


def delete_state(flags, tpm_state_path):
    """ Delete the TPM's state file """
    if flags & SETUP_TPM2_F:
        statefile = "tpm2-00.permall"
    else:
        statefile = "tpm-00.permall"

    filepath = os.path.join(tpm_state_path, statefile)
    try:
        os.unlink(os.path.join(tpm_state_path, statefile))
    except Exception as err:
        logerr(LOGFILE, "Could not remove state file %s: %s\n" % \
               (filepath, str(err)))


def versioninfo():
    """ Display version info """
    print('TPM emulator setup tool version %d.%d.%d' %
          (SWTPM_VER_MAJOR, SWTPM_VER_MINOR, SWTPM_VER_MICRO))


def usage(prgname):
    """ Display versioninfo and usage """
    versioninfo()
    print(
        "Usage: {prgname} [options]\n"
        "\n"
        "The following options are supported:\n"
        "\n"
        "--runas <user>   : Use the given user id to switch to and run this program;\n"
        "                   this parameter is interpreted by swtpm_setup that switches\n"
        "                   to this user and invokes swtpm_setup.sh.\n"
        "\n"
        "--tpm-state <dir>: Path to a directory where the TPM's state will be written\n"
        "                   into; this is a mandatory argument\n"
        "\n"
        "--tpmstate <dir> : This is an alias for --tpm-state <dir>.\n"
        "\n"
        "--tpm <executable>\n"
        "                 : Path to the TPM executable; this is an optional argument and\n"
        "                   by default 'swtpm' in the PATH is used.\n"
        "\n"
        "--swtpm_ioctl <executable>\n"
        "                 : Path to the swtpm_ioctl executable; this is deprecated\n"
        "                   argument.\n"
        "\n"
        "--tpm2           : Setup a TPM 2; by default a TPM 1.2 is setup.\n"
        "\n"
        "--createek       : Create the EK; for a TPM 2 an RSA and ECC EK will be\n"
        "                   created\n"
        "\n"
        "--allow-signing  : Create an EK that can be used for signing;\n"
        "                   this option requires --tpm2.\n"
        "\n"
        "--decryption     : Create an EK that can be used for key encipherment;\n"
        "                   this is the default unless --allow-signing is given;\n"
        "                   this option requires --tpm2.\n"
        "\n"
        "--ecc            : This option allows to create a TPM 2's ECC key as storage\n"
        "                   primary key; a TPM 2 always gets an RSA and an ECC EK key.\n"
        "\n"
        "--take-ownership : Take ownership; this option implies --createek\n"
        "  --ownerpass  <password>\n"
        "                 : Provide custom owner password; default is {DEFAULT_OWNER_PASSWORD}\n"
        "  --owner-well-known:\n"
        "                 : Use an owner password of 20 zero bytes\n"
        "  --srkpass <password>\n"
        "                 : Provide custom SRK password; default is {DEFAULT_SRK_PASSWORD}\n"
        "  --srk-well-known:\n"
        "                 : Use an SRK password of 20 zero bytes\n"
        "--create-ek-cert : Create an EK certificate; this implies --createek\n"
        "\n"
        "--create-platform-cert\n"
        "                 : Create a platform certificate; this implies --create-ek-cert\n"
        "\n"
        "--create-spk     : Create storage primary key; this requires --tpm2\n"
        "\n"
        "--lock-nvram     : Lock NVRAM access\n"
        "\n"
        "--display        : At the end display as much info as possible about the\n"
        "                   configuration of the TPM\n"
        "\n"
        "--config <config file>\n"
        "                 : Path to configuration file; default is {DEFAULT_CONFIG_FILE}\n"
        "\n"
        "--logfile <logfile>\n"
        "                 : Path to log file; default is logging to stderr\n"
        "\n"
        "--keyfile <keyfile>\n"
        "                 : Path to a key file containing the encryption key for the\n"
        "                   TPM to encrypt its persistent state with. The content\n"
        "                   must be a 32 hex digit number representing a 128bit AES key.\n"
        "                   This parameter will be passed to the TPM using\n"
        "                   '--key file=<file>'.\n"
        "\n"
        "--keyfile-fd <fd>: Like --keyfile but file descriptor is given to read\n"
        "                   encryption key from.\n"
        "\n"
        "--pwdfile <pwdfile>\n"
        "                 : Path to a file containing a passphrase from which the\n"
        "                   TPM will derive the 128bit AES key. The passphrase can be\n"
        "                   32 bytes long.\n"
        "                   This parameter will be passed to the TPM using\n"
        "                   '--key pwdfile=<file>'.\n"
        "\n"
        "--pwdfile-fd <fd>: Like --pwdfile but file descriptor to read passphrase\n"
        "                   from is given.\n"
        "\n"
        "--cipher <cipher>: The cipher to use; either aes-128-cbc or aes-256-cbc;\n"
        "                   the default is aes-128-cbc; the same cipher must be\n"
        "                   used on the swtpm command line\n"
        "\n"
        "--overwrite      : Overwrite existing TPM state be re-initializing it; if this\n"
        "                   option is not given, this program will return an error if\n"
        "                   existing state is detected\n"
        "\n"
        "--not-overwrite  : Do not overwrite existing TPM state but silently end\n"
        "\n"
        "--pcr-banks <banks>\n"
        "                 : Set of PCR banks to activate. Provide a comma separated list\n"
        "                   like 'sha1,sha256'. '-' to skip and leave all banks active.\n"
        "                   Default: {DEFAULT_PCR_BANKS}\n"
        "\n"
        "--rsa-keysize <keysize>\n"
        "                 : The RSA key size of the EK key; 3072 bits may be supported\n"
        "                   if libtpms supports it.\n"
        "                   Default: {DEFAULT_RSA_KEYSIZE}\n"
        "\n"
        "--tcsd-system-ps-file <file>\n"
        "                 : This option is deprecated and has no effect.\n"
        "\n"
        "--print-capabilities\n"
        "                 : Print JSON formatted capabilites added after v0.1 and exit.\n"
        "\n"
        "--version        : Display version and exit\n"
        "\n"
        "--help,-h,-?     : Display this help screen".format_map({
            'prgname': prgname,
            'DEFAULT_OWNER_PASSWORD': DEFAULT_OWNER_PASSWORD,
            'DEFAULT_SRK_PASSWORD': DEFAULT_SRK_PASSWORD,
            'DEFAULT_CONFIG_FILE': DEFAULT_CONFIG_FILE,
            'DEFAULT_PCR_BANKS': DEFAULT_PCR_BANKS,
            'DEFAULT_RSA_KEYSIZE': DEFAULT_RSA_KEYSIZE
        }))


def get_rsa_keysizes(flags, swtpm_prg_l):
    """ Get the support RSA key sizes
        @return This function returns a list of ints like the following
        - [ 1024, 2048, 3072 ]
        - [] (empty list, indicating only 2048 bit RSA keys are supported)
    """
    res = []

    if flags & SETUP_TPM2_F:
        cmdarray = swtpm_prg_l.copy()
        cmdarray.extend(["--tpm2", "--print-capabilities"])
        try:
            process = subprocess.Popen(cmdarray, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            stdout, _ = process.communicate()
            try:
                instr = stdout.decode()
                j = json.loads(instr)
                for entry in j["features"]:
                    if entry.startswith("rsa-keysize-"):
                        try:
                            res.append(int(entry[12:]))
                        except ValueError as err:
                            logerr(LOGFILE, "Internal error: Could not parse '%s' as int: %s\n" %
                                   (entry[12:], str(err)))
                            return [], 1
            except json.decoder.JSONDecodeError as err:
                logerr(LOGFILE, "Internal error: Could not parse '%s' as JSON: %s\n" %
                       (instr, str(err)))
                return [], 1
        except Exception as err:
            logerr(LOGFILE, "Could not start swtpm '%s': %s\n" % (" ".join(swtpm_prg_l), str(err)))
            return res, 1

    return res, 0


def get_rsakeysize_caps(flags, swtpm_prg_l):
    """ Get supported RSA key sizes useful for creating the EK key; only 2048
        and 3072 bits are checked and reported.
        This function returns a list of strings like the following
        - [ "tpm2-rsa-keysize-2048", "tpm2-rsa-keyssize-3072" ]
        - [] (empty list, indicating only 2048 bit RSA keys are supported)
    """

    supt_keysizes, ret = get_rsa_keysizes(flags, swtpm_prg_l)
    if ret != 0:
        return [], 1

    res = []
    for keysize in supt_keysizes:
        if keysize >= 2048:
            res.append("tpm2-rsa-keysize-%d" % keysize)

    return res, 0


def print_capabilities(swtpm_prg_l):
    """ pring JSON string with capabilites """
    param = ""

    output, ret = get_rsakeysize_caps(SETUP_TPM2_F, swtpm_prg_l)
    if ret != 0:
        return 1
    if len(output) > 0:
        param = ', "' + '", "'.join(output) + '"'

    print('{ "type": "swtpm_setup", ' \
          '"features": [ "cmdarg-keyfile-fd", "cmdarg-pwdfile-fd", "tpm12-not-need-root"' +
          param + ' ] '\
   '}')

    return 0

def change_process_owner(user):
    """ change the process owner to the given one """
    if not user.isnumeric():
        try:
            passwd = pwd.getpwnam(user)
        except KeyError:
            logerr(LOGFILE, "Error: User '%s' does not exist.\n" % user)
            return 1

        try:
            os.initgroups(passwd.pw_name, passwd.pw_gid)
        except PermissionError as err:
            logerr(LOGFILE, "Error: initgroups() failed: %s\n" % str(err))
            return 1
        gid = passwd.pw_gid
        uid = passwd.pw_uid
    else:
        if int(user) > 0xffffffff:
            logerr(LOGFILE, "Error: uid %s outside valid range.\n" % user)
        gid = int(user)
        uid = int(user)

    try:
        os.setgid(gid)
    except PermissionError as err:
        logerr(LOGFILE, "Error: setgid(%d) failed: %s\n" % (gid, str(err)))
        return 1

    try:
        os.setuid(uid)
    except PermissionError as err:
        logerr(LOGFILE, "Error: setuid(%d) failed: %s\n" % (uid, str(err)))
        return 1

    return 0

# pylint: disable=R0915
def main():
    """ main function - parses command line parameters and low level dealing with them """
    global LOGFILE # pylint: disable=W0603

    swtpm_prg = distutils.spawn.find_executable("swtpm")
    if swtpm_prg:
        swtpm_prg += " socket"

    try:
        opts, _ = getopt.getopt(sys.argv[1:], "h?",
                                ["tpm-state=", "tpmstate=",
                                 "tpm=",
                                 "swtpm_ioctl=",
                                 "tpm2",
                                 "ecc",
                                 "createek",
                                 "create-spk",
                                 "take-ownership",
                                 "ownerpass=",
                                 "owner-well-known",
                                 "srkpass=",
                                 "srk-well-known",
                                 "create-ek-cert",
                                 "create-platform-cert",
                                 "lock-nvram",
                                 "display",
                                 "config=",
                                 "vmid=",
                                 "keyfile=",
                                 "keyfile-fd=",
                                 "pwdfile=",
                                 "pwdfile-fd=",
                                 "cipher=",
                                 "runas=",
                                 "logfile=",
                                 "overwrite",
                                 "not-overwrite",
                                 "allow-signing",
                                 "decryption",
                                 "pcr-banks=",
                                 "rsa-keysize=",
                                 "tcsd-system-ps-file",
                                 "version",
                                 "print-capabilities",
                                 "help"])
    except getopt.GetoptError as err:
        print(err)
        usage(sys.argv[0])
        sys.exit(1)

    flags = 0
    tpm_state_path = ""
    config_file = DEFAULT_CONFIG_FILE
    ownerpass = None
    got_ownerpass = False
    srkpass = None
    got_srkpass = False
    vmid = ""
    pcr_banks = ""
    printcapabilities = False
    keyfile = ""
    keyfile_fd = ""
    pwdfile = ""
    pwdfile_fd = ""
    cipher = "aes-128-cbc"
    rsa_keysize_str = "%d" % DEFAULT_RSA_KEYSIZE
    swtpm_keyopt = ""
    fds_to_pass = []
    runas = ""

    for opt, arg in opts:
        if opt in ['--tpm-state', '--tpmstate']:
            tpm_state_path = arg
        elif opt == '--tpm':
            swtpm_prg = arg
        elif opt == '--swtpm_ioctl':
            print("Warning: --swtpm_ioctl is deprecated and has no effect.")
        elif opt == '--tpm2':
            flags |= SETUP_TPM2_F
        elif opt == '--ecc':
            flags |= SETUP_TPM2_ECC_F
        elif opt == '--createek':
            flags |= SETUP_CREATE_EK_F
        elif opt == '--create-spk':
            flags |= SETUP_CREATE_SPK_F
        elif opt == '--take-ownership':
            flags |= SETUP_CREATE_EK_F | SETUP_TAKEOWN_F
        elif opt == '--ownerpass':
            ownerpass = arg
            got_ownerpass = True
        elif opt == '--owner-well-known':
            flags |= SETUP_OWNERPASS_ZEROS_F
        elif opt == '--srkpass':
            srkpass = arg
            got_srkpass = True
        elif opt == '--srk-well-known':
            flags |= SETUP_SRKPASS_ZEROS_F
        elif opt == '--create-ek-cert':
            flags |= SETUP_CREATE_EK_F | SETUP_EK_CERT_F
        elif opt == '--create-platform-cert':
            flags |= SETUP_CREATE_EK_F | SETUP_PLATFORM_CERT_F
        elif opt == '--lock-nvram':
            flags |= SETUP_LOCK_NVRAM_F
        elif opt == '--display':
            flags |= SETUP_DISPLAY_RESULTS_F
        elif opt == '--config':
            config_file = arg
        elif opt == '--vmid':
            vmid = arg
        elif opt == '--keyfile':
            keyfile = arg
        elif opt == '--keyfile-fd':
            keyfile_fd = arg
        elif opt == '--pwdfile':
            pwdfile = arg
        elif opt == '--pwdfile-fd':
            pwdfile_fd = arg
        elif opt == '--cipher':
            cipher = arg
        elif opt == '--runas':
            runas = arg
        elif opt == '--logfile':
            LOGFILE = arg
        elif opt == '--overwrite':
            flags |= SETUP_STATE_OVERWRITE_F
        elif opt == '--not-overwrite':
            flags |= SETUP_STATE_NOT_OVERWRITE_F
        elif opt == '--allow-signing':
            flags |= SETUP_ALLOW_SIGNING_F
        elif opt == '--decryption':
            flags |= SETUP_DECRYPTION_F
        elif opt == '--pcr-banks':
            pcr_banks = pcr_banks + "," + arg
        elif opt == '--rsa-keysize':
            rsa_keysize_str = arg
        elif opt == '--tcsd-system-ps-file':
            print("Warning: --tcsd-system-ps-file is deprecated and has no effect.")
        elif opt == '--version':
            versioninfo()
            sys.exit(0)
        elif opt == '--print-capabilities':
            printcapabilities = True
        elif opt in ['--help', '-h', '-?']:
            usage(sys.argv[0])
            sys.exit(0)
        else:
            sys.stderr.write("Unknown option %s\n" % opt)
            usage(sys.argv[0])
            sys.exit(1)

    if not swtpm_prg:
        logerr(LOGFILE,
               "Default TPM 'swtpm' could not be found and was not provided using --tpm\n.")
        sys.exit(1)
    swtpm_prg_l = swtpm_prg.split()
    if not distutils.spawn.find_executable(swtpm_prg_l[0]):
        logerr(LOGFILE, "TPM at %s is not an executable.\n" % (" ".join(swtpm_prg_l)))
        sys.exit(1)

    if printcapabilities:
        ret = print_capabilities(swtpm_prg_l)
        sys.exit(ret)

    if runas:
        ret = change_process_owner(runas)
        if ret != 0:
            sys.exit(1)

    if not got_ownerpass:
        flags |= SETUP_OWNERPASS_ZEROS_F
    if not got_srkpass:
        flags |= SETUP_SRKPASS_ZEROS_F

    # sequeeze ',' and remove leading and trailing ','
    pcr_banks = re.sub(r',$', '',
                       re.sub(r'^,', '',
                              re.sub(r',,+', ',', pcr_banks)))
    if len(pcr_banks) == 0:
        pcr_banks = DEFAULT_PCR_BANKS

    # set owner password to default if user didn't provide any password wish
    # and wants to take ownership
    if flags & SETUP_TAKEOWN_F and \
        flags & SETUP_OWNERPASS_ZEROS_F and \
        not got_srkpass:
        srkpass = DEFAULT_SRK_PASSWORD

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

    # Check tpm_state_path directory and access rights
    if len(tpm_state_path) == 0:
        logerr(LOGFILE, "--tpm-state must be provided\n")
        sys.exit(1)
    if not os.path.isdir(tpm_state_path):
        logerr(LOGFILE,
               "User %s cannot access directory %s. Make sure it exists and is a directory.\n" %
               (getpass.getuser(), tpm_state_path))
        sys.exit(1)
    if not os.access(tpm_state_path, os.R_OK):
        logerr(LOGFILE, "Need read rights on directory %s for user %s.\n" %
               (tpm_state_path, getpass.getuser()))
        sys.exit(1)
    if not os.access(tpm_state_path, os.W_OK):
        logerr(LOGFILE, "Need write rights on directory %s for user %s.\n" %
               (tpm_state_path, getpass.getuser()))
        sys.exit(1)

    if flags & SETUP_TPM2_F:
        if flags & SETUP_TAKEOWN_F:
            logerr(LOGFILE, "Taking ownership is not supported for TPM 2.\n")
            sys.exit(1)
    else:
        if flags & SETUP_TPM2_ECC_F:
            logerr(LOGFILE, "--ecc requires --tpm2.\n")
            sys.exit(1)
        if flags & SETUP_CREATE_SPK_F:
            logerr(LOGFILE, "--create-spk requires --tpm2.\n")
            sys.exit(1)

    ret = check_state_overwrite(flags, tpm_state_path)
    if ret == 1:
        sys.exit(1)
    elif ret == 2:
        sys.exit(0)

    files = glob.glob(os.path.join(tpm_state_path, "*permall"))
    files.extend(glob.glob(os.path.join(tpm_state_path, "*volatilestate")))
    files.extend(glob.glob(os.path.join(tpm_state_path, "*savestate")))

    try:
        for fil in files:
            os.remove(fil)
    except Exception as err:
        logerr(LOGFILE, "Could not remove previous state files. Need execute access rights on the "
               "directory %s.\n" % tpm_state_path)
        sys.exit(1)

    lockfile = os.path.join(tpm_state_path, ".lock")
    if os.path.exists(lockfile) and not os.access(lockfile, os.W_OK | os.R_OK):
        logerr(LOGFILE, "User %s cannot read/write %s.\n" % (getpass.getuser(), lockfile))
        sys.exit(1)

    if not os.access(config_file, os.R_OK):
        logerr(LOGFILE, "User %s cannot read %s.\n" % (getpass.getuser(), config_file))
        sys.exit(1)

    if len(cipher) > 0:
        if cipher not in ['aes-128-cbc', 'aes-cbc', 'aes-256-cbc']:
            logerr(LOGFILE, "Unsupported cipher %s.\n" % cipher)
            sys.exit(1)
        cipher = ",mode=%s" % cipher

    if len(keyfile) > 0:
        if not os.access(keyfile, os.R_OK):
            logerr(LOGFILE, "User %s cannot read keyfile %s.\n" % (getpass.getuser(), keyfile))
            sys.exit(1)
        swtpm_keyopt = "file=%s%s" % (keyfile, cipher)
        logit(LOGFILE, "  The TPM's state will be encrypted with a provided key.\n")
    elif len(pwdfile) > 0:
        if not os.access(pwdfile, os.R_OK):
            logerr(LOGFILE, "User %s canot read passphrase file %s.\n" % \
                   (getpass.getuser(), keyfile))
            sys.exit(1)
        swtpm_keyopt = "pwdfile=%s%s" % (pwdfile, cipher)
        logit(LOGFILE,
              "  The TPM's state will be encrypted using a key derived from a passphrase.\n")
    elif len(keyfile_fd) > 0:
        if not keyfile_fd.isnumeric():
            logerr(LOGFILE,
                   "--keyfile-fd parameter $keyfile_fd is not a valid file descriptor.\n")
            sys.exit(1)
        fds_to_pass.append(int(keyfile_fd))
        swtpm_keyopt = "fd=%s%s" % (keyfile_fd, cipher)
        logit(LOGFILE,
              "  The TPM's state will be encrypted with a provided key (fd).\n")
    elif len(pwdfile_fd) > 0:
        if not pwdfile_fd.isnumeric():
            logerr(LOGFILE,
                   "--pwdfile-fd parameter $pwdfile_fd is not a valid file descriptor.\n")
            sys.exit(1)
        fds_to_pass.append(int(pwdfile_fd))
        swtpm_keyopt = "pwdfd=%s%s" % (pwdfile_fd, cipher)
        logit(LOGFILE,
              "  The TPM's state will be encrypted using a key derived from a passphrase (fd).\n")

    if rsa_keysize_str == "max":
        keysizes, ret = get_rsa_keysizes(flags, swtpm_prg_l)
        if ret != 0:
            sys.exit(1)
        if len(keysizes) > 0:
            rsa_keysize_str = keysizes[-1]
        else:
            rsa_keysize_str = "2048"
    if rsa_keysize_str in ["2048", "3072"]:
        rsa_keysize = int(rsa_keysize_str)
        supported_keysizes, ret = get_rsa_keysizes(flags, swtpm_prg_l)
        if ret != 0:
            sys.exit(1)
        if rsa_keysize not in supported_keysizes and rsa_keysize != 2048:
            logerr(LOGFILE, "%s bit RSA keys are not supported by libtpms.\n" % rsa_keysize_str)
            sys.exit(1)
    else:
        logerr(LOGFILE, "Unsupported RSA key size %s.\n" % rsa_keysize_str)
        sys.exit(1)

    user = getpass.getuser()
    try:
        group = grp.getgrnam(user)[0]
    except KeyError:
        group = "<unknown>"
    tzinfo = datetime.datetime.now(datetime.timezone.utc).astimezone().tzinfo
    logit(LOGFILE, "Starting vTPM manufacturing as %s:%s @ %s\n" %
          (user, group,
           datetime.datetime.now(tz=tzinfo).strftime("%a %d %h %Y %I:%M:%S %p %Z")))

    if not flags & SETUP_TPM2_F:
        ret = init_tpm(flags, swtpm_prg_l, config_file, tpm_state_path, ownerpass, srkpass, vmid,
                       swtpm_keyopt, fds_to_pass)
    else:
        ret = init_tpm2(flags, swtpm_prg_l, config_file, tpm_state_path, vmid, pcr_banks,
                        swtpm_keyopt, fds_to_pass, rsa_keysize)

    if ret == 0:
        logit(LOGFILE, "Successfully authored TPM state.\n")
    else:
        logerr(LOGFILE, "An error occurred. Authoring the TPM state failed.\n")
        delete_state(flags, tpm_state_path)

    logit(LOGFILE, "Ending vTPM manufacturing @ %s\n" %
          datetime.datetime.now(tz=tzinfo).strftime("%a %d %h %Y %I:%M:%S %p %Z"))

    sys.exit(ret)


if __name__ == "__main__":
    main()
