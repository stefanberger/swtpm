
""" tpm.py

Wrapper classes for swtpm
"""

# pylint: disable=R0902,R0913,R0914,C0302,W0703


#
# swtpm_setup.py
#
# Authors: Stefan Berger <stefanb@linux.ibm.com>
#
# (c) Copyright IBM Corporation 2020
#

import os
import socket
import struct
import subprocess
import time

# TPM1.2 imports
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

from py_swtpm_setup.swtpm_utils import logit, logerr, sha1

CMD_INIT = 0x2
CMD_SHUTDOWN = 0x3
CMD_GET_INFO = 0x12

TPMLIB_INFO_TPMSPECIFICATION = 1
TPMLIB_INFO_TPMATTRIBUTES = 2

#
# swtpm base class for TPM 1.2 and TPM 2.0
#
class Swtpm:
    """ Swtpm is the base class for usage of swtpm as TPM 1.2 or TPM 2 """

    def __init__(self, swtpm_exec_l, state_path, keyopt, logfile, fds_to_pass, is_tpm2=False):
        """ Class constructor
            swtpm_exec_l is a list like ["swtpm", "socket"]
        """

        self.swtpm_exec_l = swtpm_exec_l
        self.state_path = state_path
        self.keyopt = keyopt
        self.logfile = logfile
        self.fds_to_pass = fds_to_pass
        self.is_tpm2 = is_tpm2

        self.pidfile = None
        self.swtpm_proc = None
        self.data_client_socket = None
        self.data_swtpm_socket = None
        self.ctrl_client_socket = None
        self.ctrl_swtpm_socket = None

    def start(self):
        """ The start method starts the TPM 2 """

        self.pidfile = os.path.join(self.state_path, ".swtpm_setup.pidfile")
        cmdline = self.swtpm_exec_l.copy()

        if self.is_tpm2:
            cmdline.extend(["--tpm2"])

        if self.keyopt:
            cmdline.extend(["--key", self.keyopt])

        cmdline.extend(["--flags", "not-need-init",
                        "--tpmstate", "dir=%s" % self.state_path,
                        "--pid", "file=%s" % self.pidfile])
        # cmdline.extend(["--log", "file=/tmp/log,level=20"])

        ctr = 0
        while ctr < 100:
            self.data_client_socket, self.data_swtpm_socket = socket.socketpair(socket.AF_UNIX,
                                                                                socket.SOCK_STREAM)
            os.set_inheritable(self.data_swtpm_socket.fileno(), True)

            self.ctrl_client_socket, self.ctrl_swtpm_socket = socket.socketpair(socket.AF_UNIX,
                                                                                socket.SOCK_STREAM)
            os.set_inheritable(self.ctrl_swtpm_socket.fileno(), True)

            r_cmdline = cmdline.copy()
            r_cmdline.extend(["--server", "type=tcp,fd=%d" % self.data_swtpm_socket.fileno(),
                              "--ctrl", "type=unixio,clientfd=%d" %
                              self.ctrl_swtpm_socket.fileno()])

            self.remove_pidfile()

            # print("starting swtpm: %s\n" % r_cmdline)
            try:
                pass_fds = [self.data_swtpm_socket.fileno(),
                            self.ctrl_swtpm_socket.fileno()]
                pass_fds.extend(self.fds_to_pass)

                self.swtpm_proc = subprocess.Popen(r_cmdline, stdout=subprocess.PIPE,
                                                   stderr=subprocess.STDOUT, pass_fds=pass_fds)
            except Exception as err:
                logerr(self.logfile,
                       "Failed to start swtpm %s: %s\n" % (" ".join(self.swtpm_exec_l), str(err)))

            ctr += 1

            ctr2 = 0
            while True:
                # Is it still running?
                if self.swtpm_proc.poll():
                    stderr = self.swtpm_proc.communicate()[0]
                    print("TPM died? %s\n" % stderr)
                    self.stop()
                    break

                if os.path.exists(self.pidfile):
                    print("TPM is listening on Unix socket.")
                    return 0

                ctr2 += 1
                time.sleep(0.05)

                if ctr2 == 40:
                    self.stop()
                    break

        return 1

    def remove_pidfile(self):
        """ Remove the pidfile if it exists """

        if self.pidfile:
            try:
                os.remove(self.pidfile)
            except Exception:
                pass

    def stop(self):
        """ Stop the running swtpm instance """

        if self.swtpm_proc:
            if not self.swtpm_proc.poll():
                self.ctrl_shutdown()
            try:
                self.swtpm_proc.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                self.swtpm_proc.kill()
                self.swtpm_proc.wait()
            self.swtpm_proc = None
        self.remove_pidfile()

        for sock in [self.data_client_socket, self.data_swtpm_socket,
                     self.ctrl_client_socket, self.ctrl_swtpm_socket]:
            if sock:
                sock.close()
        self.data_client_socket = None
        self.data_swtpm_socket = None
        self.ctrl_client_socket = None
        self.ctrl_swtpm_socket = None

    def destroy(self):
        """ Destroy the running swtpm instance """

        self.stop()

    def transfer(self, req, cmdname, use_ctrl=False):
        """ Send a command to swtpm and receive a response """

        if use_ctrl:
            sock = self.ctrl_client_socket
            offset = 0
        else:
            sock = self.data_client_socket
            offset = 6

        try:
            sock.sendall(req)
            rsp = sock.recv(4096)
        except Exception as err:
            logerr(self.logfile, "transfer error: %s\n" % str(err))
            return None, 1

        if not use_ctrl:
            if len(rsp) < 10:
                logerr(self.logfile,
                       "Response for %s has only %d bytes.\n" % (cmdname, len(rsp)))
                return None, 1

        returncode = struct.unpack(">I", rsp[offset:offset+4])[0]
        if returncode != 0:
            logerr(self.logfile, "%s failed: 0x%x\n" % (cmdname, returncode))
            return None, 1

        return rsp, 0

    def ctrl_init(self):
        """ Send an Init over the control channel """

        req = struct.pack(">I I", CMD_INIT, 0)
        _, ret = self.transfer(req, "CMD_INIT", use_ctrl=True)
        return ret

    def ctrl_shutdown(self):
        """ Send an Init over the control channel """

        req = struct.pack(">I", CMD_SHUTDOWN)
        _, ret = self.transfer(req, "CMD_SHUTDOWN", use_ctrl=True)
        return ret

    def ctrl_get_tpm_specs_and_attrs(self):
        """ Get the TPM specification parameters over the control channel """

        req = struct.pack(">I QII", CMD_GET_INFO,
                          TPMLIB_INFO_TPMSPECIFICATION | TPMLIB_INFO_TPMATTRIBUTES, 0, 0)
        rsp, ret = self.transfer(req, "CMD_GET_INFO", use_ctrl=True)
        if ret != 0:
            return "", 1

        length = struct.unpack(">I", rsp[8:12])[0]
        # compensate for null-terminated string
        length -= 1
        data = struct.unpack("%ds" % length, rsp[12:12+length])[0]

        return data.decode(), 0

#
# TPM 2 support
#

TPM2_ST_NO_SESSIONS = 0x8001
TPM2_ST_SESSIONS = 0x8002

TPM2_CC_EVICTCONTROL = 0x00000120
TPM2_CC_NV_DEFINESPACE = 0x0000012a
TPM2_CC_PCR_ALLOCATE = 0x0000012b
TPM2_CC_CREATEPRIMARY = 0x00000131
TPM2_CC_NV_WRITE = 0x00000137
TPM2_CC_NV_WRITELOCK = 0x00000138
TPM2_CC_STARTUP = 0x00000144
TPM2_CC_SHUTDOWN = 0x00000145
TPM2_CC_GETCAPABILITY = 0x0000017a

TPM2_SU_CLEAR = 0x0000

TPM2_RH_OWNER = 0x40000001
TPM2_RS_PW = 0x40000009
TPM2_RH_ENDORSEMENT = 0x4000000b
TPM2_RH_PLATFORM = 0x4000000c

TPM2_ALG_RSA = 0x0001
TPM2_ALG_SHA1 = 0x0004
TPM2_ALG_AES = 0x0006
TPM2_ALG_SHA256 = 0x000b
TPM2_ALG_SHA384 = 0x000c
TPM2_ALG_SHA512 = 0x000d
TPM2_ALG_SHA3_256 = 0x0027
TPM2_ALG_SHA3_384 = 0x0028
TPM2_ALG_SHA3_512 = 0x0028
TPM2_ALG_NULL = 0x0010
TPM2_ALG_SM3 = 0x0012
TPM2_ALG_ECC = 0x0023
TPM2_ALG_CFB = 0x0043

TPM2_CAP_PCRS = 0x00000005

TPM2_ECC_NIST_P384 = 0x0004

TPMA_NV_PLATFORMCREATE = 0x40000000
TPMA_NV_AUTHREAD = 0x40000
TPMA_NV_NO_DA = 0x2000000
TPMA_NV_PPWRITE = 0x1
TPMA_NV_PPREAD = 0x10000
TPMA_NV_OWNERREAD = 0x20000
TPMA_NV_WRITEDEFINE = 0x2000

# Use standard EK Cert NVRAM, EK and SRK handles per IWG spec.
# "TCG TPM v2.0 Provisioning Guide"; Version 1.0, Rev 1.0, March 15, 2017
# Table 2
TPM2_NV_INDEX_RSA2048_EKCERT = 0x01c00002
TPM2_NV_INDEX_RSA2048_EKTEMPLATE = 0x01c00004
TPM2_NV_INDEX_RSA3072_HI_EKCERT = 0x01c0001c
TPM2_NV_INDEX_RSA3072_HI_EKTEMPLATE = 0x01c0001d
# For ECC follow "TCG EK Credential Profile For TPM Family 2.0; Level 0"
# Specification Version 2.1; Revision 13; 10 December 2018
TPM2_NV_INDEX_PLATFORMCERT = 0x01c08000

TPM2_NV_INDEX_ECC_SECP384R1_HI_EKCERT = 0x01c00016
TPM2_NV_INDEX_ECC_SECP384R1_HI_EKTEMPLATE = 0x01c00017

TPM2_EK_RSA_HANDLE = 0x81010001
TPM2_EK_RSA3072_HANDLE = 0x8101001c
TPM2_EK_ECC_SECP384R1_HANDLE = 0x81010016
TPM2_SPK_HANDLE = 0x81000001

NONCE_EMPTY = struct.pack('>H', 0)
NONCE_RSA2048 = struct.pack('>H256s', 0x100, ('\0' * 0x100).encode())
NONCE_RSA3072 = struct.pack('>H384s', 0x180, ('\0' * 0x180).encode())
NONCE_ECC_384 = struct.pack('>H48s', 0x30, ('\0' * 0x30).encode())

PCR_BANKS_TO_NAMES = {
    TPM2_ALG_SHA1: "sha1",
    TPM2_ALG_SHA256: "sha256",
    TPM2_ALG_SHA384: "sha384",
    TPM2_ALG_SHA512: "sha512",
    TPM2_ALG_SM3: "sm3-256",
    TPM2_ALG_SHA3_256: "sha3-256",
    TPM2_ALG_SHA3_384: "sha3-384",
    TPM2_ALG_SHA3_512: "sha3-512",
}

BANK_NAMES_TO_ALGID = {
    "sha1": TPM2_ALG_SHA1,
    "sha256": TPM2_ALG_SHA256,
    "sha384": TPM2_ALG_SHA384,
    "sha512": TPM2_ALG_SHA512,
    "sm3-256": TPM2_ALG_SM3,
    "sha3-256": TPM2_ALG_SHA3_256,
    "sha3-384": TPM2_ALG_SHA3_384,
    "sha3-512": TPM2_ALG_SHA3_512,
}


class Swtpm2(Swtpm):
    """ Class for manufacturing a swtpm TPM 2 """

    def __init__(self, swtpm_exec_l, state_path, keyopt, logfile, fds_to_pass):
        """ Class constructor
            swtpm_exec_l is a list like ["swtpm", "socket"]
        """

        super(Swtpm2, self).__init__(swtpm_exec_l, state_path, keyopt, logfile, fds_to_pass,
                                     is_tpm2=True)

    def shutdown(self):
        """ Shut down the TPM 2 """

        fmt = ">HII H"
        req = struct.pack(fmt,
                          TPM2_ST_NO_SESSIONS, struct.calcsize(fmt), TPM2_CC_SHUTDOWN,
                          TPM2_SU_CLEAR)

        _, ret = self.transfer(req, "TPM2_Shutdown")
        return ret

    def run_swtpm_bios(self):
        """ Startup the TPM 2 """

        fmt = '>HII H'
        req = struct.pack(fmt,
                          TPM2_ST_NO_SESSIONS, struct.calcsize(fmt), TPM2_CC_STARTUP,
                          TPM2_SU_CLEAR)
        _, ret = self.transfer(req, "TPM2_Startup")
        return ret

    def get_all_pcr_banks(self):
        """ Get all available PCR banks """

        fmt = '>HII III'
        req = struct.pack(fmt,
                          TPM2_ST_NO_SESSIONS, struct.calcsize(fmt), TPM2_CC_GETCAPABILITY,
                          TPM2_CAP_PCRS, 0, 64)
        rsp, ret = self.transfer(req, "TPM2_GetCapability")
        if ret != 0:
            return [], 1

        count = struct.unpack('>H', rsp[17:19])[0]
        offset = 19

        res = []
        for _ in range(count):
            bank, length = struct.unpack('>HB', rsp[offset:offset+3])
            name = PCR_BANKS_TO_NAMES[bank]
            if name:
                res.append(name)
            else:
                res.append('%02x' % bank)
            offset += 2 + 1 + length

        return res, 0

    def set_active_pcr_banks(self, pcr_banks, all_pcr_banks):
        """ Set the list of active PCR banks to the one the user wants """

        pcrselects = "".encode()
        count = 0
        active = []

        # enable the ones the user wants
        for pcr_bank in pcr_banks:
            if pcr_bank not in all_pcr_banks:
                # Skip if not even available
                continue
            try:
                hashalg = BANK_NAMES_TO_ALGID[pcr_bank]
            except KeyError:
                continue

            active.insert(0, pcr_bank)
            pcrselects += struct.pack('>H BBBB', hashalg, 3, 0xff, 0xff, 0xff)

            #print("activate hashalg = %d\n" % hashalg)
            count += 1

        if len(active) == 0:
            logerr(self.logfile,
                   "No PCR banks could be allocated. None of the selected algorithms are "
                   "supported.\n")
            return [], 1

        # disable the rest
        for pcr_bank in all_pcr_banks:
            if pcr_bank in pcr_banks:
                # Skip if to activate
                continue

            try:
                hashalg = BANK_NAMES_TO_ALGID[pcr_bank]
            except KeyError:
                continue

            #print("deactivate hashalg = %d\n" % hashalg)
            pcrselects += struct.pack('>H BBBB', hashalg, 3, 0, 0, 0)
            count += 1

        authblock = struct.pack('>I HBH', TPM2_RS_PW, 0, 0, 0)
        fmt = '>HII I I%ds I %ds' % (len(authblock), len(pcrselects))
        req = struct.pack(fmt,
                          TPM2_ST_SESSIONS, struct.calcsize(fmt), TPM2_CC_PCR_ALLOCATE,
                          TPM2_RH_PLATFORM,
                          len(authblock), authblock,
                          count,
                          pcrselects)

        _, ret = self.transfer(req, "TPM2_PCR_Allocate")

        return active, ret

    def evictcontrol(self, curr_handle, perm_handle):
        """ Make object at the curr_handler permanent with the perm_handle """

        authblock = struct.pack('>IHBH', TPM2_RS_PW, 0, 0, 0)

        fmt = '>HII II I%ds I' % len(authblock)
        req = struct.pack(fmt,
                          TPM2_ST_SESSIONS, struct.calcsize(fmt), TPM2_CC_EVICTCONTROL,
                          TPM2_RH_OWNER, curr_handle,
                          len(authblock), authblock,
                          perm_handle)

        _, ret = self.transfer(req, "TPM2_EvictControl")
        return ret

    def createprimary_ek_rsa(self, rsa_keysize, allowsigning, decryption):
        """ Create an RSA Ek """

        if rsa_keysize == 2048:
            authpolicy = b'\x83\x71\x97\x67\x44\x84\xb3\xf8\x1a\x90\xcc\x8d' \
            b'\x46\xa5\xd7\x24\xfd\x52\xd7\x6e\x06\x52\x0b\x64' \
            b'\xf2\xa1\xda\x1b\x33\x14\x69\xaa'
            keyflags = 0
            symkeylen = 128
            havenonce = True
            addlen = 0
        elif rsa_keysize == 3072:
            authpolicy = b'\xB2\x6E\x7D\x28\xD1\x1A\x50\xBC\x53\xD8\x82\xBC' \
            b'\xF5\xFD\x3A\x1A\x07\x41\x48\xBB\x35\xD3\xB4\xE4' \
            b'\xCB\x1C\x0A\xD9\xBD\xE4\x19\xCA\xCB\x47\xBA\x09' \
            b'\x69\x96\x46\x15\x0F\x9F\xC0\x00\xF3\xF8\x0E\x12'
            keyflags = 0x40
            symkeylen = 256
            havenonce = False
            addlen = 16

        if allowsigning and decryption:
            # keyflags: fixedTPM, fixedParent, sensitiveDatOrigin,
            # adminWithPolicy, sign, decrypt
            keyflags = keyflags | 0x000600b2
            # symmetric: TPM_ALG_NULL
            symkeydata = struct.pack(">H", TPM2_ALG_NULL)
            off = 72 + addlen
        elif allowsigning:
            # keyflags: fixedTPM, fixedParent, sensitiveDatOrigin,
            # adminWithPolicy, sign
            keyflags = keyflags | 0x000400b2
            # symmetric: TPM_ALG_NULL
            symkeydata = struct.pack(">H", TPM2_ALG_NULL)
            off = 72 + addlen
        else:
            # keyflags: fixedTPM, fixedParent, sensitiveDatOrigin,
            # adminWithPolicy, restricted, decrypt
            keyflags = keyflags | 0x000300b2
            # symmetric: TPM_ALG_AES, 128bit or 256bit, TPM_ALG_CFB
            symkeydata = struct.pack(">HHH", TPM2_ALG_AES, symkeylen, TPM2_ALG_CFB)
            off = 76 + addlen

        return self._createprimary_rsa(TPM2_RH_ENDORSEMENT, keyflags, symkeydata, authpolicy,
                                       rsa_keysize, havenonce, off)

    def _createprimary_rsa(self, primaryhandle, keyflags, symkeydata, authpolicy,
                           rsa_keysize, havenonce, off):
        """ Create an RSA key with the given parameters """

        if rsa_keysize == 2048:
            nonce = NONCE_RSA2048
            hashalg = TPM2_ALG_SHA256
        elif rsa_keysize == 3072:
            if not havenonce:
                nonce = NONCE_EMPTY
            else:
                nonce = NONCE_RSA3072
            hashalg = TPM2_ALG_SHA384
        else:
            logerr(self.logfile, "Unsupported keysize %d\n" % rsa_keysize)
            return b'', "", 0, 1

        authblock = struct.pack('>IHBH', TPM2_RS_PW, 0, 0, 0)

        fmt = '>HHI H%ds %ds HH I %ds' % \
              (len(authpolicy), len(symkeydata), len(nonce))
        public = struct.pack(fmt,
                             TPM2_ALG_RSA, hashalg, keyflags,
                             len(authpolicy), authpolicy,
                             symkeydata,
                             TPM2_ALG_NULL, rsa_keysize,
                             0,
                             nonce)
        ek_template = public

        fmt = ">HII I I%ds HI H%ds IH" % (len(authblock), len(public))
        req = struct.pack(fmt,
                          TPM2_ST_SESSIONS, struct.calcsize(fmt), TPM2_CC_CREATEPRIMARY,
                          primaryhandle,
                          len(authblock), authblock,
                          4, 0,
                          len(public), public,
                          0, 0)
        rsp, ret = self.transfer(req, "TPM2_CreatePrimary")
        if ret != 0:
            return b'', "", 0, 1

        handle = struct.unpack(">I", rsp[10:14])[0]

        modlen = struct.unpack(">H", rsp[off:off+2])[0]
        if modlen != rsa_keysize >> 3:
            logerr(self.logfile, "RSA key: Getting modulus from wrong offset %d\n" % off)
            return b'', "", 0, 1
        off += 2
        ekparam = struct.unpack(">%ds" % modlen, rsp[off:off+modlen])[0].hex()

        return ek_template, ekparam, handle, 0

    def _createprimary_ecc(self, primaryhandle, keyflags, symkeydata, authpolicy,
                           curveid, hashalg, nonce, off):
        """ Create an ECC key with the given parameters """

        authblock = struct.pack('>IHBH', TPM2_RS_PW, 0, 0, 0)

        fmt = '>HHI H%ds %ds HH H %ds%ds' % \
              (len(authpolicy), len(symkeydata), len(nonce), len(nonce))
        public = struct.pack(fmt,
                             TPM2_ALG_ECC, hashalg, keyflags,
                             len(authpolicy), authpolicy,
                             symkeydata,
                             TPM2_ALG_NULL, curveid,
                             TPM2_ALG_NULL,
                             nonce, nonce)
        ek_template = public

        fmt = '>HII I I%ds HI H%ds IH' % (len(authblock), len(public))
        req = struct.pack(fmt,
                          TPM2_ST_SESSIONS, struct.calcsize(fmt), TPM2_CC_CREATEPRIMARY,
                          primaryhandle,
                          len(authblock), authblock,
                          4, 0,
                          len(public), public,
                          0, 0)
        rsp, ret = self.transfer(req, "TPM2_CreatePrimary")
        if ret != 0:
            return b'', "", 0, 1

        handle = struct.unpack('>I', rsp[10:14])[0]

        if curveid == TPM2_ECC_NIST_P384:
            exp_ksize = 48
            cid = "secp384r1"
        else:
            logerr(self.logfile, "Unknown curveid 0x%x\n" % curveid)
            return b'', "", 0, 1

        ksize1 = struct.unpack('>H', rsp[off:off+2])[0]
        off2 = off + 2 + ksize1
        ksize2 = struct.unpack('>H', rsp[off2:off2+2])[0]

        if ksize1 != exp_ksize or ksize2 != exp_ksize:
            logerr(self.logfile, "ECC: Getting key parameters from wrong offset\n")
            return b'', "", 0, 1

        off += 2
        xparam = struct.unpack(">%ds" % ksize1, rsp[off:off+ksize1])[0]
        off2 += 2
        yparam = struct.unpack(">%ds" % ksize2, rsp[off2:off2+ksize2])[0]

        ekparam = "x=%s,y=%s,id=%s" % (xparam.hex(), yparam.hex(), cid)

        return ek_template, ekparam, handle, 0

    def createprimary_spk_ecc_nist_p384(self):
        """ Create a NIST p384 ECC SPK """

        keyflags = 0x00030472
        symkeydata = struct.pack('>HHH', TPM2_ALG_AES, 256, TPM2_ALG_CFB)
        authpolicy = b''
        off = 42

        return self._createprimary_ecc(TPM2_RH_OWNER, keyflags, symkeydata, authpolicy,
                                       TPM2_ECC_NIST_P384, TPM2_ALG_SHA384, NONCE_ECC_384, off)

    def createprimary_spk_rsa(self, rsa_keysize):
        """ Create a primary RSA key with the given keysize """

        keyflags = 0x00030472
        authpolicy = ''.encode()

        if rsa_keysize == 2048:
            symkeylen = 128
        elif rsa_keysize == 3072:
            symkeylen = 256
        symkeydata = struct.pack('>HHH', TPM2_ALG_AES, symkeylen, TPM2_ALG_CFB)
        off = 44

        return self._createprimary_rsa(TPM2_RH_OWNER, keyflags, symkeydata, authpolicy,
                                       rsa_keysize, True, off)

    def create_spk(self, isecc, rsa_keysize):
        """ Create either an ECC or RSA storage primary key """

        if isecc:
            _, _, handle, ret = self.createprimary_spk_ecc_nist_p384()
        else:
            _, _, handle, ret = self.createprimary_spk_rsa(rsa_keysize)

        if ret != 0:
            return 1

        ret = self.evictcontrol(handle, TPM2_SPK_HANDLE)
        if ret == 0:
            logit(self.logfile,
                  "Successfully created storage primary key with handle 0x%x.\n" % TPM2_SPK_HANDLE)

        return ret

    def createprimary_ek_ecc_nist_p384(self, allowsigning, decryption):
        """ Create en ECC EK key that may be allowed to sign and/or decrypt """

        if allowsigning and decryption:
            # keyflags: fixedTPM, fixedParent, sensitiveDatOrigin,
            # userWithAuth, adminWithPolicy, sign, decrypt
            keyflags = 0x000600f2
            # symmetric: TPM_ALG_NULL
            symkeydata = struct.pack(">H", TPM2_ALG_NULL)
            off = 86
        elif allowsigning:
            # keyflags: fixedTPM, fixedParent, sensitiveDatOrigin,
            # userWithAuth, adminWithPolicy, sign
            keyflags = 0x000400f2
            # symmetric: TPM_ALG_NULL
            symkeydata = struct.pack(">H", TPM2_ALG_NULL)
            off = 86
        else:
            # keyflags: fixedTPM, fixedParent, sensitiveDatOrigin,
            # userWithAuth, adminWithPolicy, restricted, decrypt
            keyflags = 0x000300f2
            # symmetric: TPM_ALG_AES, 256bit, TPM_ALG_CFB
            symkeydata = struct.pack(">HHH", TPM2_ALG_AES, 256, TPM2_ALG_CFB)
            off = 90

	# authPolicy from Ek Credential Profile; Spec v 2.1; rev12; p. 43
        authpolicy = b'\xB2\x6E\x7D\x28\xD1\x1A\x50\xBC\x53\xD8\x82\xBC' \
        b'\xF5\xFD\x3A\x1A\x07\x41\x48\xBB\x35\xD3\xB4\xE4' \
        b'\xCB\x1C\x0A\xD9\xBD\xE4\x19\xCA\xCB\x47\xBA\x09' \
        b'\x69\x96\x46\x15\x0F\x9F\xC0\x00\xF3\xF8\x0E\x12'

        ek_template, ekparam, handle, ret = \
            self._createprimary_ecc(TPM2_RH_ENDORSEMENT, keyflags, symkeydata, authpolicy,
                                    TPM2_ECC_NIST_P384, TPM2_ALG_SHA384, NONCE_EMPTY, off)
        if ret != 0:
            logerr(self.logfile, "create_spk_ecc failed\n")

        return ek_template, ekparam, handle, ret

    def create_ek(self, isecc, rsa_keysize, allowsigning, decryption, lock_nvram):
        """ Create an ECC or RSA EK """

        if isecc:
            tpm2_ek_handle = TPM2_EK_ECC_SECP384R1_HANDLE
            keytype = "ECC"
            nvindex = TPM2_NV_INDEX_ECC_SECP384R1_HI_EKTEMPLATE
        else:
            if rsa_keysize == 2048:
                tpm2_ek_handle = TPM2_EK_RSA_HANDLE
                nvindex = TPM2_NV_INDEX_RSA2048_EKTEMPLATE
            elif rsa_keysize == 3072:
                tpm2_ek_handle = TPM2_EK_RSA3072_HANDLE
                nvindex = TPM2_NV_INDEX_RSA3072_HI_EKTEMPLATE
            keytype = "RSA %d" % rsa_keysize

        if isecc:
            ek_template, ekparam, handle, ret = \
                self.createprimary_ek_ecc_nist_p384(allowsigning, decryption)
        else:
            ek_template, ekparam, handle, ret = \
                self.createprimary_ek_rsa(rsa_keysize, allowsigning, decryption)

        if ret == 0:
            ret = self.evictcontrol(handle, tpm2_ek_handle)
        if ret != 0:
            logerr(self.logfile, "create_ek failed\n")
            return "", 1

        logit(self.logfile,
              "Successfully created %s EK with handle 0x%x.\n" % (keytype, tpm2_ek_handle))

        if allowsigning:
            nvindexattrs = TPMA_NV_PLATFORMCREATE | \
		TPMA_NV_AUTHREAD | \
		TPMA_NV_OWNERREAD | \
		TPMA_NV_PPREAD | \
		TPMA_NV_PPWRITE | \
		TPMA_NV_NO_DA | \
		TPMA_NV_WRITEDEFINE
            ret = self.write_nvram(nvindex, nvindexattrs, ek_template, lock_nvram, "EK template")
            if ret == 0:
                logit(self.logfile,
                      "Successfully created NVRAM area 0x%x for %s EK template.\n" %
                      (nvindex, keytype))

        return ekparam, ret

    def nv_definespace(self, nvindex, nvindexattrs, size):
        """ Define an NVIndex with attributes and given size """

        authblock = struct.pack(">IHBH", TPM2_RS_PW, 0, 0, 0)

        nvpublic = struct.pack('>IHI H H',
                               nvindex, TPM2_ALG_SHA256, nvindexattrs,
                               0,
                               size)

        fmt = ">HII I I%ds H H%ds" % (len(authblock), len(nvpublic))
        req = struct.pack(fmt,
                          TPM2_ST_SESSIONS, struct.calcsize(fmt), TPM2_CC_NV_DEFINESPACE,
                          TPM2_RH_PLATFORM,
                          len(authblock), authblock,
                          0,
                          len(nvpublic), nvpublic)

        _, ret = self.transfer(req, "TPM2_NV_DefineSpace")
        return ret

    def nv_write(self, nvindex, data):
        """ Write the data into the given NVIndex """

        authblock = struct.pack(">IHBH", TPM2_RS_PW, 0, 0, 0)

        offset = 0
        stepsize = 1024

        while offset < len(data):
            if offset + stepsize < len(data):
                buf = data[offset : offset + stepsize]
            else:
                buf = data[offset : len(data)]

            fmt = ">HII II I%ds H%dsH" % (len(authblock), len(buf))
            req = struct.pack(fmt,
                              TPM2_ST_SESSIONS, struct.calcsize(fmt), TPM2_CC_NV_WRITE,
                              TPM2_RH_PLATFORM, nvindex,
                              len(authblock), authblock,
                              len(buf), buf, offset)

            _, ret = self.transfer(req, "TPM2_NV_Write")
            if ret != 0:
                return 1

            offset += stepsize

        return 0

    def nv_writelock(self, nvindex):
        """ Lock the given index """

        authblock = struct.pack(">IHBH", TPM2_RS_PW, 0, 0, 0)

        fmt = ">HII II I%ds" % (len(authblock))
        req = struct.pack(fmt,
                          TPM2_ST_SESSIONS, struct.calcsize(fmt), TPM2_CC_NV_WRITELOCK,
                          TPM2_RH_PLATFORM, nvindex,
                          len(authblock), authblock)

        _, ret = self.transfer(req, "TPM2_NV_WriteLock")
        return ret

    def write_nvram(self, nvindex, nvindexattrs, data, lock_nvram, purpose):
        """ Define NVRAM space, write data to it and lock it if wanted """

        ret = self.nv_definespace(nvindex, nvindexattrs, len(data))
        if ret != 0:
            logerr(self.logfile, "Could not create NVRAM area 0x%x for %s.\n" % (nvindex, purpose))
            return 1

        ret = self.nv_write(nvindex, data)
        if ret != 0:
            logerr(self.logfile,
                   "Could not write %s into NVRAM area 0x%x.\n" % (purpose, nvindex))
            return 1

        if lock_nvram:
            ret = self.nv_writelock(nvindex)
            if ret != 0:
                logerr(self.logfile, "Could not lock EK template NVRAM area 0x%x.\n" % nvindex)
                return 1

        return ret

    def write_ek_cert_nvram(self, isecc, rsa_keysize, lock_nvram, ekcert):
        """ Write the given ekcert into an NVRAM area appropriate for the key type and size """

        if not isecc:
            if rsa_keysize == 2048:
                nvindex = TPM2_NV_INDEX_RSA2048_EKCERT
            elif rsa_keysize == 3072:
                nvindex = TPM2_NV_INDEX_RSA3072_HI_EKCERT
            keytype = "RSA %d" % rsa_keysize
        else:
            nvindex = TPM2_NV_INDEX_ECC_SECP384R1_HI_EKCERT
            keytype = "ECC"

        nvindexattrs = TPMA_NV_PLATFORMCREATE | \
            TPMA_NV_AUTHREAD | \
            TPMA_NV_OWNERREAD | \
            TPMA_NV_PPREAD | \
            TPMA_NV_PPWRITE | \
            TPMA_NV_NO_DA | \
            TPMA_NV_WRITEDEFINE
        ret = self.write_nvram(nvindex, nvindexattrs, ekcert, lock_nvram, "EK Certificate")
        if ret == 0:
            logit(self.logfile,
                  "Successfully created NVRAM area 0x%x for %s EK certificate.\n" %
                  (nvindex, keytype))
        else:
            logerr(self.logfile,
                   "Could not create NVRAM area 0x%x for %s EK certificate.\n" %
                   (nvindex, keytype))
        return ret

    def write_platform_cert_nvram(self, lock_nvram, platformcert):
        """ Write the platform certificate into an NVRAM area """

        nvindex = TPM2_NV_INDEX_PLATFORMCERT
        nvindexattrs = TPMA_NV_PLATFORMCREATE | \
            TPMA_NV_AUTHREAD | \
            TPMA_NV_OWNERREAD | \
            TPMA_NV_PPREAD | \
            TPMA_NV_PPWRITE | \
            TPMA_NV_NO_DA | \
            TPMA_NV_WRITEDEFINE
        ret = self.write_nvram(nvindex, nvindexattrs, platformcert, lock_nvram,
                               "Platform Certificate")
        if ret == 0:
            logit(self.logfile,
                  "Successfully created NVRAM area 0x%x for platform certificate.\n" % nvindex)
        else:
            logerr(self.logfile,
                   "Could not create NVRAM area 0x%x for platform certificate.\n" % nvindex)
        return ret


#
# TPM 1.2 support
#

TPM_TAG_RQU_COMMAND = 0x00c1
TPM_TAG_RQU_AUTH1_COMMAND = 0x00c2

TPM_ORD_OIAP = 0x0000000A
TPM_ORD_OSAP = 0x0000000B
TPM_ORD_TAKE_OWNERSHIP = 0x0000000D
TPM_ORD_OWNER_CLEAR = 0x0000005B
TPM_ORD_PHYSICAL_ENABLE = 0x0000006F
TPM_ORD_PHYSICAL_SET_DEACTIVATED = 0x00000072
TPM_ORD_STARTUP = 0x00000099
TPM_ORD_NV_DEFINE_SPACE = 0x000000CC
TPM_ORD_NV_WRITE_VALUE = 0x000000CD
TSC_ORD_PHYSICAL_PRESENCE = 0x4000000A

TPM_ST_CLEAR = 0x0001

TPM_PHYSICAL_PRESENCE_CMD_ENABLE = 0x0020
TPM_PHYSICAL_PRESENCE_PRESENT = 0x0008

TPM_ALG_RSA = 0x00000001

TPM_KEY_STORAGE = 0x0011

TPM_AUTH_ALWAYS = 0x01

TPM_PID_OWNER = 0x0005

TPM_ES_RSAESOAEP_SHA1_MGF1 = 0x0003
TPM_SS_NONE = 0x0001

TPM_TAG_PCR_INFO_LONG = 0x0006
TPM_TAG_NV_ATTRIBUTES = 0x0017
TPM_TAG_NV_DATA_PUBLIC = 0x0018
TPM_TAG_KEY12 = 0x0028

TPM_LOC_ZERO = 0x01
TPM_LOC_ALL = 0x1f

TPM_NV_INDEX_D_BIT = 0x10000000
TPM_NV_INDEX_EKCERT = 0xF000
TPM_NV_INDEX_PLATFORMCERT = 0xF002

TPM_NV_INDEX_LOCK = 0xFFFFFFFF

TPM_NV_PER_OWNERREAD = 0x00020000
TPM_NV_PER_OWNERWRITE = 0x00000002

TPM_ET_OWNER = 0x02
TPM_ET_NV = 0x0b

TPM_KH_EK = 0x40000006

class Swtpm12(Swtpm):
    """ Class for manufacturing a swtpm TPM 1.2 """

    def __init__(self, swtpm_exec_l, state_path, keyopt, logfile, fds_to_pass):
        """ Class constructor
            swtpm_exec_l is a list like ["swtpm", "socket"]
        """

        super(Swtpm12, self).__init__(swtpm_exec_l, state_path, keyopt, logfile, fds_to_pass)

    def startup(self, startup_type):
        """ Run TPM_Startup() """

        fmt = ">HII H"
        req = struct.pack(fmt,
                          TPM_TAG_RQU_COMMAND, struct.calcsize(fmt), TPM_ORD_STARTUP,
                          startup_type)

        _, ret = self.transfer(req, "TPM_Startup")
        return ret

    def tsc_physicalpresence(self, physicalpresence):
        """ Run TSC_PhysicalPresence """

        fmt = ">HII H"
        req = struct.pack(fmt,
                          TPM_TAG_RQU_COMMAND, struct.calcsize(fmt), TSC_ORD_PHYSICAL_PRESENCE,
                          physicalpresence)

        _, ret = self.transfer(req, "TSC_PhysicalPresence")
        return ret

    def physical_enable(self):
        """ Run TPM_PhysicalEnable """

        fmt = ">HII"
        req = struct.pack(fmt,
                          TPM_TAG_RQU_COMMAND, struct.calcsize(fmt), TPM_ORD_PHYSICAL_ENABLE)

        _, ret = self.transfer(req, "TSC_PhysicalEnable")
        return ret

    def physical_set_deactivated(self, state):
        """ Run TPM_PhysicalSetDeactivated """

        fmt = ">HI I B"
        req = struct.pack(fmt,
                          TPM_TAG_RQU_COMMAND, struct.calcsize(fmt),
                          TPM_ORD_PHYSICAL_SET_DEACTIVATED,
                          state)

        _, ret = self.transfer(req, "TPM_PhysiclaSetDaectivated")
        return ret

    def run_swtpm_bios(self):
        """ Initialize the swtpm """

        if self.startup(TPM_ST_CLEAR) or \
           self.tsc_physicalpresence(TPM_PHYSICAL_PRESENCE_CMD_ENABLE) or \
           self.tsc_physicalpresence(TPM_PHYSICAL_PRESENCE_PRESENT) or \
           self.physical_enable() or \
           self.physical_set_deactivated(0):
            return 1
        return 0

    def create_endorsement_key_pair(self):
        """ Create an endorsement key for the TPM 1.2 """

        req = b'\x00\xc1\x00\x00\x00\x36\x00\x00\x00\x78\x38\xf0\x30\x81\x07\x2b' \
        b'\x0c\xa9\x10\x98\x08\xc0\x4B\x05\x11\xc9\x50\x23\x52\xc4\x00\x00' \
        b'\x00\x01\x00\x03\x00\x02\x00\x00\x00\x0c\x00\x00\x08\x00\x00\x00' \
        b'\x00\x02\x00\x00\x00\x00'

        rsp, ret = self.transfer(req, "TPM_CreateEndorsementKeyPair")
        if ret != 0:
            return b'', 1

        length = struct.unpack(">I", rsp[34:38])[0]
        if length != 256:
            logerr(self.logfile, "Offset to EK Public key is wrong.\n")
            return b'', 1

        pubek = struct.unpack("256s", rsp[38:38+256])[0]

        return pubek, 0

    def oiap(self):
        """ Create an OIAP session """

        fmt = ">HII"
        req = struct.pack(fmt,
                          TPM_TAG_RQU_COMMAND, struct.calcsize(fmt), TPM_ORD_OIAP)

        rsp, ret = self.transfer(req, "TPM_OIAP")
        if ret != 0:
            return b'', 0, 1

        authhandle = struct.unpack(">I", rsp[10:14])[0]
        nonce_even = struct.unpack("20s", rsp[14:34])[0]

        return nonce_even, authhandle, 0

    def take_ownership(self, ownerpass_digest, srkpass_digest, pubek):
        """ Run TPM_TakeOwernship """

        exponent = int('10001', 16)
        modulus = int(pubek.hex(), 16)
        pubekkey = RSAPublicNumbers(exponent, modulus).public_key(backend=default_backend())

        oaep = padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label="TCPA".encode()
        )
        enc_owner_auth = pubekkey.encrypt(ownerpass_digest, oaep)
        enc_srk_auth = pubekkey.encrypt(srkpass_digest, oaep)

        nonce_even, auth_handle, ret = self.oiap()
        if ret != 0:
            return 1

        tpm_rsa_key_parms = struct.pack(">III",
                                        2048, # keyLength
                                        2, # numPrimes
                                        0) # exponentSize
        tpm_key_parms = struct.pack(">I HH I%ds" % (len(tpm_rsa_key_parms)),
                                    TPM_ALG_RSA, # algorithmId
                                    TPM_ES_RSAESOAEP_SHA1_MGF1, # encScheme
                                    TPM_SS_NONE, # sigScheme
                                    len(tpm_rsa_key_parms), tpm_rsa_key_parms)
        tpm_key12 = struct.pack(">HH HIB %ds I I I" %
                                (len(tpm_key_parms)),
                                TPM_TAG_KEY12, 0,
                                TPM_KEY_STORAGE, # keyUsage
                                0, # keyFlags
                                TPM_AUTH_ALWAYS, # authDataUsage
                                tpm_key_parms,
                                0,
                                0,
                                0)
        fmt_auth = ">I20sB20s"
        fmt = ">HII H I256s I256s %ds" % len(tpm_key12)
        nonce_odd = os.urandom(20)
        req = struct.pack(fmt,
                          TPM_TAG_RQU_AUTH1_COMMAND,
                          struct.calcsize(fmt) + struct.calcsize(fmt_auth),
                          TPM_ORD_TAKE_OWNERSHIP,
                          TPM_PID_OWNER,
                          len(enc_owner_auth), enc_owner_auth,
                          len(enc_srk_auth), enc_srk_auth,
                          tpm_key12)
        # req needs authhandle, nonceodd & ownerAuth appended
        shainput = struct.unpack("%ds" % (len(req) - 6), req[6:len(req)])[0]
        in_param_digest = sha1(shainput)

        continue_auth_session = 0
        in_auth_setup_params = struct.pack(">20s20sB", nonce_even, nonce_odd, continue_auth_session)
        macinput = struct.pack(">20s %ds" % len(in_auth_setup_params),
                               in_param_digest, in_auth_setup_params)
        myhmac = hmac.HMAC(ownerpass_digest, hashes.SHA1(), backend=default_backend())
        myhmac.update(macinput)
        owner_auth = myhmac.finalize()

        req += struct.pack(fmt_auth, auth_handle, nonce_odd, continue_auth_session, owner_auth)

        _, ret = self.transfer(req, "TPM_TakeOwnership")
        return ret

    def ownerclear(self, ownerpass_digest):
        """ clear TPM ownership """

        nonce_even, auth_handle, ret = self.oiap()
        if ret != 0:
            return 1

        nonce_odd = os.urandom(20)

        fmt_auth = ">I20sB20s"
        fmt = ">H II"
        req = struct.pack(fmt,
                          TPM_TAG_RQU_AUTH1_COMMAND,
                          struct.calcsize(fmt) + struct.calcsize(fmt_auth), TPM_ORD_OWNER_CLEAR)

        shainput = struct.unpack("%ds" % (len(req) - 6), req[6:len(req)])[0]
        in_param_digest = sha1(shainput)

        continue_auth_session = 0
        in_auth_setup_params = struct.pack(">20s20sB", nonce_even, nonce_odd, continue_auth_session)
        macinput = struct.pack(">20s %ds" % len(in_auth_setup_params),
                               in_param_digest, in_auth_setup_params)
        myhmac = hmac.HMAC(ownerpass_digest, hashes.SHA1(), backend=default_backend())
        myhmac.update(macinput)
        owner_auth = myhmac.finalize()

        req += struct.pack(fmt_auth, auth_handle, nonce_odd, continue_auth_session, owner_auth)

        _, ret = self.transfer(req, "TPM_ClearOwner")
        return ret

    def nv_define_space(self, nvindex, nvindexattrs, size):
        """ Define an nvindex with the given permissions and size """

        pcr_info_short = struct.pack(">HBBB B 20s",
                                     3, 0, 0, 0,
                                     TPM_LOC_ALL,
                                     ('\x00' * 20).encode())

        fmt = ">HI %ds%ds HI BBBI" % (len(pcr_info_short), len(pcr_info_short))
        nv_data_public = struct.pack(fmt,
                                     TPM_TAG_NV_DATA_PUBLIC, nvindex,
                                     pcr_info_short, pcr_info_short,
                                     TPM_TAG_NV_ATTRIBUTES, nvindexattrs,
                                     0, 0, 0, size)
        fmt = ">HII %ds 20s" % len(nv_data_public)
        req = struct.pack(fmt,
                          TPM_TAG_RQU_COMMAND, struct.calcsize(fmt), TPM_ORD_NV_DEFINE_SPACE,
                          nv_data_public,
                          ('\x00' * 20).encode())
        _, ret = self.transfer(req, "TPM_NV_DefineSpace")
        return ret

    def nv_write_value(self, nvindex, data):
        """ Write data to an index """

        fmt = ">HII III%ds" % len(data)
        req = struct.pack(fmt,
                          TPM_TAG_RQU_COMMAND, struct.calcsize(fmt), TPM_ORD_NV_WRITE_VALUE,
                          nvindex, 0, len(data), data)
        _, ret = self.transfer(req, "TPM_NV_WriteValue")
        return ret

    def write_ek_cert_nvram(self, data):
        """ Write the EK Certificate into NVRAM """

        nvindex = TPM_NV_INDEX_EKCERT|TPM_NV_INDEX_D_BIT
        ret = self.nv_define_space(nvindex, TPM_NV_PER_OWNERREAD|TPM_NV_PER_OWNERWRITE, len(data))
        if ret != 0:
            return 1

        ret = self.nv_write_value(nvindex, data)
        if ret != 0:
            return 1

        return 0

    def write_platform_cert_nvram(self, data):
        """ Write the Platform Certificate into NVRAM """

        nvindex = TPM_NV_INDEX_PLATFORMCERT|TPM_NV_INDEX_D_BIT
        ret = self.nv_define_space(nvindex, TPM_NV_PER_OWNERREAD|TPM_NV_PER_OWNERWRITE, len(data))
        if ret != 0:
            return 1

        return self.nv_write_value(nvindex, data)

    def nv_lock(self):
        """ Lock the NVRAM """

        return self.nv_define_space(TPM_NV_INDEX_LOCK, 0, 0)
