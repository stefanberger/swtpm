#!/usr/bin/env python3

import os
import sys
import socket
import subprocess
import time
import struct

child = None
fd = -1
ctrlfd = -1


def wait_for_pidfile(pidfile, timeout):
    while timeout != 0:
        if os.path.exists(pidfile):
            return True
        time.sleep(1)
        timeout -= 1
    return False


def spawn_swtpm():
    global child, fd, ctrlfd

    _fd, fd = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    _ctrlfd, ctrlfd = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)

    swtpm_exe = os.getenv('SWTPM_EXE')
    tpmpath = os.getenv('TPMDIR')
    pidfile = os.getenv('PID_FILE')

    if not swtpm_exe or not tpmpath or not pidfile:
        print("Missing test environment \n swtpm_exe=%s,\n"
              " tpmpath=%s\n pidfile=%s" %
              (swtpm_exe, tpmpath, pidfile))
        return False

    cmd = swtpm_exe + " socket --fd=" + str(_fd.fileno())
    cmd += " --ctrl type=unixio,clientfd=" + str(_ctrlfd.fileno())
    cmd += " --pid file=" + pidfile + " --tpmstate dir=" + tpmpath
    if os.getenv('SWTPM_TEST_SECCOMP_OPT'):
        cmd += " " + os.getenv('SWTPM_TEST_SECCOMP_OPT')
    print("Running child cmd: %s" % cmd)
    try:
        if sys.version_info[0] >= 3:
            child = subprocess.Popen(cmd.split(),
                                     pass_fds=[_fd.fileno(), _ctrlfd.fileno()])
        else:
            child = subprocess.Popen(cmd.split())
    except OSError as err:
        print("OS error: %d" % err.errno)
        return False

    print("Child PID: %d" % child.pid)

    if not wait_for_pidfile(pidfile, 3):
        print("waitpid timeout")
        child.kill()
        child = None
        return False

    return True


def test_get_caps():
    global ctrlfd

    # test get capabilities
    # CMD_GET_CAPABILITY = 0x00 00 00 01
    cmd_get_caps = bytearray([0x00, 0x00, 0x00, 0x01])
    expected_caps = bytearray([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0xff])

    def toString(arr):
        return ' '.join('{:02x}'.format(x) for x in arr)

    try:
        ctrlfd.sendall(cmd_get_caps)
    except SocketError as e:
        print("SocketError")
    buf = ctrlfd.recv(8)
    if buf:
        caps = bytearray(buf)
        if caps == expected_caps:
            return True
        else:
            print("Unexpected reply for CMD_GET_CAPABILITY: \n"
                  "  actual: %s\n  expected: %s"
                  % (toString(caps), toString(expected_caps)))
            return False
    else:
        print("Null reply from swtpm")
        return False

if __name__ == "__main__":
    try:
        if not spawn_swtpm() or not test_get_caps():
            res = 1
        else:
            res = 0
    except:
        print("__Exception: ", sys.exc_info())
        res = -1

    if child:
        child.terminate()

    sys.exit(res)
