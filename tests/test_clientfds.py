#!/usr/bin/python

import os, sys
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

    if swtpm_exe == None or tpmpath == None or pidfile == None:
        print("Missing test environment \n swtpm_exe=%s,\n tpmpath=%s\n pidfile=%s" %
                (swtpm_exe, tpmpath, pidfile));
        return False

    cmd = swtpm_exe + " socket --fd=" + str(_fd.fileno())
    cmd += " --ctrl type=unixio,clientfd=" + str(_ctrlfd.fileno())
    cmd += " --pid file=" + pidfile + " --tpmstate dir=" + tpmpath
    print("Running child cmd: %s" % cmd)
    try:
        child = subprocess.Popen(cmd.split())
    except OSError as err:
        print("OS error: %d" % err.errno)
        return False

    print("Child PID: %d" % child.pid)

    if wait_for_pidfile(pidfile, 3) == False:
        print("waitpid timeout");
        child.kill()
        child = None
        return False

    return True

def test_get_caps():
    global ctrlfd

    # test get capabilities
    # CMD_GET_CAPABILITY = 0x00 00 00 01
    cmd_get_caps = bytearray([0x00,0x00,0x00,0x01])
    expected_caps = bytearray([0x00,0x00,0x00,0x00,0x00,0x00,0x0f,0xff])

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
            print("Unexpected reply for CMD_GET_CAPABILITY: \n  actual: %s\n  expected: %s"
                   % (toString(caps), toString(expected_caps)))
            return False
    else:
        print("Null reply from swtpm")
        return False

if __name__ == "__main__":
    try:
        if spawn_swtpm() == False or test_get_caps() == False:
            res = 1
        else:
            res = 0
    except:
        print "__Exception: ", sys.exc_info()
        res = -1

    if child: child.terminate()

    sys.exit(res)
