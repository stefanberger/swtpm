#!/usr/bin/env python3

import os
import sys
import socket
import subprocess
import time
import struct

from array import array

def toString(arr):
    return ' '.join('{:02x}'.format(x) for x in arr)


def test_ReadPCR10(fd):
    send_data = bytearray(b"\x00\xC1\x00\x00\x00\x0C\x00\x00\x00\x99\x00\x01")
    exp_data = bytearray([0x00, 0xC4, 0x00, 0x00, 0x00, 0x0A,
                          0x00, 0x00, 0x00, 0x26])

    try:
        print("Sending data over ....")
        n = fd.send(send_data)
        print("Written %d bytes " % n)
    except socket.error as e:
        print("SocketError")
        fd.close()
        return False

    buf = fd.recv(1024)
    fd.close()
    if buf:
        if bytearray(buf) == exp_data:
            return True
        else:
            print("Unexpected reply:\n  actual: %s\n  expected: %s"
                  % (toString(buf), toString(exp_data)))
            return False
    else:
        print("Null reply from swtpm")
        return False


def test_SetDatafd():
    fd, _fd = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock_path = os.getenv('SOCK_PATH')
    cmd_set_data_fd = bytearray([0x00, 0x00, 0x00, 0x10])
    expected_res = bytearray([0x00, 0x00, 0x00, 0x00])
    try:
        fds = array("i")
        fds.append(_fd.fileno())
        ctrlfd = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        print("Connecting to server at : %s" % sock_path)
        ctrlfd.connect(sock_path)
        print("Sending data fd over ctrl fd...")
        if sys.version_info[0] < 3:
            sendmsg.send1msg(ctrlfd.fileno(), str(cmd_set_data_fd), 0,
                             [(socket.SOL_SOCKET,
                               sendmsg.SCM_RIGHTS,
                               struct.pack("i", _fd.fileno()))])
        else:
            ctrlfd.sendmsg([cmd_set_data_fd],
                           [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)])
    except socket.error as e:
        print("SocketError: " + str(e))
        ctrlfd.close()

    buf = ctrlfd.recv(4)
    print("Received bytes.. : %s" % buf)
    if buf:
        caps = bytearray(buf)
        if caps == expected_res:
            return test_ReadPCR10(fd)
        else:
            print("Unexpected reply for CMD_SET_DATA_FD: \n"
                  "  actual: %s\n  expected: %s"
                  % (toString(caps), toString(expected_res)))
            return False
    else:
        print("Null reply from swtpm")
        return False

if __name__ == "__main__":
    try:
        if not test_SetDatafd():
            res = 1
        else:
            res = 0
    except:
        print("__Exception: ", sys.exc_info())
        res = -1

    sys.exit(res)
