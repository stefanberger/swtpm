""" swtpm_logging.py
"""

# pylint: disable=W0703

import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


def append_to_file(filename, string):
    """" Append a string to a file """
    try:
        fobj = open(filename, 'a')
        fobj.write(string)
        fobj.close()
    except Exception:
        sys.stdout.write(string)


def logit(logfile, string):
    """ Print the given string to stdout or into the logfile """
    if len(logfile) == 0:
        sys.stdout.write(string)
    else:
        append_to_file(logfile, string)


def logerr(logfile, string):
    """ Print the given string to stderr or into the logfile """
    if len(logfile) == 0:
        sys.stdout.write(string)
    else:
        append_to_file(logfile, string)


def sha1(bytemsg):
    """ Calculate the SHA1 of the given messge """
    digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    digest.update(bytemsg)
    return digest.finalize()
