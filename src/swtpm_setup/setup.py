#!/usr/bin/env python3
""" setup.py

Install swtpm_setup
"""
import setuptools

from py_swtpm_setup.swtpm_setup_conf import SWTPM_VER_MAJOR, SWTPM_VER_MINOR, SWTPM_VER_MICRO

setuptools.setup(
    name="swtpm_setup",
    version="%d.%d.%d" % (SWTPM_VER_MAJOR, SWTPM_VER_MINOR, SWTPM_VER_MICRO),
    author="Stefan Berger et al.",
    author_email="stefanb@linux.ibm.com",
    url="https::/github.com/stefanberger/swptm",
    #packages=setuptools.find_packages(),
    description="Swtpm tool for simulating the manufacturing of a TPM 1.2 or TPM 2",
    python_requires=">=3.2",
    packages=["py_swtpm_setup"],
    package_dir={
        "py_swtpm_setup": "py_swtpm_setup"
    },
    license="BSD3",
    install_requires=[
        "cryptography",
    ],
)
