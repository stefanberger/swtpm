#!/usr/bin/env python3
""" setup.py

Install swtpm-localca
"""
import setuptools

from py_swtpm_localca.swtpm_localca_conf import SWTPM_VER_MAJOR, SWTPM_VER_MINOR, SWTPM_VER_MICRO

setuptools.setup(
    name="swtpm-localca",
    version="%d.%d.%d" % (SWTPM_VER_MAJOR, SWTPM_VER_MINOR, SWTPM_VER_MICRO),
    author="Stefan Berger et al.",
    author_email="stefanb@linux.ibm.com",
    url="https::/github.com/stefanberger/swptm",
    #packages=setuptools.find_packages(),
    description="A local CA for creating TPM 1.2 and TPM 2 EK and platform certificates",
    python_requires=">=3.2",
    packages=["py_swtpm_localca"],
    package_dir={
        "py_swtpm_localca": "py_swtpm_localca"
    },
    license="BSD3",
    install_requires=[
    ],
)
