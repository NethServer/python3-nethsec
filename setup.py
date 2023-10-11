#!/usr/bin/env python

from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name = 'nethsec',
    version = '0.0.8',
    author = 'Giacomo Sanchietti',
    author_email = 'giacomo.sanchietti@nethesis.it',
    description = 'Utilities for NethSecurity development',
    long_description = long_description,
    long_description_content_type = "text/markdown",
    url = "https://github.com/NethServer/python3-nethsec",
    license = "GPLv3",
    package_dir = {'': 'src'},
    packages = ['nethsec', 'nethsec.utils', 'nethsec.firewall', 'nethsec.mwan', 'nethsec.dpi'],
    #packages = find_packages(),
    requires = [ "pyuci" ],
    classifiers = [
        "Programming Language :: Python :: 3",
        "License v3 (LGPLv3)   License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)",
        "Operating System :: OS Independent",
    ],
    python_requires = '>=3.7',
)
