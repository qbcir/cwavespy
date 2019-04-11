#!/usr/bin/env python

import os
import sys

from setuptools import setup, find_packages

os.chdir(os.path.dirname(sys.argv[0]) or ".")

setup(
    name="cwavespy",
    version="0.1",
    description="CFFI Python binding for waves-c library",
    url="https://github.com/qbcir/cwavespy",
    author="Alexander Golenev",
    author_email="alex.golenev@gmail.com",
    classifiers=[
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: Implementation :: PyPy"
    ],
    packages=find_packages(),
    install_requires=["cffi>=1.0.0"],
    setup_requires=["cffi>=1.0.0"],
    cffi_modules=[
        "./cwavespy/build_cext.py:ffi"
    ],
)