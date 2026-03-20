# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) TrueNAS, 2026

from setuptools import setup, Extension

truenas_auparse_ext = Extension(
    'truenas_auparse',
    sources=[
        'src/cext/truenas_auparse.c',
        'src/cext/auparse_event.c',
        'src/cext/auparse_feed.c',
    ],
    include_dirs=['src/cext'],
    libraries=['auparse', 'audit'],
)

setup(
    ext_modules=[truenas_auparse_ext],
    packages=['truenas_auparse', '_truenas_audit_scripts', 'truenas_audit_parse'],
    package_dir={
        'truenas_auparse': 'stubs',
        '_truenas_audit_scripts': 'scripts',
        'truenas_audit_parse': 'src/truenas_audit_parse',
    },
    package_data={
        'truenas_auparse': ['*.pyi', 'py.typed'],
        'truenas_audit_parse': ['py.typed'],
    },
)
