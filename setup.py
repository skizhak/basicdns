#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys


try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

if sys.argv[-1] == 'publish':
    os.system('python setup.py sdist upload')
    sys.exit()

readme = open('README.rst').read()
history = open('HISTORY.rst').read().replace('.. :changelog:', '')

setup(
    name='dns-server',
    version='0.1.0',
    description='This is a simple multiprocess supported DNS server with basic feature set',
    long_description=readme + '\n\n' + history,
    author='Sarin Kizhakkepurayil',
    author_email='sarinkp@hotmail.com',
    url='https://github.com/skizhak/dns-server',
    packages=[
        'dns-server',
    ],
    package_dir={'dns-server':
                 'dns-server'},
    include_package_data=True,
    install_requires=['dnspython>=1.11.1'
    ],
    license="BSD",
    zip_safe=False,
    keywords='dns-server',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        "Programming Language :: Python :: 2",
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
    ],
    test_suite='tests',
)
