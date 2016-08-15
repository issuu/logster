#!/usr/bin/env python

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

from Cython.Build import cythonize

setup(
    name='logster',
    version='0.0.1',
    description='Parse log files, generate metrics for Graphite and Ganglia',
    author='Etsy',
    url='https://github.com/etsy/logster',
    packages=[
        'logster',
        'logster/parsers',
        'logster/tailers'
    ],
    install_requires = [
        #'pygtail>=0.5.1',
        'ua-parser'
    ],
    ext_modules = cythonize(["tailers/logtailtailer.pyx", "tailers/pygtailtailer.pyx", "logster/logster_helper.pyx", "logster/parsers/HaProxyLogster.pyx"]),
    zip_safe=False,
    scripts=[
        'bin/logster'
    ],
    license='GPL3'
)
