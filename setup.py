# !/usr/bin/env python
# coding:utf-8
'''
PA Vandewoestyne
'''

import pathlib

from setuptools import setup, find_packages

HERE = pathlib.Path(__file__).parent
README = (HERE / "readme.md").read_text()

setup(
    name="DonPAPI",
    version="1.0.0",
    author="PA Vandewoestyne",
    description="Dumping DPAPI credentials remotely",
    long_description=README,
    long_description_content_type="text/markdown",
    include_package_data=True,
    url="https://github.com/login-securite/DonPAPI",
    zip_safe=True,
    license="MIT",
    packages=find_packages(),
    package_data={"DonPAPI": ["config/seatbelt_config.json", "res/*", "res/css/*"]},
    install_requires=[
        'impacket',
        'pyasn',
        'LnkParse3',
        'wheel',
    ],
    python_requires='>=3.6',
    classifiers=(
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ),
    entry_points={
        'console_scripts': [
            'DonPAPI = DonPAPI.DonPAPI:main',
        ],
    }
)
