#!/usr/bin/env python
# SentinelX Setup Script

from setuptools import setup, find_packages
import os

# Read the contents of README.md
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read the requirements from requirements.txt
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="sentinelx",
    version="0.1.0",
    author="SentinelX Team",
    author_email="info@sentinelx.io",
    description="Network security monitoring and visualization tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/sentinelx/sentinelx",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "sentinelx=src.sentinelx.__main__:main",
            "sentinelx-vis=src.visualization.__main__:main",
        ],
    },
    include_package_data=True,
)