#!/usr/bin/env python3

"""Hashpipe setup."""

import setuptools  # type: ignore[import]


def get_version() -> str:
    """Extract version number."""
    fname = "hashpipe/__init__.py"
    with open(fname, encoding="utf-8") as file_:
        for line in file_:
            if line.startswith("__version__"):
                return line.split("=")[-1].strip("\"'\r\n ")
    raise Exception("No __version__ in %s!" % fname)


if __name__ == "__main__":
    setuptools.setup(version=get_version())
