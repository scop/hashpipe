#!/usr/bin/env python3

"""Hashpipe setup."""

from pathlib import Path

import setuptools  # type: ignore[import]


def get_version() -> str:
    """Extract version number."""
    fpath = Path("hashpipe", "__init__.py")
    with fpath.open(encoding="utf-8") as file_:
        for line in file_:
            if line.startswith("__version__"):
                return line.split("=")[-1].strip("\"'\r\n ")
    raise NameError("No __version__ in %s!" % fpath)


if __name__ == "__main__":
    setuptools.setup(version=get_version())
