#!/usr/bin/python3 -u

# Copyright 2018 Ville Skyttä
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Regular expression match hasher."""

import functools
import hashlib
import hmac
from binascii import hexlify
from typing import Match, Pattern

# for hmac.digest only available in 3.7+
# mypy: no-warn-unused-ignores

__version__ = "0.9.2"
DEFAULT_ALGORITHM = "sha1"


class Hashpipe:
    """Hash pipe."""

    def __init__(
        self,
        pattern: Pattern[bytes],
        algorithm: str = DEFAULT_ALGORITHM,
        key: bytes = b"",
        prefix: bytes = b"",
    ) -> None:
        """Create new Hashpipe."""
        if hasattr(hmac, "digest"):
            # Optimize for CPython 3.7+: use hmac.digest with str digestmod
            self._digestname = algorithm
            self._digest = self._digest_hmac_digest
        else:
            # Try getattr for faster direct constructor access than .new
            self._digestmod = getattr(
                hashlib, algorithm, functools.partial(hashlib.new, algorithm)
            )
            self._digest = self._digest_hmac_new
        self.pattern = pattern
        self.key = key
        self.prefix = prefix

    def _digest_hmac_new(self, data: bytes) -> bytes:
        return hmac.new(self.key, data, self._digestmod).digest()

    def _digest_hmac_digest(self, data: bytes) -> bytes:
        return hmac.digest(  # type: ignore[attr-defined,no-any-return] # 3.7+
            self.key, data, self._digestname
        )

    def hash_matches(self, data: bytes) -> bytes:
        """Hash matches.

        Replace the first groups of regular expression matches in given text
        with their HMAC hex digests surrounded by angle brackets.
        """

        def _replace(match: Match[bytes]) -> bytes:
            """Process a match."""
            if match.groups():
                # hash first group
                data = match.group(1)
                pre = match.string[match.start(0) : match.start(1)]
                post = match.string[match.end(1) : match.end(0)]
            else:
                # hash entire match
                data = match.group(0)
                pre = post = b""
            digest = self._digest(data)
            return pre + b"<" + self.prefix + hexlify(digest) + b">" + post

        return self.pattern.sub(_replace, data)


if __name__ == "__main__":
    from hashpipe.__main__ import main

    main()
