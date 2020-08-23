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

import argparse
import functools
import hashlib
import hmac
import re
import sys
from binascii import hexlify
from typing import BinaryIO, Iterable, Match, Pattern, Set

# for hmac.digest only available in 3.7+
# mypy: no-warn-unused-ignores

__version__ = "0.9.2"
DEFAULT_ALGORITHM = "sha1"


class Hashpipe:  # pylint: disable=too-few-public-methods
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
            self._digestmod = algorithm
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
        return hmac.digest(  # type: ignore # pylint: disable=no-member # 3.7+
            self.key, data, self._digestmod
        )

    def hash_matches(self, data: bytes) -> bytes:
        """
        Hash matches.

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


def _available_algorithms() -> Set[str]:
    """
    Get available algorithms for use in suggestions.

    Algorithm names are case sensitive, but for many there is an all-lowercase
    spelling as well as some variants available. Keep only the all-lowercase
    one of those.
    """
    avail = set()
    pass2 = set()
    for algo in hashlib.algorithms_available:
        lalgo = algo.lower()
        if "with" in lalgo:
            continue  # skip apparently redundant ones
        if lalgo != algo:
            pass2.add(algo)
        else:
            avail.add(lalgo)
    for algo in pass2:
        if algo.lower() not in avail:
            avail.add(algo)
    return avail


def main(
    in_: Iterable[bytes] = sys.stdin.buffer, out: BinaryIO = sys.stdout.buffer
) -> None:
    """Run main entry point."""
    parser = argparse.ArgumentParser(
        description="Read stdin line by line, hash regex matches, and output "
        "the result to stdout"
    )

    parser.add_argument(
        "-V", "--version", action="version", version="hashpipe %s" % __version__
    )

    parser.add_argument(
        "-k",
        "--key",
        type=bytes.fromhex,
        default=b"",
        help="HMAC key hex encoded, default is empty",
    )

    parser.add_argument(
        "-p",
        "--prefix",
        type=str.encode,
        default=b"",
        help="Prefix to add in replacements",
    )

    algorithm_arg = parser.add_argument(
        "-a",
        "--algorithm",
        type=str,
        default=DEFAULT_ALGORITHM,
        help="Digest algorithm to use, one of: %s"
        % ", ".join(sorted(_available_algorithms(), key=lambda x: x.lower())),
    )
    # type ignore: argcomplete adds the "completer" attribute
    algorithm_arg.completer = lambda **_: _available_algorithms()  # type: ignore

    parser.add_argument(
        "-A",
        "--available-algorithms",
        action="store_true",
        help="List available algorithms and exit",
    )

    def pattern(arg: str) -> Pattern[bytes]:
        """Convert argument to compiled pattern."""
        try:
            return re.compile(str.encode(arg))
        except BaseException as ex:
            raise argparse.ArgumentError from ex

    if any(x in sys.argv for x in ("-h", "--help")) or not any(
        x in sys.argv for x in ("-A", "--available-algorithms")
    ):
        parser.add_argument(
            "regex", type=pattern, metavar="REGEX", help="Regular expression to match"
        )

    try:
        import argcomplete  # type: ignore # pylint: disable=import-outside-toplevel
    except ImportError:
        pass
    else:
        argcomplete.autocomplete(parser)

    args = parser.parse_args()

    if args.available_algorithms:
        for algo in sorted(_available_algorithms()):
            print(algo)
        return

    hashpipe = Hashpipe(
        pattern=args.regex, algorithm=args.algorithm, key=args.key, prefix=args.prefix
    )

    for line in in_:
        out.write(hashpipe.hash_matches(line))


if __name__ == "__main__":
    main()
