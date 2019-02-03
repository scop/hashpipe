#!/usr/bin/python3 -u

"""Regular expression match hasher utility."""

import argparse
import functools
import hashlib
import hmac
import re
import sys
from typing import List  # noqa: F401 pylint: disable=unused-import
from typing import Match, Pattern


__version__ = "0.9.0"
DEFAULT_ALGORITHM = "sha1"


class Hashpipe:  # pylint: disable=too-few-public-methods
    """Hash pipe."""

    def __init__(self, algorithm: str = DEFAULT_ALGORITHM) -> None:
        """Create new Hashpipe using given digest algorithm."""
        if hasattr(hmac, "digest"):
            # Optimize for CPython 3.7+: use hmac.digest with str digestmod
            self._digestmod = algorithm
            self.hexdigest = self._hexdigest_hmac_digest
        else:
            # Try getattr for faster direct constructor access than .new
            self._digestmod = getattr(
                hashlib, algorithm, functools.partial(hashlib.new, algorithm))
            self.hexdigest = self._hexdigest_hmac_new

    def _hexdigest_hmac_new(self, key: bytes, msg: bytes) -> str:
        return hmac.new(key, msg, self._digestmod).hexdigest()

    def _hexdigest_hmac_digest(self, key: bytes, msg: bytes) -> str:
        return hmac.digest(  # 3.7+ pylint: disable=no-member
            key, msg, self._digestmod).hex()

    def hash_matches(self, regex: Pattern[bytes], data: bytes,
                     key: bytes = b"", prefix: bytes = b"") -> bytes:
        """
        Hash matches.

        Replace the first groups of regular expression matches in given text
        with their HMAC hex digests surrounded by angle brackets, using the
        given algorithm, optionally prefixing them with the given prefix.
        """
        def _replace(match: Match[bytes]) -> bytes:
            """Process a match."""
            if match.groups():
                # hash first group
                data = match.group(1)
                pre = match.string[match.start(0):match.start(1)]
                post = match.string[match.end(1):match.end(0)]
            else:
                # hash entire match
                data = match.group(0)
                pre = post = b""
            digest = self.hexdigest(key, data).encode()
            return pre + b"<" + prefix + digest + b">" + post

        return regex.sub(_replace, data)


def main() -> None:
    """Run main entry point."""
    parser = argparse.ArgumentParser(
        description="Read stdin line by line, hash regex matches, and " +
        "output the result to stdout")

    parser.add_argument("-k", "--key", type=str.encode, default=b"",
                        help="HMAC key, default is empty")

    parser.add_argument("-p", "--prefix", type=str.encode, default=b"",
                        help="Prefix to add in replacements")

    # weed out uppercase variants where lowercase exists from available
    avail = []  # type: List[str]
    for algo in hashlib.algorithms_available:
        if "with" in algo.lower():
            continue  # skip apparently redundant ones
        if algo.upper() != algo and algo.lower() not in avail:
            avail.append(algo)
    parser.add_argument("-a", "--algorithm", type=str,
                        default=DEFAULT_ALGORITHM,
                        help="Digest algorithm to use, one of: %s" %
                        ", ".join(sorted(avail, key=lambda x: x.lower())))

    def regex(arg: str) -> Pattern[bytes]:
        """Convert argument to compiled regex."""
        try:
            return re.compile(str.encode(arg))
        except BaseException:
            raise argparse.ArgumentError
    parser.add_argument("regex", type=regex, metavar="REGEX",
                        help="Regular expression to match")

    args = parser.parse_args()

    hashpipe = Hashpipe(args.algorithm)

    for line in sys.stdin.buffer:
        sys.stdout.buffer.write(
            hashpipe.hash_matches(
                regex=args.regex, data=line, key=args.key, prefix=args.prefix))


if __name__ == "__main__":
    main()
