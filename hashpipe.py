#!/usr/bin/python3 -u

"""Regular expression match hasher utility."""

import argparse
import hashlib
import hmac
import re
import sys


DEFAULT_ALGORITHM = "sha1"
__REGEX_TYPE = type(re.compile(b"."))


if hasattr(hmac, "digest"):
    # Faster (for our purposes) hmac.digest is available in Python 3.7+
    def hmac_hexdigest(key: bytes, msg: bytes, digest: str) -> str:
        """Create HMAC hex digest."""
        return hmac.digest(key, msg, digest).hex()  # pylint: disable=no-member
else:
    def hmac_hexdigest(key: bytes, msg: bytes, digest: str) -> str:
        """Create HMAC hex digest."""
        return hmac.new(key, msg, digest).hexdigest()


def hash_matches(
        regex: __REGEX_TYPE, data: bytes, key: bytes = b"",
        algorithm: str = DEFAULT_ALGORITHM, prefix: bytes = b"") -> bytes:
    """
    Hash matches.

    Replace the first groups of regular expression matches in given text with
    their HMAC hex digests surrounded by angle brackets, using the given
    algorithm, optionally prefixing them with the given prefix.
    """
    def _replace(match):
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

        return b"%s<%s%s>%s" % (
            pre,
            prefix,
            hmac_hexdigest(key, data, algorithm).encode(),
            post)

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
    avail = []
    for algo in hashlib.algorithms_available:
        if "with" in algo.lower():
            continue  # skip apparently redundant ones
        if algo.upper() != algo and algo.lower() not in avail:
            avail.append(algo)
    parser.add_argument("-a", "--algorithm", type=str,
                        default=DEFAULT_ALGORITHM,
                        help="Digest algorithm to use, one of: %s" %
                        ", ".join(sorted(avail, key=lambda x: x.lower())))

    def regex(arg: str) -> __REGEX_TYPE:
        """Convert argument to compiled regex."""
        try:
            return re.compile(str.encode(arg))
        except BaseException:
            raise argparse.ArgumentError
    parser.add_argument("regex", type=regex, metavar="REGEX",
                        help="Regular expression to match")

    args = parser.parse_args()

    for line in sys.stdin.buffer:
        sys.stdout.buffer.write(
            hash_matches(algorithm=args.algorithm, regex=args.regex,
                         data=line, key=args.key, prefix=args.prefix))


if __name__ == "__main__":
    main()
