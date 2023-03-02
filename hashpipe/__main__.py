"""Hashpipe entry point.

Running with Python's `-u` flag or `PYTHONUNBUFFERED=1` in the environment recommended.
"""

import argparse
import hashlib
import re
import sys
from typing import BinaryIO, Iterable, Pattern, Set

from . import DEFAULT_ALGORITHM, Hashpipe, __version__


def _available_algorithms(**_: str) -> Set[str]:
    """Get available algorithms for use in suggestions.

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


def main(  # noqa: C901
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

    key_arg = parser.add_argument(
        "-k",
        "--key",
        type=bytes.fromhex,
        default=b"",
        help="HMAC key hex encoded, default is empty",
    )

    prefix_arg = parser.add_argument(
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
        except (TypeError, re.error) as err:
            raise argparse.ArgumentTypeError(err) from err

    regex_arg = None
    if any(x in sys.argv for x in ("-h", "--help")) or not any(
        x in sys.argv for x in ("-A", "--available-algorithms")
    ):
        regex_arg = parser.add_argument(
            "regex", type=pattern, metavar="REGEX", help="Regular expression to match"
        )

    try:
        import argcomplete  # type: ignore[import]
    except ImportError:
        pass
    else:

        def _no_completion(**_: str) -> Iterable[str]:
            return ()

        # type ignores: argcomplete adds the "completer" attribute
        algorithm_arg.completer = _available_algorithms  # type: ignore[attr-defined]
        key_arg.completer = _no_completion  # type: ignore[attr-defined]
        prefix_arg.completer = _no_completion  # type: ignore[attr-defined]
        if regex_arg:
            regex_arg.completer = _no_completion  # type: ignore[attr-defined]

        argcomplete.autocomplete(parser)

    args = parser.parse_args()

    if args.available_algorithms:
        for algo in sorted(_available_algorithms()):
            print(algo)  # noqa: T201
        return

    hashpipe = Hashpipe(
        pattern=args.regex, algorithm=args.algorithm, key=args.key, prefix=args.prefix
    )

    for line in in_:
        out.write(hashpipe.hash_matches(line))


if __name__ == "__main__":
    main()
