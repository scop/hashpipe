"""hashpipe tests."""

import re
from binascii import hexlify
from io import BytesIO
from typing import Dict, NamedTuple, Pattern
from unittest.mock import patch

import pytest

from hashpipe import Hashpipe, _available_algorithms, main


def _format_hash(hash_: bytes, prefix: bytes = b"") -> bytes:
    return b"<" + prefix + hash_ + b">"


def test_ref_nongrouping() -> None:
    """Test reference hashes, with non-grouping regexes."""
    TestCase = NamedTuple(
        "TestCase",
        [
            ("key", bytes),
            ("data", bytes),
            ("pattern", Pattern[bytes]),
            ("hashes", Dict[str, bytes]),
        ],
    )

    cases = (
        # https://en.wikipedia.org/wiki/HMAC#Examples
        TestCase(
            key=b"",
            data=b"",
            pattern=re.compile(b".*"),
            hashes=dict(
                md5=b"74e6f7298a9c2d168935f58c001bad88",
                sha1=b"fbdb1d1b18aa6c08324b7d64b71fb76370690e1d",
                sha256=(
                    b"b613679a0814d9ec772f95d778c35fc5"
                    b"ff1697c493715653c6c712144292c5ad"
                ),
            ),
        ),
        TestCase(
            key=b"key",
            data=b"The quick brown fox jumps over the lazy dog",
            pattern=re.compile(b".+"),
            hashes=dict(
                md5=b"80070713463e7749b90c2dc24911e275",
                sha1=b"de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9",
                sha256=(
                    b"f7bc83f430538424b13298e6aa6fb143"
                    b"ef4d59a14946175997479dbc2d1a3cd8"
                ),
            ),
        ),
        # https://tools.ietf.org/html/rfc2202
        TestCase(
            key=bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
            data=b"Hi There",
            pattern=re.compile(b".+"),
            hashes=dict(md5=b"9294727a3638bb1c13f48ef8158bfc9d"),
        ),
        TestCase(
            key=bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
            data=b"Hi There",
            pattern=re.compile(b".+"),
            hashes=dict(sha1=b"b617318655057264e28bc0b6fb378c8ef146be00"),
        ),
        TestCase(
            key=b"Jefe",
            data=b"what do ya want for nothing?",
            pattern=re.compile(b".+"),
            hashes=dict(
                md5=b"750c783e6ab0b503eaa86e310a5db738",
                sha1=b"effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
            ),
        ),
        TestCase(
            key=bytes.fromhex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            data=bytes.fromhex("dd" * 50),
            pattern=re.compile(b".+"),
            hashes=dict(md5=b"56be34521d144c88dbb8c733f0e8b3f6"),
        ),
        TestCase(
            key=bytes.fromhex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            data=bytes.fromhex("dd" * 50),
            pattern=re.compile(b".+"),
            hashes=dict(sha1=b"125d7342b9ac11cd91a39af48aa17b4f63f175d3"),
        ),
        TestCase(
            key=bytes.fromhex("0102030405060708090a0b0c0d0e0f10111213141516171819"),
            data=bytes.fromhex("cd" * 50),
            pattern=re.compile(b".+"),
            hashes=dict(
                md5=b"697eaf0aca3a3aea3a75164746ffaa79",
                sha1=b"4c9007f4026250c6bc8414f9bf50c86c2d7235da",
            ),
        ),
        TestCase(
            key=bytes.fromhex("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"),
            data=b"Test With Truncation",
            pattern=re.compile(b".+"),
            hashes=dict(md5=b"56461ef2342edc00f9bab995690efd4c"),
        ),
        TestCase(
            key=bytes.fromhex("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"),
            data=b"Test With Truncation",
            pattern=re.compile(b".+"),
            hashes=dict(sha1=b"4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"),
        ),
        TestCase(
            key=bytes.fromhex("aa" * 80),
            data=b"Test Using Larger Than Block-Size Key - Hash Key First",
            pattern=re.compile(b".+"),
            hashes=dict(
                md5=b"6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd",
                sha1=b"aa4ae5e15272d00e95705637ce8a3b55ed402112",
            ),
        ),
        TestCase(
            key=bytes.fromhex("aa" * 80),
            data=(
                b"Test Using Larger Than Block-Size Key "
                b"and Larger Than One Block-Size Data"
            ),
            pattern=re.compile(b".+"),
            hashes=dict(
                md5=b"6f630fad67cda0ee1fb1f562db3aa53e",
                sha1=b"e8e99d0f45237d786d6bbaa7965c7808bbff1a91",
            ),
        ),
    )

    for case in cases:
        for algorithm, hash_ in case.hashes.items():

            expected = _format_hash(hash_)

            hashpipe = Hashpipe(pattern=case.pattern, algorithm=algorithm, key=case.key)
            assert (  # noqa: S101 # nosec: B101
                hashpipe.hash_matches(case.data) == expected
            )

            outbuf = BytesIO()
            with patch(
                "sys.argv",
                [
                    __file__,
                    "-k",
                    hexlify(case.key).decode(),
                    "-a",
                    algorithm,
                    case.pattern.pattern.decode(),
                ],
            ):
                main(in_=(case.data,), out=outbuf)
            assert outbuf.getvalue() == expected  # noqa: S101 # nosec: B101


def test_grouping() -> None:
    """Test grouping replacements."""
    TestCase = NamedTuple(
        "TestCase",
        [
            ("key", bytes),
            ("data", bytes),
            ("pattern", Pattern[bytes]),
            ("algorithm", str),
            ("result", bytes),
        ],
    )

    cases = (
        TestCase(
            key=bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
            data=b"Well, Hi There!",
            pattern=re.compile(rb"Well, (Hi There)"),
            algorithm="md5",
            result=(
                "Well, %s!" % _format_hash(b"9294727a3638bb1c13f48ef8158bfc9d").decode()
            ).encode(),
        ),
        TestCase(
            key=bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
            data=b"Well, Hi There!",
            pattern=re.compile(rb"(?P<name_ignored>Hi There)"),
            algorithm="md5",
            result=(
                "Well, %s!" % _format_hash(b"9294727a3638bb1c13f48ef8158bfc9d").decode()
            ).encode(),
        ),
        TestCase(
            key=bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
            data=b"Well, Hi There!",
            pattern=re.compile(rb"\b(Hi There)\b"),
            algorithm="sha1",
            result=(
                "Well, %s!"
                % _format_hash(b"b617318655057264e28bc0b6fb378c8ef146be00").decode()
            ).encode(),
        ),
    )

    for case in cases:

        hashpipe = Hashpipe(
            pattern=case.pattern, algorithm=case.algorithm, key=case.key
        )
        assert (  # noqa: S101 # nosec: B101
            hashpipe.hash_matches(case.data) == case.result
        )

        outbuf = BytesIO()
        with patch(
            "sys.argv",
            [
                __file__,
                "-k",
                hexlify(case.key).decode(),
                "-a",
                case.algorithm,
                case.pattern.pattern.decode(),
            ],
        ):
            main(in_=(case.data,), out=outbuf)
        assert outbuf.getvalue() == case.result  # noqa: S101 # nosec: B101


def test_prefixing() -> None:
    """Test prefixing."""
    for prefix in b"foo", b"foo:", b"":

        algorithm = "md5"
        data = b""
        key = b""
        expected = _format_hash(b"74e6f7298a9c2d168935f58c001bad88", prefix=prefix)

        hashpipe = Hashpipe(
            pattern=re.compile(b".*"), algorithm=algorithm, key=key, prefix=prefix
        )
        assert hashpipe.hash_matches(data) == expected  # noqa: S101 # nosec: B101

        outbuf = BytesIO()
        with patch(
            "sys.argv",
            [
                __file__,
                "-k",
                hexlify(key).decode(),
                "-a",
                algorithm,
                "-p",
                prefix.decode(),
                ".*",
            ],
        ):
            main(in_=(b"",), out=outbuf)
        assert outbuf.getvalue() == expected  # noqa: S101 # nosec: B101


def test_invalid_cli_regex() -> None:
    """Test invalid regex from CLI."""
    with pytest.raises(SystemExit, match="^[^0]*$"):
        with patch("sys.argv", [__file__, "***"]):
            main()


def test_available_algorithms() -> None:
    """Test finding available algorithms."""
    avail = _available_algorithms()
    # Some found?
    assert avail  # noqa: S101 # nosec: B101
    # Ones containing "with" have been excluded?
    assert not any("with" in x for x in avail)  # noqa: S101 # nosec: B101
    # Non-lowercase variants have been excluded?
    assert not any(  # noqa: S101 # nosec: B101
        x.lower() in avail for x in avail if x != x.lower()
    )
