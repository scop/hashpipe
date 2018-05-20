"""hashpipe tests."""

import re

from hashpipe import hash_matches


def _format_hash(hash_: bytes, prefix: bytes = b"") -> bytes:
    return b"<%s%s>" % (prefix, hash_)


def test_ref_nongrouping():
    """Test reference hashes, with non-grouping regexes."""
    cases = [
        # https://en.wikipedia.org/wiki/HMAC#Examples
        {
            "key": b"",
            "data": b"",
            "hashes": {
                "md5": b"74e6f7298a9c2d168935f58c001bad88",
                "sha1": b"fbdb1d1b18aa6c08324b7d64b71fb76370690e1d",
                "sha256": b"b613679a0814d9ec772f95d778c35fc5"
                          b"ff1697c493715653c6c712144292c5ad"
            },
        },
        {
            "key": b"key",
            "data": b"The quick brown fox jumps over the lazy dog",
            "hashes": {
                "md5": b"80070713463e7749b90c2dc24911e275",
                "sha1": b"de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9",
                "sha256": b"f7bc83f430538424b13298e6aa6fb143"
                          b"ef4d59a14946175997479dbc2d1a3cd8"
            },
        },

        # https://tools.ietf.org/html/rfc2202
        {
            "key": bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
            "data": b"Hi There",
            "hashes": {
                "md5": b"9294727a3638bb1c13f48ef8158bfc9d",
            },
        },
        {
            "key": bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
            "data": b"Hi There",
            "hashes": {
                "sha1": b"b617318655057264e28bc0b6fb378c8ef146be00",
            },
        },
        {
            "key": b"Jefe",
            "data": b"what do ya want for nothing?",
            "hashes": {
                "md5": b"750c783e6ab0b503eaa86e310a5db738",
                "sha1": b"effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
            },
        },
        {
            "key": bytes.fromhex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            "data": bytes.fromhex("dd" * 50),
            "hashes": {
                "md5": b"56be34521d144c88dbb8c733f0e8b3f6",
            },
        },
        {
            "key": bytes.fromhex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            "data": bytes.fromhex("dd" * 50),
            "hashes": {
                "sha1": b"125d7342b9ac11cd91a39af48aa17b4f63f175d3",
            },
        },
        {
            "key": bytes.fromhex(
                "0102030405060708090a0b0c0d0e0f10111213141516171819"),
            "data": bytes.fromhex("cd" * 50),
            "hashes": {
                "md5": b"697eaf0aca3a3aea3a75164746ffaa79",
                "sha1": b"4c9007f4026250c6bc8414f9bf50c86c2d7235da",
            },
        },
        {
            "key": bytes.fromhex("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"),
            "data": b"Test With Truncation",
            "hashes": {
                "md5": b"56461ef2342edc00f9bab995690efd4c",
            },
        },
        {
            "key": bytes.fromhex("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"),
            "data": b"Test With Truncation",
            "hashes": {
                "sha1": b"4c1a03424b55e07fe7f27be1d58bb9324a9a5a04",
            },
        },
        {
            "key": bytes.fromhex("aa" * 80),
            "data": b"Test Using Larger Than Block-Size Key - Hash Key First",
            "hashes": {
                "md5": b"6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd",
                "sha1": b"aa4ae5e15272d00e95705637ce8a3b55ed402112",
            }
        },
        {
            "key": bytes.fromhex("aa" * 80),
            "data": b"Test Using Larger Than Block-Size Key "
                    b"and Larger Than One Block-Size Data",
            "hashes": {
                "md5": b"6f630fad67cda0ee1fb1f562db3aa53e",
                "sha1": b"e8e99d0f45237d786d6bbaa7965c7808bbff1a91",
            },
        },
    ]
    regex = re.compile(b".*")

    for case in cases:
        for algorithm, hash_ in case["hashes"].items():
            assert hash_matches(
                algorithm=algorithm, regex=regex,
                data=case["data"], key=case["key"],
            ) == _format_hash(hash_)


def test_grouping():
    """Test grouping replacements."""
    cases = [
        {
            "key": bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
            "data": b"Well, Hi There!",
            "regex": re.compile(br"Well, (Hi There)"),
            "algorithm": "md5",
            "result": b"Well, %s!" % _format_hash(
                b"9294727a3638bb1c13f48ef8158bfc9d"),
        },
        {
            "key": bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
            "data": b"Well, Hi There!",
            "regex": re.compile(br"(?P<name_ignored>Hi There)"),
            "algorithm": "md5",
            "result": b"Well, %s!" % _format_hash(
                b"9294727a3638bb1c13f48ef8158bfc9d"),
        },
        {
            "key": bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
            "data": b"Well, Hi There!",
            "regex": re.compile(br"\b(Hi There)\b"),
            "algorithm": "sha1",
            "result": b"Well, %s!" % _format_hash(
                b"b617318655057264e28bc0b6fb378c8ef146be00"),
        },
    ]

    for case in cases:
        assert hash_matches(
            algorithm=case["algorithm"], regex=case["regex"],
            data=case["data"], key=case["key"],
        ) == case["result"]


def test_prefixing():
    """Test prefixing."""
    for prefix in b"foo", b"foo:", b"":
        assert hash_matches(
            algorithm="md5", regex=re.compile(b".*"),
            data=b"", key=b"", prefix=prefix,
        ) == _format_hash(b"74e6f7298a9c2d168935f58c001bad88", prefix=prefix)
