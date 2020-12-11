# hashpipe -- Regular expression match hasher

[![Python versions](https://img.shields.io/pypi/pyversions/hashpipe.svg)](https://pypi.org/project/hashpipe/)
[![PyPI version](https://badge.fury.io/py/hashpipe.svg)](https://badge.fury.io/py/hashpipe)
[![CI status](https://github.com/scop/hashpipe/workflows/CI/badge.svg)](https://github.com/scop/hashpipe/actions?query=workflow%3ACI)
[![Test coverage](https://codecov.io/gh/scop/hashpipe/branch/master/graph/badge.svg)](https://codecov.io/gh/scop/hashpipe)

hashpipe is a command line tool and a Python library for hashing
regular expression matches in input data.

Matches are hashed with their HMAC hex digests using a configurable
key and digest algorithm, surrounded by angle brackets, and optionally
prefixed with a configurable string within the brackets.

What gets hashed for each match depends on whether the regular
expression contains capturing groups. If it doesn't, the entire match
content is hashed. If it does, only content of the first capturing
group is.

The command line tool operates as a pipe, reading standard input and
outputting to standard output. It has optional shell completion support
using [argcomplete](https://pypi.org/project/argcomplete/).

## Examples

### Python

```python3
import os
import re

from hashpipe import Hashpipe

hashpipe = Hashpipe(
    pattern=re.compile(br"\bfox|dog\b"),
    algorithm="sha256",
    key=os.urandom(128),
)
hashed = hashpipe.hash_matches(b"The quick brown fox jumps over the lazy dog.")
# hashed now contains something like:
# b'The quick brown <00adbe4c178e322e582e4e45c4989a204655c4b3960c0be298bc763e29dc738b> '
# b'jumps over the lazy <ee68954fe2f64931fb63756a5ecd1e22b90984c6b29fe3340b159dcff1f98244>.'
```

### Shell

```
$ hashpipe --key=deadbeef --algorithm=md5 --prefix='{md5}' '^[^:]+' < /etc/passwd
<{md5}31572cc0e16e31b00f9888a18310ceab>:x:0:0:root:/root:/bin/bash
<{md5}1b4fa176c601aadfa5453b9074ba32d8>:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```
