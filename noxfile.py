"""nox config for hashpipe."""

import nox


@nox.session(
    python=["%s3.%s" % (py, x) for py in ("", "pypy") for x in range(3, 13)]
    + ["pyston3"]
)
def test(session: nox.Session) -> None:
    """Run tests."""
    session.install("-r", "requirements-test.txt")
    session.run(
        *"python3 -X dev -bb -m pytest --cov=hashpipe".split() + session.posargs
    )
