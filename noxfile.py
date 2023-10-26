"""nox config for hashpipe."""

import nox


@nox.session(
    python=["{}3.{}".format(py, x) for py in ("", "pypy") for x in range(5, 14)]
    + ["pyston3"]
)
def test(session: nox.Session) -> None:
    """Run tests."""
    session.install(".", "-r", "requirements-test.txt")
    session.run("hashpipe", "--version")
    session.run("python3", "-m", "hashpipe", "--version")
    session.run(
        *"python3 -X dev -bb -m pytest --cov=hashpipe".split() + session.posargs
    )
