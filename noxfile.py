import nox

nox.options.default_venv_backend = "uv"
nox.options.reuse_existing_virtualenvs = True


@nox.session(python="3.12")
def tests(session: nox.Session) -> None:
    """Run the full test suite."""
    session.install("-e", ".")
    session.install("pytest")
    session.run("pytest", *session.posargs)


@nox.session(python="3.12")
def unit(session: nox.Session) -> None:
    """Run unit tests only."""
    session.install("-e", ".")
    session.install("pytest")
    session.run("pytest", "tests/unit", *session.posargs)


@nox.session(python="3.12")
def integration(session: nox.Session) -> None:
    """Run integration tests only."""
    session.install("-e", ".")
    session.install("pytest")
    session.run("pytest", "tests/integration", *session.posargs)
