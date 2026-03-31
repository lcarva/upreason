import nox

nox.options.default_venv_backend = "uv"
nox.options.reuse_existing_virtualenvs = True

PYTHON_VERSIONS = ["3.12", "3.13", "3.14"]


@nox.session(python=PYTHON_VERSIONS)
def tests(session: nox.Session) -> None:
    """Run the full test suite."""
    session.install("-e", ".")
    session.install("pytest", "pytest-asyncio")
    session.run("pytest", *session.posargs)


@nox.session(python=PYTHON_VERSIONS)
def unit(session: nox.Session) -> None:
    """Run unit tests only."""
    session.install("-e", ".")
    session.install("pytest", "pytest-asyncio")
    session.run("pytest", "tests/unit", *session.posargs)


@nox.session(python=PYTHON_VERSIONS)
def integration(session: nox.Session) -> None:
    """Run integration tests only."""
    session.install("-e", ".")
    session.install("pytest", "pytest-asyncio")
    session.run("pytest", "tests/integration", *session.posargs)


@nox.session(python="3.13")
def lint(session: nox.Session) -> None:
    """Run linting with ruff."""
    session.install("ruff")
    session.run("ruff", "check", "src", "tests", *session.posargs)
    session.run("ruff", "format", "--check", "src", "tests", *session.posargs)


@nox.session(python="3.13")
def format(session: nox.Session) -> None:
    """Auto-format and fix lint issues."""
    session.install("ruff")
    session.run("ruff", "check", "--fix", "src", "tests", *session.posargs)
    session.run("ruff", "format", "src", "tests", *session.posargs)
