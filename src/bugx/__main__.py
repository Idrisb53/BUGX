"""Allow ``python -m bugx`` as an alias for ``python -m bugx.cli``."""

from bugx.cli import app

if __name__ == "__main__":
    app()
