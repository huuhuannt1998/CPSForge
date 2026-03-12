"""
CPSForge main.py -- programmatic entry-point.

For CLI usage, use the ``cpsforge`` command (defined in pyproject.toml scripts).
This module enables: ``python -m cpsforge``
"""

from cpsforge.cli.app import app

if __name__ == "__main__":
    app()
