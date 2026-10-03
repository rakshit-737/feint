"""Entry point for ``python -m feint`` (see :func:`feint.cli.main`)."""
import sys

from .cli import main

sys.exit(main())
