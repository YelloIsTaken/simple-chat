"""Entry point for running from source (`python chat.py ...`) and for PyInstaller."""

import sys

from simplechat.cli import main

if __name__ == "__main__":
    sys.exit(main())
