#!/usr/bin/env python
"""Script to run the ACME Certificate Manager server."""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acme_certmanager.server import run_server

if __name__ == "__main__":
    run_server()