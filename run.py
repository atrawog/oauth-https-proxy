#!/usr/bin/env python3
"""CLI entry point for OAuth HTTPS Proxy.

This script is the main entry point for running the proxy server
in development or via Docker. It starts the full server with all
components including the dispatcher, workflow orchestrator, and API.

For production ASGI deployment, use src.app:app instead.
"""

import sys
import os

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

print("RUN.PY: Starting imports...", file=sys.stderr)
from src.main import main
print("RUN.PY: Import successful, calling main()...", file=sys.stderr)

if __name__ == "__main__":
    print("RUN.PY: __name__ == __main__, executing main()...", file=sys.stderr)
    main()
    print("RUN.PY: main() completed", file=sys.stderr)