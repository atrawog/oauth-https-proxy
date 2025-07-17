#!/usr/bin/env python3
"""Test route list with token."""

import sys
import os

print(f"Arguments received: {sys.argv}")
print(f"Number of args: {len(sys.argv)}")

if len(sys.argv) > 1:
    token = sys.argv[1]
    print(f"Token received: {token[:20]}..." if len(token) > 20 else f"Token received: {token}")
else:
    print("No token provided")

# Now run route_list with the token
from route_list import list_routes

if len(sys.argv) > 1:
    success = list_routes(sys.argv[1])
else:
    success = list_routes()
    
sys.exit(0 if success else 1)