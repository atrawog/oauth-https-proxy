#!/usr/bin/env python
"""Analyze logs to find Let's Encrypt request patterns."""

import subprocess
import re
from datetime import datetime

def main():
    # Get recent logs
    result = subprocess.run(
        ["docker", "logs", "oauth-https-proxy-api-1", "--since=5m"],
        capture_output=True,
        text=True
    )
    
    logs = result.stdout + result.stderr
    
    # Find all Let's Encrypt requests
    le_requests = []
    for line in logs.split('\n'):
        if "Let's Encrypt validation server" in line:
            # Extract timestamp from previous lines
            timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})', line)
            if not timestamp_match:
                # Look for timestamp in surrounding lines
                continue
            le_requests.append(line)
    
    # Find all authorization status changes
    auth_changes = []
    for line in logs.split('\n'):
        if "Authorization status:" in line:
            auth_changes.append(line)
    
    # Find challenge endpoint hits
    challenge_hits = []
    current_request = {}
    for line in logs.split('\n'):
        if "INCOMING REQUEST:" in line:
            current_request = {}
        elif "Path: /.well-known/acme-challenge/" in line:
            current_request['path'] = line
        elif "Client: Address" in line and current_request:
            current_request['client'] = line
        elif "Response Status:" in line and 'path' in current_request:
            current_request['status'] = line
            challenge_hits.append(current_request)
            current_request = {}
    
    print("=== ANALYSIS ===")
    print(f"\nFound {len(le_requests)} Let's Encrypt requests")
    print(f"Found {len(auth_changes)} authorization status changes")
    print(f"Found {len(challenge_hits)} challenge endpoint hits")
    
    print("\n=== CHALLENGE REQUESTS ===")
    for hit in challenge_hits:
        print(f"\n{hit.get('path', 'Unknown path')}")
        print(f"{hit.get('client', 'Unknown client')}")
        print(f"{hit.get('status', 'Unknown status')}")
    
    print("\n=== AUTHORIZATION TIMELINE ===")
    for change in auth_changes[-10:]:  # Last 10 changes
        print(change)

if __name__ == "__main__":
    main()