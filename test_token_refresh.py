#!/usr/bin/env python3
"""Test token refresh behavior by temporarily expiring the token."""

import os
import time
from pathlib import Path

# Backup current token expiry
env_path = Path('.env')
lines = []
original_expires_at = None

with open(env_path, 'r') as f:
    for line in f:
        if line.startswith('OAUTH_TOKEN_EXPIRES_AT='):
            original_expires_at = line.strip()
            # Set expiry to 1 second ago to simulate expired token
            lines.append(f'OAUTH_TOKEN_EXPIRES_AT={time.time() - 1}\n')
            print(f"Original: {original_expires_at}")
            print(f"Temporary: OAUTH_TOKEN_EXPIRES_AT={time.time() - 1}")
        else:
            lines.append(line)

# Write back with expired time
with open(env_path, 'w') as f:
    f.writelines(lines)

print("\nToken temporarily expired. Run: pixi run proxy-client oauth login")
print("Then restore with: python restore_token.py")

# Create restore script
restore_script = """#!/usr/bin/env python3
import os
from pathlib import Path

env_path = Path('.env')
lines = []

with open(env_path, 'r') as f:
    for line in f:
        if line.startswith('OAUTH_TOKEN_EXPIRES_AT='):
            lines.append('{original}\\n')
        else:
            lines.append(line)

with open(env_path, 'w') as f:
    f.writelines(lines)

print("Token expiry restored.")
""".replace('{original}', original_expires_at if original_expires_at else 'OAUTH_TOKEN_EXPIRES_AT=0')

with open('restore_token.py', 'w') as f:
    f.write(restore_script)

print("Restore script created: restore_token.py")