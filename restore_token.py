#!/usr/bin/env python3
import os
from pathlib import Path

env_path = Path('.env')
lines = []

with open(env_path, 'r') as f:
    for line in f:
        if line.startswith('OAUTH_TOKEN_EXPIRES_AT='):
            lines.append('OAUTH_TOKEN_EXPIRES_AT=1756044082.2841089\n')
        else:
            lines.append(line)

with open(env_path, 'w') as f:
    f.writelines(lines)

print("Token expiry restored.")
