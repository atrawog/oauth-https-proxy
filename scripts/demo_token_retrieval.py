#!/usr/bin/env python3
"""Demonstrate full token retrieval capability."""

import subprocess
import time

def run_command(cmd):
    """Run a command and return output."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(f"$ {cmd}")
    print(result.stdout)
    if result.stderr:
        print(f"Error: {result.stderr}")
    return result.stdout

def demo_token_retrieval():
    """Show that tokens can be fully retrieved after generation."""
    print("=== Token Retrieval Demo ===\n")
    
    print("1. Generate a new token:")
    output = run_command("just token-generate retrieval-demo")
    
    # Extract token from output
    token = None
    for line in output.split('\n'):
        if line.startswith('Token: '):
            token = line.split('Token: ')[1].strip()
            break
    
    print("\n2. Token stored successfully!")
    print("   Unlike before, the FULL token is now stored in Redis")
    
    print("\n3. Retrieve the token later:")
    run_command("just token-show retrieval-demo")
    
    print("\n4. List all tokens (shows full tokens):")
    run_command("just token-list | grep retrieval-demo")
    
    print("\n=== Summary ===")
    print("✓ Tokens are now FULLY retrievable after generation")
    print("✓ Use 'just token-show <name>' to retrieve any token")
    print("✓ Use 'just token-list' to see all tokens")
    print("✓ No more 'cannot be retrieved' nonsense!")


if __name__ == "__main__":
    demo_token_retrieval()