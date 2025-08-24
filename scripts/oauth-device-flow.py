#!/usr/bin/env python3
"""OAuth Device Flow authentication script.

This script helps users authenticate via GitHub Device Flow and obtain OAuth tokens
for use with the OAuth HTTPS Proxy API.
"""

import os
import sys
import time
import json
import webbrowser
import httpx
from typing import Optional

def device_flow_auth(auth_domain: str = "localhost", open_browser: bool = True) -> Optional[str]:
    """Authenticate via GitHub Device Flow and return OAuth access token.
    
    Args:
        auth_domain: The OAuth server domain (default: localhost)
        open_browser: Whether to automatically open the browser (default: True)
    
    Returns:
        The OAuth access token if successful, None otherwise
    """
    base_url = f"http://{auth_domain}" if auth_domain == "localhost" else f"https://{auth_domain}"
    
    # Step 1: Get device code from our OAuth server
    print(f"Requesting device code from {base_url}/device/code...")
    
    try:
        with httpx.Client() as client:
            response = client.post(f"{base_url}/device/code")
            response.raise_for_status()
            device_data = response.json()
    except Exception as e:
        print(f"Error getting device code: {e}")
        return None
    
    device_code = device_data.get("device_code")
    user_code = device_data.get("user_code")
    verification_uri = device_data.get("verification_uri")
    expires_in = device_data.get("expires_in", 900)
    interval = device_data.get("interval", 5)
    
    if not all([device_code, user_code, verification_uri]):
        print("Invalid response from device/code endpoint")
        return None
    
    # Step 2: Show user the code and URL
    print(f"\n{'='*50}")
    print(f"Please visit: {verification_uri}")
    print(f"And enter code: {user_code}")
    print(f"{'='*50}\n")
    
    if open_browser:
        try:
            webbrowser.open(verification_uri)
            print("Browser opened automatically.")
        except:
            print("Could not open browser automatically.")
    
    print(f"Waiting for authorization (expires in {expires_in} seconds)...")
    
    # Step 3: Poll for token
    start_time = time.time()
    while time.time() - start_time < expires_in:
        time.sleep(interval)
        
        try:
            with httpx.Client() as client:
                response = client.post(
                    f"{base_url}/device/token",
                    data={
                        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                        "device_code": device_code,
                        "client_id": "device_flow_client"
                    }
                )
                
                if response.status_code == 200:
                    token_data = response.json()
                    access_token = token_data.get("access_token")
                    refresh_token = token_data.get("refresh_token")
                    scope = token_data.get("scope", "")
                    expires_in = token_data.get("expires_in", 1800)
                    
                    print(f"\n✓ Authentication successful!")
                    print(f"Scopes granted: {scope}")
                    print(f"Token expires in: {expires_in} seconds")
                    
                    # Save tokens to file for convenience
                    token_file = os.path.expanduser("~/.oauth-https-proxy-tokens.json")
                    with open(token_file, "w") as f:
                        json.dump({
                            "access_token": access_token,
                            "refresh_token": refresh_token,
                            "scope": scope,
                            "expires_at": time.time() + expires_in,
                            "auth_domain": auth_domain
                        }, f, indent=2)
                    print(f"Tokens saved to: {token_file}")
                    
                    # Also set environment variable
                    print(f"\nTo use this token in commands:")
                    print(f"export OAUTH_ACCESS_TOKEN={access_token}")
                    
                    return access_token
                
                elif response.status_code == 400:
                    error_data = response.json()
                    error = error_data.get("error")
                    
                    if error == "authorization_pending":
                        # User hasn't authorized yet, keep polling
                        print(".", end="", flush=True)
                    elif error == "slow_down":
                        # We're polling too fast
                        interval = error_data.get("interval", interval + 5)
                    elif error == "expired_token":
                        print("\n✗ Device code expired. Please try again.")
                        return None
                    elif error == "access_denied":
                        print("\n✗ Access denied by user.")
                        return None
                    else:
                        print(f"\n✗ Error: {error}")
                        return None
        except Exception as e:
            print(f"\nError polling for token: {e}")
            # Continue polling
    
    print("\n✗ Authentication timed out.")
    return None


def save_token_to_env(token: str) -> bool:
    """Save OAuth access token to .env file.
    
    Args:
        token: The OAuth access token to save
        
    Returns:
        True if successful, False otherwise
    """
    try:
        env_path = ".env"
        lines = []
        token_found = False
        
        # Read existing .env if it exists
        if os.path.exists(env_path):
            with open(env_path, 'r') as f:
                for line in f:
                    if line.startswith('OAUTH_ACCESS_TOKEN='):
                        lines.append(f'OAUTH_ACCESS_TOKEN={token}\n')
                        token_found = True
                    else:
                        lines.append(line)
        
        # Add token if not found
        if not token_found:
            # Ensure there's a newline before adding the token
            if lines and not lines[-1].endswith('\n'):
                lines.append('\n')
            lines.append('\n# OAuth Access Token (generated by oauth-login)\n')
            lines.append(f'OAUTH_ACCESS_TOKEN={token}\n')
        
        # Write back to .env
        with open(env_path, 'w') as f:
            f.writelines(lines)
        
        print(f"✓ Token saved to .env")
        return True
        
    except Exception as e:
        print(f"✗ Error saving token to .env: {e}")
        return False


def main():
    """Main entry point."""
    # No arguments needed - always localhost, never browser, always save
    print("Starting OAuth Device Flow authentication...")
    
    # Always use localhost, never open browser
    token = device_flow_auth("localhost", open_browser=False)
    
    if token:
        # Always save to .env
        save_token_to_env(token)
        print("\n✓ Authentication complete!")
        print("Token saved to .env")
        print("\nTo use the token:")
        print("  source .env")
        print("  OR")
        print("  just restart  (to reload environment)")
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()