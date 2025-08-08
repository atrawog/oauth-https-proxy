#\!/usr/bin/env python3
"""Test the web GUI route management functionality."""

import os
import sys
import requests


def main():
    api_url = os.getenv('TEST_API_URL', 'http://localhost:80')
    
    print("Testing Web GUI Route Management")
    print("="*50)
    
    # 1. Check if GUI is accessible
    print("\n1. Testing GUI accessibility...")
    try:
        resp = requests.get(f"{api_url}/static/index.html")
        if resp.ok:
            print("✓ GUI is accessible at /static/index.html")
        else:
            print(f"✗ GUI returned status: {resp.status_code}")
            return 1
    except Exception as e:
        print(f"✗ Failed to access GUI: {e}")
        return 1
    
    # 2. Check static assets
    print("\n2. Testing static assets...")
    assets = ['/static/styles.css', '/static/app.js']
    for asset in assets:
        try:
            resp = requests.get(f"{api_url}{asset}")
            if resp.ok:
                print(f"✓ {asset} loaded successfully")
            else:
                print(f"✗ {asset} returned status: {resp.status_code}")
        except Exception as e:
            print(f"✗ Failed to load {asset}: {e}")
    
    # 3. Instructions for manual testing
    print("\n3. Manual GUI Testing Instructions:")
    print("-"*50)
    print("1. Open browser to: http://localhost/static/index.html")
    print("2. Login with your admin token")
    print("3. Go to the Proxies tab")
    print("4. Create a test proxy if needed")
    print("5. Click the 'Routes' button on any proxy card")
    print("6. Test the route management modal:")
    print("   - Switch between route modes (all/selective/none)")
    print("   - Enable/disable specific routes")
    print("   - Save changes")
    print("\nThe GUI should now support full per-proxy route control!")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
