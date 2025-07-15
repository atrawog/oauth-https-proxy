#!/usr/bin/env python3
"""Run certificate tests inside Docker container."""

import os
import sys
import subprocess
import time

def ensure_services_running():
    """Ensure Docker services are running."""
    print("🚀 Checking Docker services...")
    result = subprocess.run(["docker-compose", "ps"], capture_output=True, text=True)
    
    if "healthy" not in result.stdout:
        print("⚠️  Services not healthy. Starting services...")
        subprocess.run(["docker-compose", "up", "-d"])
        
        # Wait for services to be healthy
        max_wait = 60
        waited = 0
        while waited < max_wait:
            result = subprocess.run(["docker-compose", "ps"], capture_output=True, text=True)
            if "healthy" in result.stdout and "acme-certmanager" in result.stdout:
                print("✅ Services are healthy!")
                break
            print(".", end="", flush=True)
            time.sleep(2)
            waited += 2
        
        if waited >= max_wait:
            print("\n❌ Services did not become healthy in time")
            return False
    else:
        print("✅ Services are running")
    
    return True

def run_cert_command_tests():
    """Run the certificate command tests."""
    print("\n🧪 Running Certificate Command Tests\n")
    
    # Run the test inside the Docker container
    cmd = [
        "docker", "exec", 
        "mcp-http-proxy-acme-certmanager-1",
        "pixi", "run", "python", 
        "scripts/test_all_cert_commands.py"
    ]
    
    result = subprocess.run(cmd, capture_output=False, text=True)
    return result.returncode == 0

def main():
    """Main test runner."""
    if not ensure_services_running():
        print("❌ Failed to start services")
        return 1
    
    if not run_cert_command_tests():
        print("\n❌ Certificate command tests failed")
        return 1
    
    print("\n✅ All tests completed successfully!")
    return 0

if __name__ == "__main__":
    sys.exit(main())