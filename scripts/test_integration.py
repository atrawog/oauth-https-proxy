#!/usr/bin/env python
"""Script to run integration tests against deployed services."""

import subprocess
import sys
import time
import os
import json


def check_service_health(service_name):
    """Check if a specific service is healthy."""
    result = subprocess.run(
        ["docker-compose", "ps", "--format", "json", service_name],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        return False
    
    try:
        # Parse the JSON output
        services = json.loads(result.stdout)
        if isinstance(services, list) and services:
            service = services[0]
            return service.get("Health", "").lower() == "healthy"
    except:
        # Fallback to string parsing if JSON fails
        return "healthy" in result.stdout.lower()
    
    return False


def wait_for_services():
    """Wait for Docker services to be healthy."""
    print("Waiting for services to be ready...")
    
    services_to_check = ["redis", "acme-certmanager"]
    max_retries = 60
    
    for i in range(max_retries):
        all_healthy = True
        
        for service in services_to_check:
            if not check_service_health(service):
                all_healthy = False
                break
        
        if all_healthy:
            print("\nAll services are healthy!")
            
            # Additional wait for services to fully initialize
            print("Waiting for services to fully initialize...")
            time.sleep(5)
            return True
        
        if i < max_retries - 1:
            time.sleep(2)
            print(".", end="", flush=True)
    
    print("\nServices did not become healthy in time")
    
    # Show service status for debugging
    subprocess.run(["docker-compose", "ps"])
    subprocess.run(["docker-compose", "logs", "--tail=50"])
    
    return False


def run_tests():
    """Run integration tests."""
    # Ensure we're in the right directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(script_dir)
    os.chdir(project_dir)
    
    # Stop any existing services
    print("Stopping any existing services...")
    subprocess.run(["docker-compose", "down", "-v"])
    
    # Build services
    print("Building services...")
    result = subprocess.run(["docker-compose", "build"])
    if result.returncode != 0:
        print("Failed to build services")
        return 1
    
    # Start services
    print("Starting services...")
    subprocess.run(["docker-compose", "up", "-d"])
    
    if not wait_for_services():
        return 1
    
    # Set test environment - all config from .env
    test_env = os.environ.copy()
    # .env should already be loaded by docker-compose and just
    # No hardcoded values!
    test_env.update({
        "PYTHONPATH": project_dir
    })
    
    # Run tests
    print("\nRunning integration tests...")
    result = subprocess.run(
        ["pixi", "run", "pytest", "tests/", "-v", "--tb=short", "-m", "not slow"],
        env=test_env
    )
    
    # Show logs if tests failed
    if result.returncode != 0:
        print("\nTest failed! Showing service logs...")
        subprocess.run(["docker-compose", "logs", "--tail=100"])
    
    return result.returncode


def cleanup():
    """Clean up Docker services."""
    print("\nCleaning up...")
    subprocess.run(["docker-compose", "down", "-v"])


if __name__ == "__main__":
    try:
        exit_code = run_tests()
    finally:
        cleanup()
    
    sys.exit(exit_code)