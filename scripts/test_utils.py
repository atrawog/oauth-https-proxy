"""Common utilities for test scripts."""

import os
import subprocess
import json
import time
from typing import Dict, Optional


def run_command(cmd: str, timeout: int = 30) -> Dict:
    """Run a shell command and return result."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return {
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "success": result.returncode == 0
        }
    except subprocess.TimeoutExpired:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": "Command timed out",
            "success": False
        }
    except Exception as e:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": str(e),
            "success": False
        }


def get_admin_token() -> Optional[str]:
    """Get or create admin token."""
    # First check environment variable
    admin_token = os.getenv("ADMIN_TOKEN")
    if admin_token:
        return admin_token
    
    # If we're inside Docker, try to get token directly from Redis
    if os.getenv('RUNNING_IN_DOCKER'):
        try:
            # Import here to avoid circular dependency
            import sys
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            from src.storage import RedisStorage
            
            redis_url = os.getenv('REDIS_URL')
            if redis_url:
                storage = RedisStorage(redis_url)
                token_data = storage.redis_client.hgetall("token:admin")
                if token_data and 'token' in token_data:
                    return token_data['token']
        except Exception:
            pass
    
    # Otherwise try using just command
    result = run_command("just token-show admin")
    
    if result["success"] and "token:" in result["stdout"]:
        # Extract token from output
        lines = result["stdout"].strip().split("\n")
        for line in lines:
            if line.startswith("token:"):
                return line.split(":", 1)[1].strip()
    
    # Create admin token if it doesn't exist
    print("Creating admin token...")
    result = run_command("just token-generate admin admin@example.com")
    
    if result["success"]:
        # Extract token from creation output
        lines = result["stdout"].strip().split("\n")
        for line in lines:
            if line.startswith("Token:"):
                return line.split(":", 1)[1].strip()
    
    return None


def wait_for_service(url: str, timeout: int = 60) -> bool:
    """Wait for a service to be available."""
    import httpx
    
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            response = httpx.get(url, verify=False, timeout=5)
            if response.status_code < 500:
                return True
        except:
            pass
        time.sleep(2)
    
    return False


def get_api_api_url() -> str:
    """Get the correct API base URL based on environment.
    
    When running inside the Docker container, use the internal API port.
    When running outside, use the external API_URL.
    """
    # Check if we're running inside the container
    if os.path.exists('/.dockerenv') or os.getenv('RUNNING_IN_DOCKER'):
        return 'http://localhost:9000'
    
    # Otherwise use the configured API_URL
    return os.getenv('API_URL', 'http://localhost:80')


def cleanup_test_resources(prefix: str = "test"):
    """Clean up test resources."""
    # Clean up test proxies
    result = run_command(f"just proxy-list | grep {prefix}")
    if result["success"]:
        lines = result["stdout"].strip().split("\n")
        for line in lines:
            if prefix in line:
                hostname = line.split()[0]
                run_command(f"just proxy-delete {hostname} admin '' force")
    
    # Clean up test certificates
    result = run_command(f"just cert-list | grep {prefix}")
    if result["success"]:
        lines = result["stdout"].strip().split("\n")
        for line in lines:
            if prefix in line:
                cert_name = line.split()[0]
                run_command(f"just cert-delete {cert_name} admin force")
    
    # Clean up test tokens
    result = run_command(f"just token-list | grep {prefix}")
    if result["success"]:
        lines = result["stdout"].strip().split("\n")
        for line in lines:
            if prefix in line:
                token_name = line.split()[0]
                run_command(f"just token-delete {token_name}")