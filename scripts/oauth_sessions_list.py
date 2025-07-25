#!/usr/bin/env python3
"""List OAuth sessions."""

import os
import sys
import requests
from datetime import datetime
from tabulate import tabulate

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from test_utils import get_api_base_url, get_admin_token


def list_oauth_sessions():
    """List all active OAuth sessions."""
    base_url = get_api_base_url()
    if not base_url:
        print("Error: Unable to determine API base URL")
        return False
    
    # Get token
    token = get_admin_token()
    if not token:
        print("Error: Admin token not found")
        return False
    
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        response = requests.get(f"{base_url}/oauth/sessions", headers=headers, timeout=10)
        
        if response.status_code == 401:
            print("Error: Unauthorized - invalid or expired token")
            return False
        elif response.status_code == 404:
            print("Error: OAuth endpoints not available")
            return False
        
        response.raise_for_status()
        
        data = response.json()
        sessions = data.get("sessions", [])
        
        if not sessions:
            print("No active OAuth sessions")
            return True
        
        # Format for display
        table_data = []
        for session in sessions:
            created = session.get("created_at", "")
            if created:
                try:
                    created_dt = datetime.fromisoformat(created.replace('Z', '+00:00'))
                    created = created_dt.strftime("%Y-%m-%d %H:%M")
                except:
                    pass
            
            expires = session.get("expires_at", "")
            if expires:
                try:
                    expires_dt = datetime.fromisoformat(expires.replace('Z', '+00:00'))
                    expires = expires_dt.strftime("%Y-%m-%d %H:%M")
                except:
                    pass
            else:
                expires = "Never"
            
            user_info = session.get("user_info", {})
            username = user_info.get("username", "Unknown")
            email = user_info.get("email", "")
            
            table_data.append([
                session.get("session_id", "")[:8] + "...",  # Truncate session ID
                username,
                email,
                session.get("client_id", "")[:20] + "..." if len(session.get("client_id", "")) > 20 else session.get("client_id", ""),
                created,
                expires
            ])
        
        headers = ["Session ID", "Username", "Email", "Client ID", "Created", "Expires"]
        
        print(f"\n=== Active OAuth Sessions ({len(sessions)} total) ===\n")
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        
        # Show summary by client
        clients = {}
        for session in sessions:
            client_id = session.get("client_id", "Unknown")
            clients[client_id] = clients.get(client_id, 0) + 1
        
        if len(clients) > 1:
            print(f"\nSessions by client:")
            for client_id, count in sorted(clients.items(), key=lambda x: x[1], reverse=True):
                print(f"  {client_id}: {count} session(s)")
        
        return True
        
    except requests.exceptions.RequestException as e:
        print(f"Error: Failed to list OAuth sessions: {e}")
        return False


if __name__ == "__main__":
    success = list_oauth_sessions()
    sys.exit(0 if success else 1)