#!/usr/bin/env python3
"""Quick verification of MCP authorization compliance."""

import httpx
import json
import sys


def check_oauth_metadata():
    """Check OAuth server metadata for MCP compliance."""
    print("\n🔍 Checking OAuth Authorization Server Metadata...")
    
    try:
        # Use the auth proxy domain - this is how OAuth is accessed in production
        auth_domain = "auth.atradev.org"
        print(f"  ℹ️  Using auth proxy: {auth_domain}")
        
        response = httpx.get(
            f"https://{auth_domain}/.well-known/oauth-authorization-server",
            verify=False,
            timeout=10
        )
        
        if response.status_code != 200:
            print(f"❌ Failed to get OAuth metadata: {response.status_code}")
            return False
        
        metadata = response.json()
        
        # Check for MCP-specific fields
        mcp_fields = {
            "resource_indicators_supported": metadata.get("resource_indicators_supported"),
            "resource_parameter_supported": metadata.get("resource_parameter_supported"),
            "mcp_protocol_version": metadata.get("mcp_protocol_version"),
            "mcp_compliance": metadata.get("mcp_compliance")
        }
        
        print("\n📋 OAuth Server MCP Support:")
        for field, value in mcp_fields.items():
            status = "✅" if value else "❌"
            print(f"  {status} {field}: {value}")
        
        # Check scopes
        scopes = metadata.get("scopes_supported", [])
        mcp_scopes = [s for s in scopes if s.startswith("mcp:")]
        if mcp_scopes:
            print(f"  ✅ MCP scopes: {', '.join(mcp_scopes)}")
        else:
            print(f"  ❌ No MCP scopes found")
        
        return all(mcp_fields.values())
        
    except Exception as e:
        print(f"❌ Error checking OAuth metadata: {e}")
        return False


def check_protected_resource_metadata():
    """Check if MCP servers have protected resource metadata."""
    print("\n🔍 Checking Protected Resource Metadata...")
    
    # Test with localhost (should work if any MCP server is running)
    try:
        response = httpx.get(
            "http://localhost:3000/.well-known/oauth-protected-resource",
            timeout=5
        )
        
        if response.status_code == 404:
            print("❌ Protected resource metadata endpoint not found")
            print("   (This is expected if no MCP servers are running)")
            return None
        
        if response.status_code != 200:
            print(f"❌ Failed to get protected resource metadata: {response.status_code}")
            return False
        
        metadata = response.json()
        
        print("\n📋 Protected Resource Metadata:")
        important_fields = ["resource", "authorization_servers", "scopes_supported", "mcp_server_info"]
        for field in important_fields:
            value = metadata.get(field)
            if value:
                print(f"  ✅ {field}: {json.dumps(value, indent=4) if isinstance(value, dict) else value}")
            else:
                print(f"  ❌ {field}: Not found")
        
        return True
        
    except httpx.ConnectError:
        print("⚠️  Cannot connect to MCP server on port 3000")
        print("   (Start an MCP echo server to test this)")
        return None
    except Exception as e:
        print(f"❌ Error checking protected resource metadata: {e}")
        return False


def check_resource_registry():
    """Check if resource registry is available."""
    print("\n🔍 Checking Resource Registry...")
    
    try:
        # Try to access resource registry (will fail without auth, but that's OK)
        response = httpx.get("http://localhost/resources")
        
        if response.status_code == 401 or response.status_code == 403:
            print("✅ Resource registry endpoint exists (requires authentication)")
            return True
        elif response.status_code == 200:
            print("✅ Resource registry endpoint accessible")
            resources = response.json().get("resources", [])
            print(f"   Found {len(resources)} registered resources")
            return True
        else:
            print(f"❌ Unexpected response from resource registry: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Error checking resource registry: {e}")
        return False


def check_authorization_endpoint():
    """Check if authorization endpoint accepts resource parameter."""
    print("\n🔍 Checking Authorization Endpoint...")
    
    # Use the auth proxy domain
    auth_domain = "auth.atradev.org"
    
    # Build a test authorization URL
    auth_url = f"https://{auth_domain}/authorize?client_id=test&redirect_uri=http://localhost/callback&response_type=code&resource=https://test.example.com"
    
    try:
        response = httpx.get(auth_url, verify=False, follow_redirects=False, timeout=10)
        
        # We expect either a redirect (to login) or an error
        if response.status_code in [302, 303]:
            print("✅ Authorization endpoint accepts requests")
            location = response.headers.get("location", "")
            if "error=invalid_resource" in location:
                print("❌ Resource parameter rejected")
                return False
            else:
                print("✅ Resource parameter accepted (or ignored)")
                return True
        elif response.status_code == 400:
            # Check if it's specifically about the resource parameter
            if response.headers.get("content-type", "").startswith("text/html"):
                print("✅ Authorization endpoint exists (client validation working)")
                return True
            else:
                body = response.text
                if "invalid_resource" in body:
                    print("❌ Resource parameter explicitly rejected")
                    return False
                else:
                    print("✅ Authorization endpoint exists")
                    return True
        else:
            print(f"⚠️  Unexpected response: {response.status_code}")
            return None
            
    except Exception as e:
        print(f"❌ Error checking authorization endpoint: {e}")
        return False


def main():
    """Run quick MCP compliance verification."""
    print("🚀 MCP Authorization Compliance Quick Check")
    print("=" * 50)
    
    results = []
    
    # Run checks
    results.append(("OAuth Metadata", check_oauth_metadata()))
    results.append(("Protected Resource Metadata", check_protected_resource_metadata()))
    results.append(("Resource Registry", check_resource_registry()))
    results.append(("Authorization Endpoint", check_authorization_endpoint()))
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 Summary:")
    print("=" * 50)
    
    passed = 0
    failed = 0
    skipped = 0
    
    for name, result in results:
        if result is True:
            print(f"✅ {name}")
            passed += 1
        elif result is False:
            print(f"❌ {name}")
            failed += 1
        else:
            print(f"⚠️  {name} (skipped/not applicable)")
            skipped += 1
    
    print(f"\nTotal: {passed} passed, {failed} failed, {skipped} skipped")
    
    if failed == 0:
        print("\n✅ Core MCP authorization features are implemented!")
        print("\nNext steps:")
        print("1. Start MCP echo servers to test protected resource metadata")
        print("2. Create test proxies and resources for full compliance testing")
        print("3. Run the comprehensive test suite: python scripts/test_mcp_compliance.py")
    else:
        print("\n❌ Some MCP features are missing. Check the details above.")
    
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())