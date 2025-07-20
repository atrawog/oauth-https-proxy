#!/usr/bin/env python3
"""Test ACME registration directly."""

import os
import sys
import json
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acme import messages
from acme_certmanager.storage import RedisStorage
from acme_certmanager.acme_client import ACMEClient

# Test email parsing
email = "atrawog@gmail.com"
print(f"Testing ACME registration with email: {email}")
print(f"Email domain: {email.split('@')[1]}")
print(f"Email TLD: {email.split('.')[-1]}")

# Test contact URI format
contact_uri = f"mailto:{email}"
print(f"\nContact URI: {contact_uri}")

# Try to create a NewRegistration object
try:
    # Test the old way (that was failing)
    print("\nTesting messages.NewRegistration.from_data():")
    try:
        new_reg = messages.NewRegistration.from_data(
            email=email,
            terms_of_service_agreed=True
        )
        print(f"  Success! Contact: {new_reg.contact}")
    except Exception as e:
        print(f"  Failed: {e}")
    
    # Test the new way
    print("\nTesting messages.NewRegistration() with contact tuple:")
    new_reg = messages.NewRegistration(
        contact=(contact_uri,),
        terms_of_service_agreed=True
    )
    print(f"  Success! Contact: {new_reg.contact}")
    print(f"  Contact type: {type(new_reg.contact)}")
    print(f"  ToS agreed: {new_reg.terms_of_service_agreed}")
    
    # Check JSON serialization
    print("\nJSON representation:")
    print(json.dumps(new_reg.to_json(), indent=2))
    
except Exception as e:
    print(f"Error creating registration: {e}")
    import traceback
    traceback.print_exc()

# Check if there's something wrong with the provider URL parsing
print("\n\nTesting provider URL parsing:")
provider_url = "https://acme-v02.api.letsencrypt.org/directory"
parsed = urlparse(provider_url)
provider_name = parsed.hostname.replace('.', '_')
print(f"Provider URL: {provider_url}")
print(f"Parsed hostname: {parsed.hostname}")
print(f"Provider name: {provider_name}")