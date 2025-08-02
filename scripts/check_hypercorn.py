#!/usr/bin/env python3
"""Check available Hypercorn modules."""
import sys
import importlib

modules_to_check = [
    'hypercorn',
    'hypercorn.protocol',
    'hypercorn.protocol.h11',
    'hypercorn.protocol.h2',
    'hypercorn.protocol.http',
    'hypercorn.protocol.ws',
    'hypercorn.asyncio',
    'hypercorn.config',
    'hypercorn.typing',
]

for module_name in modules_to_check:
    try:
        module = importlib.import_module(module_name)
        print(f"✓ {module_name}")
        # List attributes if it's a protocol module
        if 'protocol' in module_name and hasattr(module, '__all__'):
            print(f"  Exports: {', '.join(module.__all__)}")
        elif 'protocol' in module_name:
            attrs = [a for a in dir(module) if not a.startswith('_')]
            if attrs:
                print(f"  Available: {', '.join(attrs[:5])}...")
    except ImportError as e:
        print(f"✗ {module_name}: {e}")