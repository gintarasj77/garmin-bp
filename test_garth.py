#!/usr/bin/env python3
"""Test script to understand garth library structure"""
import sys
sys.path.insert(0, '.')

try:
    import garth
    print("Garth imported successfully")
    print(f"Garth version: {garth.__version__ if hasattr(garth, '__version__') else 'unknown'}")
    print(f"\nGarth module contents:")
    for attr in dir(garth):
        if not attr.startswith('_'):
            print(f"  - {attr}")
    
    print(f"\nGarth.client type: {type(garth.client)}")
    print(f"Garth.client attributes:")
    for attr in dir(garth.client):
        if not attr.startswith('_'):
            try:
                val = getattr(garth.client, attr)
                print(f"  - {attr}: {type(val).__name__}")
            except:
                print(f"  - {attr}: (error accessing)")
    
    print(f"\nAll attributes (including private):")
    for attr in dir(garth.client):
        try:
            val = getattr(garth.client, attr)
            if isinstance(val, type):
                print(f"  - {attr}: {val}")
            elif 'session' in attr.lower() or 'http' in attr.lower() or 'request' in attr.lower():
                print(f"  - {attr}: {type(val).__name__}")
        except:
            pass

except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
