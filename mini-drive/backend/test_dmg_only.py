#!/usr/bin/env python3
"""
Test script to verify only DMG files are accepted
"""

# Test data with magic bytes
test_files = {
    "pdf_sample": b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n",  # PDF sample (should be rejected)
    "dmg_macho_32_be": b"\xfe\xed\xfa\xce" + b"\x00" * 100,  # 32-bit big-endian Mach-O (should be accepted)
    "dmg_macho_64_be": b"\xfe\xed\xfa\xcf" + b"\x00" * 100,  # 64-bit big-endian Mach-O (should be accepted)
    "dmg_compressed": b"\x78\x9c" + b"\x00" * 100,  # gzip compressed DMG (should be accepted)
    "invalid_file": b"This is not a valid file type",  # Invalid (should be rejected)
    "empty_file": b"",  # Empty (should be rejected)
}

# Import the functions from main.py
import sys
import os
sys.path.append(os.path.dirname(__file__))

from main import detect_file_type_from_magic_bytes, validate_file_type

def test_dmg_only_validation():
    """Test that only DMG files are accepted"""
    print("🧪 Testing DMG-Only File Validation")
    print("=" * 50)
    
    for test_name, test_data in test_files.items():
        print(f"\nTesting: {test_name}")
        print(f"Data preview: {test_data[:20].hex() if test_data else 'empty'}")
        
        detected_type = detect_file_type_from_magic_bytes(test_data)
        is_valid, result = validate_file_type(test_data)
        
        print(f"Detected type: {detected_type}")
        print(f"Is valid: {is_valid}")
        print(f"Result: {result}")
        
        # Expected results - only DMG files should be valid
        expected_results = {
            "pdf_sample": (None, False),  # PDF should be rejected now
            "dmg_macho_32_be": ("dmg", True),
            "dmg_macho_64_be": ("dmg", True), 
            "dmg_compressed": ("dmg", True),
            "invalid_file": (None, False),
            "empty_file": (None, False),
        }
        
        expected_type, expected_valid = expected_results[test_name]
        
        if detected_type == expected_type and is_valid == expected_valid:
            print("✅ PASS")
        else:
            print(f"❌ FAIL - Expected: type={expected_type}, valid={expected_valid}")
    
    print("\n" + "=" * 50)
    print("🎯 DMG-Only Validation Test Complete")
    print("✅ Only DMG files should be accepted, all others rejected")

if __name__ == "__main__":
    test_dmg_only_validation()
