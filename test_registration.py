"""Test registration flow"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from database import EncryptedDatabase
from key_management import MilitaryKeyManager
import secrets

print("🧪 Testing Registration Flow\n")

# Initialize components
print("1. Initializing database...")
db = EncryptedDatabase(encryption_key="test_key_123")

print("2. Initializing key manager...")
key_manager = MilitaryKeyManager("test_master_password")

print("\n3. Registering user...")
user_id = "alice_test"
alias = "Alice Test"

# Simulate what app.py does
user_data = key_manager.register_user(user_id, alias)

print(f"\n📊 User data returned from register_user:")
print(f"   Keys: {list(user_data.keys())}")
print(f"   User ID: {user_data.get('user_id')}")
print(f"   Alias: {user_data.get('alias')}")
print(f"   Fingerprint: {user_data.get('fingerprint')[:50]}...")
print(f"   Public keys: {list(user_data.get('public_keys', {}).keys())}")

print("\n4. Saving user to database...")
success = db.save_user(user_id=user_id, user_data=user_data)

if success:
    print("   ✅ User saved successfully!")
else:
    print("   ❌ Failed to save user!")
    sys.exit(1)

print("\n5. Retrieving user from database...")
retrieved_user = db.get_user(user_id)

if retrieved_user:
    print("   ✅ User retrieved successfully!")
    print(f"   Retrieved keys: {list(retrieved_user.keys())}")
    print(f"   Alias: {retrieved_user.get('alias')}")
    print(f"   Fingerprint: {retrieved_user.get('fingerprint')[:50]}...")
else:
    print("   ❌ Failed to retrieve user!")
    sys.exit(1)

print("\n✅ Registration flow test PASSED!")
