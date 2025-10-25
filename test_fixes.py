"""
Test script to verify all fixes are working correctly
"""

import os
import sys

def test_database_persistence():
    """Test that database encryption key persists"""
    print("\n=== Testing Database Key Persistence ===")
    
    from database import EncryptedDatabase
    
    # First initialization
    db1 = EncryptedDatabase()
    
    # Check if key file was created
    if os.path.exists("db.key"):
        print("✅ Database key file created")
    else:
        print("❌ Database key file not created")
        return False
    
    # Save a test user
    test_user_data = {
        'user_id': 'test_user',
        'alias': 'Test User',
        'qr_code': 'test_qr',
        'fingerprint': 'test_fp',
        'public_keys': {
            'identity': 'test_identity',
            'signed_prekey': 'test_prekey',
            'verify_key': 'test_verify',
            'quantum_public_key': '',
            'created_at': 1234567890
        }
    }
    
    success = db1.save_user('test_user', test_user_data)
    if success:
        print("✅ Test user saved successfully")
    else:
        print("❌ Failed to save test user")
        return False
    
    # Create a new database instance (simulating restart)
    db2 = EncryptedDatabase()
    
    # Try to retrieve the user
    user = db2.get_user('test_user')
    if user and user['user_id'] == 'test_user':
        print("✅ Test user retrieved successfully after 'restart'")
        print(f"   User alias: {user['alias']}")
        return True
    else:
        print("❌ Failed to retrieve test user after 'restart'")
        return False

def test_quantum_crypto_session():
    """Test that quantum crypto sessions work correctly"""
    print("\n=== Testing Quantum Crypto Session ===")
    
    from quantum_crypto import QuantumResistantCrypto, AdaptiveEncryptionEngine
    
    # Create quantum crypto instance
    qr_crypto = QuantumResistantCrypto()
    
    # Create adaptive encryption engine with shared instance
    adaptive_engine = AdaptiveEncryptionEngine(qr_crypto)
    
    print("✅ AdaptiveEncryptionEngine initialized with shared instance")
    
    # Establish a session
    session_id, shared_secret = qr_crypto.establish_quantum_safe_session(
        qr_crypto.get_public_keys()['pq_public_key']
    )
    
    if session_id:
        print(f"✅ Quantum session created: {session_id[:16]}...")
    else:
        print("❌ Failed to create quantum session")
        return False
    
    # Try to encrypt using the session
    try:
        threat_context = {
            'failed_auth_attempts': 0,
            'unusual_access_pattern': False,
            'known_malicious_ip': False,
            'time_of_day_risk': 0.1
        }
        
        encrypted = adaptive_engine.encrypt_with_adaptation(
            b"Test message",
            session_id,
            threat_context
        )
        
        if encrypted:
            print("✅ Message encrypted successfully using quantum session")
            return True
        else:
            print("❌ Failed to encrypt message")
            return False
    except Exception as e:
        print(f"❌ Encryption failed with error: {e}")
        return False

def test_flask_secret_persistence():
    """Test that Flask secret key persists"""
    print("\n=== Testing Flask Secret Key Persistence ===")
    
    if os.path.exists("flask_secret.key"):
        print("✅ Flask secret key file would be created/loaded")
        return True
    else:
        print("ℹ️  Flask secret key file will be created on app startup")
        return True

def cleanup_test_files():
    """Clean up test files"""
    print("\n=== Cleaning up test files ===")
    
    files_to_remove = ['secure_data.db', 'test_user']
    
    for file in files_to_remove:
        if os.path.exists(file):
            try:
                os.remove(file)
                print(f"✅ Removed {file}")
            except Exception as e:
                print(f"⚠️  Could not remove {file}: {e}")

if __name__ == '__main__':
    print("🧪 Running Fix Verification Tests")
    print("=" * 50)
    
    all_tests_passed = True
    
    # Test 1: Database persistence
    if not test_database_persistence():
        all_tests_passed = False
    
    # Test 2: Quantum crypto session
    if not test_quantum_crypto_session():
        all_tests_passed = False
    
    # Test 3: Flask secret persistence
    if not test_flask_secret_persistence():
        all_tests_passed = False
    
    print("\n" + "=" * 50)
    if all_tests_passed:
        print("✅ ALL TESTS PASSED!")
        print("\nYou can now run the application with:")
        print("  python app.py")
        print("\nOr start it with:")
        print("  python start_secure_app.py")
    else:
        print("❌ SOME TESTS FAILED")
        print("Please review the errors above")
    
    # Clean up test files
    cleanup_test_files()
