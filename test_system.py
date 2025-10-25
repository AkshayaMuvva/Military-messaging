"""
Test script to verify all components are working correctly
"""

import sys

def test_imports():
    """Test all imports"""
    print("Testing imports...")
    try:
        from quantum_crypto import QuantumResistantCrypto, AdaptiveEncryptionEngine
        from ai_metadata_detector import MetadataProtectionSystem
        from realtime_threat_assessment import RealTimeThreatSystem
        from crypto_engine import CryptoEngine
        from key_management import MilitaryKeyManager
        from memory_manager import SecureMemoryManager
        from tor_integration import TorIntegration
        from ai_intrusion_detection import AIIntrusionDetection
        from security_signals import security_system
        print("✅ All imports successful")
        return True
    except Exception as e:
        print(f"❌ Import failed: {e}")
        return False

def test_initialization():
    """Test component initialization"""
    print("\nTesting component initialization...")
    try:
        from quantum_crypto import QuantumResistantCrypto
        qc = QuantumResistantCrypto()
        print("✅ Quantum crypto initialized")
        
        from ai_metadata_detector import MetadataProtectionSystem
        mp = MetadataProtectionSystem()
        print("✅ Metadata protection initialized")
        
        from realtime_threat_assessment import RealTimeThreatSystem
        rt = RealTimeThreatSystem()
        print("✅ Real-time threat system initialized")
        
        return True
    except Exception as e:
        print(f"❌ Initialization failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_app():
    """Test Flask app"""
    print("\nTesting Flask application...")
    try:
        from app import app_instance
        print("✅ Flask app initialized")
        return True
    except Exception as e:
        print(f"❌ App initialization failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("AI-Powered Military-Grade Messaging System - Component Test")
    print("=" * 60)
    
    results = []
    results.append(("Imports", test_imports()))
    results.append(("Component Initialization", test_initialization()))
    results.append(("Flask Application", test_app()))
    
    print("\n" + "=" * 60)
    print("Test Results:")
    print("=" * 60)
    
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{name}: {status}")
    
    all_passed = all(result for _, result in results)
    
    print("=" * 60)
    if all_passed:
        print("🎉 All tests passed! Application is ready to run.")
        print("\nTo start the application, run:")
        print("  python app.py")
        sys.exit(0)
    else:
        print("❌ Some tests failed. Please check the errors above.")
        sys.exit(1)
