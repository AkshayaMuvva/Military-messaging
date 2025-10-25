"""
Test ML-based Encryption Validator
Tests the Isolation Forest anomaly detection
"""

import time
import random
from ai_encryption_validator import get_validator

def simulate_normal_traffic(validator, user_id="user_001", count=150):
    """Simulate normal encryption/decryption events"""
    print(f"\n🔄 Simulating {count} normal encryption events...")
    
    for i in range(count):
        # Normal encryption: 50-200ms, 100-5000 bytes
        event_type = 'encrypt' if random.random() > 0.4 else 'decrypt'
        duration = random.uniform(50, 200)
        message_size = random.randint(100, 5000)
        
        validator.log_encryption_event(
            event_type=event_type,
            user_id=user_id,
            message_size=message_size,
            duration_ms=duration,
            success=True,
            ip_address="192.168.1.100",
            session_id="normal_session",
            metadata={'test': True}
        )
        
        if i % 50 == 0:
            print(f"  ✓ Logged {i} events...")
        
        time.sleep(0.01)  # Small delay
    
    print(f"  ✅ Completed {count} normal events")

def simulate_attack_patterns(validator, user_id="user_001"):
    """Simulate various attack patterns"""
    print("\n⚠️  Simulating attack patterns...")
    
    # 1. Rapid decryption attempts (brute force)
    print("  🔴 Attack 1: Rapid decryption attempts...")
    for i in range(15):
        validator.log_encryption_event(
            event_type='decrypt',
            user_id=user_id,
            message_size=500,
            duration_ms=random.uniform(10, 30),  # Very fast
            success=True,
            ip_address="192.168.1.100",
            session_id="attack_session",
            metadata={'attack': 'rapid_decrypt'}
        )
        time.sleep(0.05)
    
    # 2. Failed decryption attempts
    print("  🔴 Attack 2: Failed decryption attempts...")
    for i in range(8):
        validator.log_encryption_event(
            event_type='decrypt',
            user_id=user_id,
            message_size=random.randint(100, 1000),
            duration_ms=random.uniform(100, 300),
            success=False,  # Failed
            ip_address="192.168.1.100",
            session_id="attack_session",
            metadata={'attack': 'failed_decrypt'}
        )
        time.sleep(0.5)
    
    # 3. Timing attack pattern (very consistent timing)
    print("  🔴 Attack 3: Timing attack pattern...")
    for i in range(10):
        validator.log_encryption_event(
            event_type='decrypt',
            user_id=user_id,
            message_size=1000,
            duration_ms=100.0,  # Suspiciously consistent
            success=True,
            ip_address="192.168.1.100",
            session_id="attack_session",
            metadata={'attack': 'timing'}
        )
        time.sleep(0.1)
    
    # 4. Unusual message sizes (ML should detect this)
    print("  🔴 Attack 4: Unusual message sizes...")
    for i in range(10):
        validator.log_encryption_event(
            event_type='encrypt',
            user_id=user_id,
            message_size=50000,  # Much larger than normal
            duration_ms=random.uniform(500, 1000),
            success=True,
            ip_address="192.168.1.100",
            session_id="attack_session",
            metadata={'attack': 'large_messages'}
        )
        time.sleep(0.2)
    
    print("  ✅ Attack simulation completed")

def test_ml_validator():
    """Main test function"""
    print("=" * 70)
    print("🤖 Testing ML-Based Encryption Validator")
    print("=" * 70)
    
    validator = get_validator()
    
    # Step 1: Generate normal traffic
    simulate_normal_traffic(validator, count=150)
    
    print("\n⏳ Waiting 3 seconds for monitoring to process...")
    time.sleep(3)
    
    # Step 2: Check if ML model is trained
    report = validator.get_security_report()
    print(f"\n📊 Initial Report:")
    print(f"  • Events logged: {report['total_events_logged']}")
    print(f"  • ML Model trained: {report['ml_model_trained']}")
    print(f"  • Detection methods: {report['detection_methods']}")
    
    if not report['ml_model_trained']:
        print("\n🎓 Training ML model manually...")
        validator._train_ml_model()
        time.sleep(1)
    
    # Step 3: Simulate attacks
    simulate_attack_patterns(validator)
    
    print("\n⏳ Waiting 5 seconds for ML detection...")
    time.sleep(5)
    
    # Step 4: Get final report
    final_report = validator.get_security_report()
    
    print("\n" + "=" * 70)
    print("📊 FINAL SECURITY REPORT")
    print("=" * 70)
    print(f"Total Events Logged: {final_report['total_events_logged']}")
    print(f"Total Anomalies (24h): {final_report['total_anomalies_24h']}")
    print(f"Recent Anomalies (1h): {final_report['recent_anomalies_1h']}")
    print(f"\nSeverity Breakdown:")
    for severity, count in final_report['severity_breakdown'].items():
        print(f"  • {severity.upper()}: {count}")
    
    print(f"\nThreat Indicators:")
    for threat_type, count in final_report['threat_indicators'].items():
        print(f"  • {threat_type}: {count}")
    
    print(f"\nML Model Status: {final_report['ml_model_status']}")
    print(f"Detection Methods: {', '.join(final_report['detection_methods'])}")
    
    # Step 5: Check user risk score
    risk_score, risk_level = validator.get_user_risk_score("user_001")
    print(f"\n🎯 User Risk Assessment:")
    print(f"  • Risk Score: {risk_score:.2f}/100")
    print(f"  • Risk Level: {risk_level.upper()}")
    
    # Step 6: Show recent critical anomalies
    if final_report['recent_critical']:
        print(f"\n🚨 Recent Critical Anomalies:")
        for anomaly in final_report['recent_critical']:
            print(f"\n  Type: {anomaly['type']}")
            print(f"  Description: {anomaly['description']}")
            print(f"  Confidence: {anomaly['confidence']:.2%}")
    
    print("\n" + "=" * 70)
    print("✅ Test completed!")
    print("=" * 70)
    
    # Check if ML detected anomalies
    ml_anomalies = final_report['threat_indicators'].get('ml_detected_anomaly', 0)
    if ml_anomalies > 0:
        print(f"\n🎉 SUCCESS! ML model detected {ml_anomalies} anomalous patterns!")
    else:
        print("\n⚠️  ML model did not detect anomalies (may need more data or time)")

if __name__ == "__main__":
    test_ml_validator()
