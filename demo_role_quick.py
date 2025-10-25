"""
Quick demo of ROLE-AWARE anomaly detection (non-interactive)
"""

import time
from ai_encryption_validator import get_validator

print("\n" + "="*70)
print("  🛡️ ROLE-AWARE ANOMALY DETECTION DEMO")
print("="*70 + "\n")

validator = get_validator()

# SENDER ATTACKS
print("📤 Simulating SENDER attacks (message flooding + recipient enumeration)...")
sender = "alice_sender"
for i in range(25):
    validator.log_encryption_event(
        event_type='encrypt',
        user_id=sender,
        message_size=1024,
        duration_ms=50.0,
        success=True,
        ip_address='192.168.1.100',
        session_id=f'session_{i}',
        metadata={'recipient': f'user_{i % 8}'}  # Testing 8 recipients
    )

time.sleep(1)

# RECEIVER ATTACKS
print("📥 Simulating RECEIVER attacks (brute force + message interception)...")
receiver = "bob_receiver"

# Brute force
for i in range(15):
    validator.log_encryption_event(
        event_type='decrypt',
        user_id=receiver,
        message_size=1024,
        duration_ms=60.0,
        success=(i % 4 == 0),
        ip_address='192.168.1.200',
        session_id='session_456',
        metadata={'message_id': f'msg_{i}', 'sender': 'alice'}
    )

time.sleep(0.5)

# Message interception
for i in range(12):
    validator.log_encryption_event(
        event_type='decrypt',
        user_id=receiver,
        message_size=2048,
        duration_ms=55.0,
        success=(i % 3 == 0),
        ip_address='192.168.1.200',
        session_id='session_789',
        metadata={'message_id': f'int_msg_{i}', 'sender': f'sender_{i % 6}'}
    )

# Failed decrypts
for i in range(8):
    validator.log_encryption_event(
        event_type='decrypt',
        user_id=receiver,
        message_size=512,
        duration_ms=70.0,
        success=False,
        ip_address='192.168.1.200',
        session_id='session_999',
        metadata={'message_id': f'locked_{i}', 'error': 'wrong_key'}
    )
    time.sleep(0.3)

print("\n⏳ Processing anomaly detection...\n")
time.sleep(2)

# SHOW RESULTS
print("="*70)
print("  📊 DETECTED THREATS")
print("="*70 + "\n")

# Sender results
print("👤 SENDER (alice_sender) Threats:")
print("-"*70)
sender_report = validator.get_security_report(user_id='alice_sender')
for idx, anomaly in enumerate(sender_report['anomaly_summary'], 1):
    print(f"\n[Threat #{idx}] {anomaly['type']} - {anomaly['count']}x")
    print(f"Severity: {anomaly['severity'].upper()}")
    print(f"{anomaly['description']}")
    print(f"\n🛡️ Action: {anomaly['recommended_action'][:100]}...")

print("\n\n👤 RECEIVER (bob_receiver) Threats:")
print("-"*70)
receiver_report = validator.get_security_report(user_id='bob_receiver')
for idx, anomaly in enumerate(receiver_report['anomaly_summary'], 1):
    print(f"\n[Threat #{idx}] {anomaly['type']} - {anomaly['count']}x")
    print(f"Severity: {anomaly['severity'].upper()}")
    print(f"{anomaly['description']}")
    print(f"\n🛡️ Action: {anomaly['recommended_action'][:100]}...")

print("\n\n" + "="*70)
print("  ✅ KEY IMPROVEMENTS")
print("="*70)
print("✅ Different warnings for SENDER vs RECEIVER")
print("✅ New anomalies: message_flooding, recipient_enumeration, message_interception")
print("✅ Role-specific recommended actions")
print("✅ Better threat context")
print("\nView full details: http://127.0.0.1:5001/status\n")
