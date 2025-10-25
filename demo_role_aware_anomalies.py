"""
Demo script showing ROLE-AWARE anomaly detection
Tests sender-specific vs receiver-specific threats
"""

import sys
import time
from ai_encryption_validator import get_validator

def print_header(text):
    print("\n" + "="*70)
    print(f"  {text}")
    print("="*70 + "\n")

def simulate_sender_attacks():
    """Simulate SENDER-SPECIFIC attacks"""
    print_header("🎯 SIMULATING SENDER-SPECIFIC ATTACKS")
    
    validator = get_validator()
    sender_user = "alice_sender"
    
    # 1. MESSAGE FLOODING ATTACK (Sender sending too many messages)
    print("📤 Simulating MESSAGE FLOODING attack...")
    print("   (Sender rapidly sending 25 messages in 60 seconds)")
    for i in range(25):
        validator.log_encryption_event(
            event_type='encrypt',  # SENDER encrypts messages
            user_id=sender_user,
            message_size=1024,
            duration_ms=50.0,
            success=True,
            ip_address='192.168.1.100',
            session_id=f'session_{i}',
            metadata={'recipient': f'user_{i % 3}'}
        )
        time.sleep(0.01)
    print("   ✅ 25 encrypt operations logged\n")
    
    time.sleep(1)
    
    # 2. RECIPIENT ENUMERATION (Sender probing many recipients)
    print("🔍 Simulating RECIPIENT ENUMERATION attack...")
    print("   (Sender testing 8 different recipients in 5 minutes)")
    for i in range(15):
        validator.log_encryption_event(
            event_type='encrypt',  # SENDER encrypts messages
            user_id=sender_user,
            message_size=512,
            duration_ms=45.0,
            success=(i % 3 != 0),  # Some fail
            ip_address='192.168.1.100',
            session_id='session_123',
            metadata={'recipient': f'probe_user_{i % 8}'}  # 8 different recipients
        )
        time.sleep(0.01)
    print("   ✅ Tested 8 different recipients\n")

def simulate_receiver_attacks():
    """Simulate RECEIVER-SPECIFIC attacks"""
    print_header("🎯 SIMULATING RECEIVER-SPECIFIC ATTACKS")
    
    validator = get_validator()
    receiver_user = "bob_receiver"
    
    # 1. BRUTE FORCE ATTACK ON RECEIVER (trying to decrypt messages)
    print("🚨 Simulating RECEIVER BRUTE FORCE attack...")
    print("   (Receiver attempting 15 decryptions in 60 seconds)")
    for i in range(15):
        validator.log_encryption_event(
            event_type='decrypt',  # RECEIVER decrypts messages
            user_id=receiver_user,
            message_size=1024,
            duration_ms=60.0,
            success=(i % 4 == 0),  # Most fail
            ip_address='192.168.1.200',
            session_id='session_456',
            metadata={'message_id': f'msg_{i}', 'sender': 'alice'}
        )
        time.sleep(0.01)
    print("   ✅ 15 decrypt attempts logged\n")
    
    time.sleep(1)
    
    # 2. MESSAGE INTERCEPTION (trying to read many different senders' messages)
    print("📥 Simulating MESSAGE INTERCEPTION attack...")
    print("   (Receiver trying to read messages from 6 different senders)")
    for i in range(12):
        validator.log_encryption_event(
            event_type='decrypt',  # RECEIVER decrypts messages
            user_id=receiver_user,
            message_size=2048,
            duration_ms=55.0,
            success=(i % 3 == 0),  # Some fail (suspicious)
            ip_address='192.168.1.200',
            session_id='session_789',
            metadata={
                'message_id': f'intercepted_msg_{i}',
                'sender': f'sender_{i % 6}'  # 6 different senders
            }
        )
        time.sleep(0.01)
    print("   ✅ Attempted to read from 6 different senders\n")
    
    time.sleep(1)
    
    # 3. CREDENTIAL STUFFING ON RECEIVER
    print("🔴 Simulating RECEIVER CREDENTIAL STUFFING...")
    print("   (Failed decryption attempts - wrong keys/passwords)")
    for i in range(8):
        validator.log_encryption_event(
            event_type='decrypt',  # RECEIVER with wrong credentials
            user_id=receiver_user,
            message_size=512,
            duration_ms=70.0,
            success=False,  # All fail
            ip_address='192.168.1.200',
            session_id='session_999',
            metadata={'message_id': f'locked_msg_{i}', 'error': 'wrong_key'}
        )
        time.sleep(0.5)
    print("   ✅ 8 failed decrypt attempts logged\n")

def show_role_aware_results():
    """Display role-specific anomaly detections"""
    print_header("📊 ROLE-AWARE ANOMALY DETECTION RESULTS")
    
    validator = get_validator()
    
    # Get results for sender
    print("🔍 SENDER User (alice_sender) Threats:")
    print("-" * 70)
    sender_report = validator.get_security_report(user_id='alice_sender')
    if sender_report['anomaly_summary']:
        for idx, anomaly in enumerate(sender_report['anomaly_summary'], 1):
            print(f"\n[Sender Threat #{idx}] - {anomaly['count']}x occurrences")
            print(f"Type: {anomaly['type']}")
            print(f"Severity: {anomaly['severity'].upper()}")
            print(f"\n{anomaly['description']}")
            print("\n🔍 What This Means:")
            for indicator in anomaly['indicators'][:4]:
                print(f"  • {indicator}")
            print(f"\n🛡️ How to Counter:\n  {anomaly['recommended_action']}")
            print("-" * 70)
    else:
        print("  ✅ No threats detected for sender\n")
    
    print("\n")
    
    # Get results for receiver
    print("🔍 RECEIVER User (bob_receiver) Threats:")
    print("-" * 70)
    receiver_report = validator.get_security_report(user_id='bob_receiver')
    if receiver_report['anomaly_summary']:
        for idx, anomaly in enumerate(receiver_report['anomaly_summary'], 1):
            print(f"\n[Receiver Threat #{idx}] - {anomaly['count']}x occurrences")
            print(f"Type: {anomaly['type']}")
            print(f"Severity: {anomaly['severity'].upper()}")
            print(f"\n{anomaly['description']}")
            print("\n🔍 What This Means:")
            for indicator in anomaly['indicators'][:4]:
                print(f"  • {indicator}")
            print(f"\n🛡️ How to Counter:\n  {anomaly['recommended_action']}")
            print("-" * 70)
    else:
        print("  ✅ No threats detected for receiver\n")
    
    # Overall statistics
    print("\n")
    print_header("📈 OVERALL STATISTICS")
    overall_report = validator.get_security_report()
    print(f"Total Events Logged: {overall_report['total_events_logged']}")
    print(f"Users Monitored: {overall_report['users_monitored']}")
    print(f"Anomalies (24h): {overall_report['total_anomalies_24h']}")
    print(f"Recent Anomalies (1h): {overall_report['recent_anomalies_1h']}")
    print(f"\nSeverity Breakdown:")
    for severity, count in overall_report['severity_breakdown'].items():
        print(f"  {severity.upper()}: {count}")
    print("\n")

def main():
    print_header("🛡️ ROLE-AWARE ANOMALY DETECTION DEMO")
    print("This demo shows how the system now distinguishes between:")
    print("  👤 SENDER-specific attacks (message flooding, recipient enumeration)")
    print("  👤 RECEIVER-specific attacks (brute force, interception, wrong credentials)")
    print("\nPreviously, both received the same generic warnings.")
    print("Now, each role gets specific threat descriptions and countermeasures.")
    
    input("\nPress ENTER to start sender attack simulation...")
    simulate_sender_attacks()
    
    input("\nPress ENTER to start receiver attack simulation...")
    simulate_receiver_attacks()
    
    print("\n⏳ Waiting for anomaly detection to process...")
    time.sleep(2)
    
    input("\nPress ENTER to view role-aware results...")
    show_role_aware_results()
    
    print_header("✅ DEMO COMPLETE")
    print("Key Improvements:")
    print("  ✅ Different warnings for SENDER vs RECEIVER")
    print("  ✅ New anomaly types: message_flooding, recipient_enumeration, message_interception")
    print("  ✅ Role-specific recommended actions")
    print("  ✅ Better threat context and explanations")
    print("\nCheck the web UI at: http://127.0.0.1:5001/status")

if __name__ == '__main__':
    main()
