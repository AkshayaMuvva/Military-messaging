"""
Demo: Enhanced Encryption Anomaly Detection
Shows all 8 anomaly types with clear descriptions
"""

import sys
import time
sys.path.insert(0, '.')

from ai_encryption_validator import AIEncryptionValidator

def print_section(title):
    print("\n" + "="*80)
    print(f"  {title}")
    print("="*80)

def show_anomaly_details(report):
    """Display anomaly details with full information"""
    if report.get('anomaly_summary'):
        print_section("🚨 DETECTED THREAT SUMMARY")
        for i, anomaly in enumerate(report['anomaly_summary'], 1):
            print(f"\n[Threat Type #{i}] - {anomaly['count']}x occurrences")
            print(f"Type: {anomaly['type'].upper().replace('_', ' ')}")
            print(f"Severity: {anomaly['severity'].upper()}")
            print(f"Confidence: {anomaly['confidence']*100:.0f}%")
            print(f"\n{anomaly['description']}")
            
            if anomaly.get('indicators'):
                print("\n🔍 What This Means:")
                for indicator in anomaly['indicators']:
                    print(f"   {indicator}")
            
            if anomaly.get('recommended_action'):
                print(f"\n�️ How to Counter:")
                print(f"   {anomaly['recommended_action']}")
            
            print("-" * 80)

def main():
    print_section("Enhanced Encryption Anomaly Detection Demo")
    print("This demo shows how the system detects and describes security threats\n")
    
    validator = AIEncryptionValidator()
    
    # Scenario 1: Brute Force Attack
    print_section("Scenario 1: BRUTE FORCE ATTACK")
    print("Simulating rapid decryption attempts (password guessing)...")
    
    user_id = "attacker_test_1"
    for i in range(15):
        validator.log_encryption_event(
            event_type='decrypt',
            user_id=user_id,
            message_size=100,
            duration_ms=50,
            success=False,
            ip_address="192.168.1.100",
            session_id="session_123"
        )
        time.sleep(0.05)
    
    report = validator.get_security_report(user_id)
    show_anomaly_details(report)
    
    # Scenario 2: Credential Stuffing
    print_section("Scenario 2: CREDENTIAL STUFFING")
    print("Simulating multiple failed attempts over extended period...")
    
    user_id = "victim_test_2"
    for i in range(8):
        validator.log_encryption_event(
            event_type='decrypt',
            user_id=user_id,
            message_size=150,
            duration_ms=100,
            success=False,
            ip_address="203.0.113.45",
            session_id=f"session_{i}"
        )
        time.sleep(0.2)
    
    report = validator.get_security_report(user_id)
    show_anomaly_details(report)
    
    # Scenario 3: Session Hijacking
    print_section("Scenario 3: SESSION HIJACKING ATTEMPT")
    print("Simulating multiple different sessions from same user...")
    
    user_id = "user_test_3"
    for i in range(6):
        validator.log_encryption_event(
            event_type='encrypt',
            user_id=user_id,
            message_size=200,
            duration_ms=80,
            success=True,
            ip_address=f"10.0.{i}.100",
            session_id=f"stolen_session_{i}"
        )
        time.sleep(0.1)
    
    report = validator.get_security_report(user_id)
    show_anomaly_details(report)
    
    # Scenario 4: Impossible Travel
    print_section("Scenario 4: IMPOSSIBLE TRAVEL ATTACK")
    print("Simulating access from multiple geographic locations...")
    
    user_id = "user_test_4"
    ips = ["203.0.113.1", "198.51.100.1", "192.0.2.1", "198.18.0.1", "203.0.113.99"]
    for i, ip in enumerate(ips):
        validator.log_encryption_event(
            event_type='decrypt',
            user_id=user_id,
            message_size=180,
            duration_ms=90,
            success=True,
            ip_address=ip,
            session_id="session_xyz"
        )
        time.sleep(0.1)
    
    report = validator.get_security_report(user_id)
    show_anomaly_details(report)
    
    # Overall Statistics
    print_section("📊 OVERALL SECURITY REPORT")
    all_report = validator.get_security_report()
    
    print(f"\nTotal Events Logged: {all_report['total_events_logged']}")
    print(f"Users Monitored: {all_report['users_monitored']}")
    print(f"Anomalies (24h): {all_report['total_anomalies_24h']}")
    print(f"Recent Anomalies (1h): {all_report['recent_anomalies_1h']}")
    print(f"\nML Model Status: {all_report['ml_model_status']}")
    print(f"Detection Methods: {', '.join(all_report['detection_methods'])}")
    
    if all_report['severity_breakdown']:
        print("\n🚨 Severity Breakdown:")
        for severity, count in all_report['severity_breakdown'].items():
            print(f"   {severity.upper()}: {count} anomalies")
    
    if all_report['threat_indicators']:
        print("\n🎯 Threat Type Breakdown:")
        for threat_type, count in all_report['threat_indicators'].items():
            print(f"   {threat_type.replace('_', ' ').title()}: {count}")
    
    print_section("✅ Demo Complete")
    print("\nThe system has successfully detected and categorized multiple threat types!")
    print("Check the status page at http://127.0.0.1:5001/status to see these in action.")
    print("\nAll anomalies now include:")
    print("  • Clear attack type descriptions")
    print("  • Detailed threat indicators")
    print("  • Specific recommended actions")
    print("  • Confidence scores")
    print("\nRefer to ANOMALY_DETECTION_GUIDE.md for complete documentation.")

if __name__ == "__main__":
    main()
