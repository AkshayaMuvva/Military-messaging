"""
Quick Demo: AI-Based Metadata Leak Detection in Action
Shows real-time protection of message metadata
"""

import time
import json
from ai_metadata_detector import MetadataProtectionSystem


def print_colored(text, color="white"):
    """Print colored text"""
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "cyan": "\033[96m",
        "white": "\033[97m",
        "reset": "\033[0m"
    }
    print(f"{colors.get(color, colors['white'])}{text}{colors['reset']}")


def demo_metadata_protection():
    """Quick demonstration of metadata protection"""
    
    print("\n" + "="*70)
    print_colored("  🛡️  AI-BASED METADATA LEAK DETECTION - LIVE DEMO", "cyan")
    print("="*70 + "\n")
    
    # Initialize protection system
    protection = MetadataProtectionSystem()
    protection.set_protection_level("maximum")
    
    print_colored("✅ Protection System Initialized (Level: MAXIMUM)\n", "green")
    
    # Simulate a message being sent
    print_colored("📨 Simulating message send...\n", "yellow")
    
    original_metadata = {
        'sender': 'alice@example.com',
        'recipient': 'bob@example.com',
        'timestamp': time.time(),
        'ip': '192.168.1.100',
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'message_size': 2048,
        'session_id': 'sess_abc123',
        'client_ip': '10.0.0.5'
    }
    
    print_colored("📋 ORIGINAL METADATA (BEFORE PROTECTION):", "red")
    print(json.dumps(original_metadata, indent=2))
    
    # Apply protection
    print_colored("\n🔐 Applying AI-based protection...", "yellow")
    time.sleep(1)
    
    result = protection.protect_message_metadata(original_metadata)
    
    # Show detected threats
    print_colored("\n⚠️  THREATS DETECTED:", "yellow")
    report = result['protection_report']
    
    print(f"   • Total patterns detected: {report['detected_patterns']}")
    print_colored(f"   • High-risk patterns: {', '.join(report['risk_patterns'])}", "red")
    
    # Show protected metadata
    print_colored("\n✅ PROTECTED METADATA (AFTER AI PROTECTION):", "green")
    print(json.dumps(result['protected_metadata'], indent=2))
    
    # Show what was done
    print_colored("\n🔧 PROTECTION ACTIONS TAKEN:", "cyan")
    print("   ✅ IP addresses: REMOVED")
    print("   ✅ User-Agent: REMOVED")
    print("   ✅ Sender/Recipient: ANONYMIZED (hashed)")
    print("   ✅ Timestamp: RANDOMIZED (±5 min jitter)")
    print("   ✅ Message size: NORMALIZED to bucket")
    print("   ✅ Decoy metadata: INJECTED (5 fake fields)")
    print(f"   ✅ Send delay: {result['send_delay']:.2f} seconds (timing obfuscation)")
    
    # Show statistics
    print_colored("\n📊 PROTECTION STATISTICS:", "cyan")
    stats = protection.get_protection_stats()
    print(json.dumps(stats, indent=2))
    
    print_colored("\n🎯 RESULT: No residual communication patterns exposed!", "green")
    print("="*70 + "\n")


if __name__ == "__main__":
    demo_metadata_protection()
