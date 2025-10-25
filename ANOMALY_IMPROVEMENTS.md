# Anomaly Detection System Improvements

## Summary of Changes

This document describes the improvements made to the AI-driven encryption anomaly detection system to address:
1. **Generic anomaly types** - Made attack types more specific and descriptive
2. **Role confusion** - Clearly differentiated sender vs receiver attacks
3. **Missing context** - Added detailed attack type information

---

## Key Improvements

### 1. **Role-Specific Attack Detection**

#### **Session Hijacking Attacks**
Previously showed generic "SESSION HIJACKING" for all users. Now detects:

- **🚨 RECEIVER SESSION HIJACKING**: Attacker trying to hijack session to READ incoming messages
  - Specific to users primarily receiving/reading messages
  - Focuses on inbox access and message reading threats
  - Action: Review which messages were accessed, protect inbox

- **🚨 SENDER SESSION HIJACKING**: Attacker trying to hijack session to SEND messages as you
  - Specific to users primarily sending messages
  - Focuses on impersonation and unauthorized sending
  - Action: Notify contacts of potential impersonation, monitor sent messages

- **🚨 FULL ACCOUNT SESSION HIJACKING**: Complete access to both sending AND receiving
  - For users with mixed activity (both send and receive)
  - Most severe - complete account takeover
  - Action: Lock account, review entire message history

#### **Impossible Travel Attacks**
Previously generic location warnings. Now role-aware:

- **🌍 RECEIVER IMPOSSIBLE TRAVEL**: Reading messages from multiple locations simultaneously
  - Risk: Someone else accessing your inbox from another location
  - Action: Check message read history, enable geographic restrictions for inbox

- **🌍 SENDER IMPOSSIBLE TRAVEL**: Sending messages from multiple locations simultaneously
  - Risk: Unauthorized person sending messages pretending to be you
  - Action: Check sent message history, notify recipients of potential impersonation

- **🌍 FULL ACCOUNT IMPOSSIBLE TRAVEL**: Complete compromise with multiple locations
  - Risk: Multiple attackers OR coordinated attack on entire account
  - Action: Lock account, review complete message history, consider account migration

---

### 2. **Enhanced Attack Type Specificity**

#### **Cache Timing Attacks**
Now separated by role:

- **⚡ RECEIVER CACHE TIMING ATTACK**: CPU cache side-channel on decryption
  - Target: Extract receiver's private decryption key
  - Impact: Could decrypt ALL past and future messages
  - Method: Statistical analysis of decryption timing variations
  - Defense: Constant-time decryption, rate limiting, random jitter

- **⚡ SENDER CACHE TIMING ATTACK**: CPU cache side-channel on encryption
  - Target: Reveal encryption patterns or message characteristics
  - Impact: Compromise future messages
  - Method: Analyzing encryption timing to infer patterns
  - Defense: Constant-time encryption, batching with random intervals

#### **Cryptanalysis Attacks**
Now distinguished by attack vector:

- **🔄 SENDER KNOWN-PLAINTEXT ATTACK**: Cryptanalysis on encryption algorithm
  - Method: Encrypting known/predictable data to analyze cipher patterns
  - Goal: Extract sender's encryption keys, allow message forgery
  - Impact: Attacker can create fake messages appearing to be from you
  - Defense: Rotate keys immediately, random delays, randomized IVs

- **🔄 RECEIVER CHOSEN-CIPHERTEXT ATTACK**: Adaptive cryptanalysis on decryption
  - Method: Submitting crafted messages and analyzing decryption behavior (oracle attack)
  - Goal: Extract receiver's PRIVATE decryption key
  - Impact: Complete privacy breach - all encrypted communications compromised
  - Defense: Lock account, rotate ALL keys, implement padding oracle protection, AEAD

---

### 3. **ML-Based Anomaly Classification**

Previously: Generic "ML model detected unusual pattern"

Now: Role-specific ML anomaly types:

- **🤖 ML-DETECTED RECEIVER ANOMALY**: Unusual message reading pattern
  - May indicate: Automated scraping, bulk downloading, unauthorized access
  - Focus: How messages are being READ
  - Action: Review read patterns, check for data exfiltration

- **🤖 ML-DETECTED SENDER ANOMALY**: Unusual message sending pattern
  - May indicate: Bot activity, spam automation, account compromise
  - Focus: How messages are being SENT
  - Action: Review sent messages, check for spam/bot activity

---

### 4. **Visual Improvements in UI**

Added colored badges to instantly identify attack types:

- **📤 SENDER ATTACK** - Purple gradient badge for sender-targeted attacks
- **📥 RECEIVER ATTACK** - Pink gradient badge for receiver-targeted attacks
- **🔄 MIXED ATTACK (SEND+RECEIVE)** - Yellow gradient for full account attacks
- **🤖 ML-DETECTED** - Blue gradient for machine learning detections

Enhanced information display:
- Shows up to 5 attack indicators (previously 3)
- Better labels: "Attack Details" and "Defense Actions"
- Clearer role identification in every anomaly

---

## Attack Type Classification

### By User Role

| Attack Type | Sender | Receiver | Mixed |
|-------------|--------|----------|-------|
| Session Hijacking | ✅ | ✅ | ✅ |
| Impossible Travel | ✅ | ✅ | ✅ |
| Cache Timing | ✅ | ✅ | - |
| Brute Force | - | ✅ | - |
| Message Flooding | ✅ | - | - |
| Recipient Enumeration | ✅ | - | - |
| Message Interception | - | ✅ | - |
| Credential Stuffing | - | ✅ | ✅ |
| Known-Plaintext | ✅ | - | - |
| Chosen-Ciphertext | - | ✅ | - |
| Traffic Analysis | ✅ | ✅ | ✅ |
| ML Anomaly | ✅ | ✅ | - |

### By Severity

**CRITICAL** (Immediate action required):
- Session Hijacking (all types)
- Receiver Credential Stuffing
- Chosen-Ciphertext Attack (Receiver)
- Message Interception (Receiver)

**HIGH** (Urgent attention):
- Impossible Travel (all types)
- Cache Timing Attacks (both)
- Brute Force (Receiver)
- Message Flooding (Sender)
- Recipient Enumeration (Sender)
- Known-Plaintext Attack (Sender)

**MEDIUM** (Monitor closely):
- Timing Side-Channel
- Traffic Analysis
- ML-Detected Anomalies (low confidence)

---

## Example Anomaly Messages

### Before Improvement
```
🚨 SESSION HIJACKING: 5 different sessions detected in 1 hour (attack type: Session theft)
⚠️ CAUTION: Unusual timing pattern detected - 65% variance from normal
```

### After Improvement
```
🚨 RECEIVER SESSION HIJACKING: Attacker trying to hijack session to READ your incoming messages
   👤 User Role: RECEIVER
   📊 Recent activity: 2 sends, 15 reads
   💥 Risk: Attacker gains access to 15 incoming messages in your inbox
   🛡️ Defense: Invalidate all sessions, enable 2FA for message reading, review which messages were accessed

⏱️ RECEIVER TIMING ATTACK: Unusual timing pattern detected - 65% variance from normal
   👤 Role: RECEIVER
   🎯 Attack type: Timing side-channel
   🔍 Target: Decryption operations
   ⚙️ Defense: Add random delays (50-100ms) to message retrieval, use constant-time algorithms
```

---

## Testing Recommendations

1. **Test Sender Attacks**: Create automated script that sends messages rapidly
2. **Test Receiver Attacks**: Create script that reads messages in patterns
3. **Test Session Hijacking**: Login from multiple browsers/sessions simultaneously
4. **Test Impossible Travel**: Use VPN to switch locations rapidly
5. **Verify Badge Display**: Check that sender/receiver/mixed badges appear correctly

---

## Impact

✅ **Clarity**: Users now understand WHO is being attacked (sender vs receiver)
✅ **Specificity**: Attack types clearly describe WHAT is happening
✅ **Actionability**: Recommendations tailored to specific role and attack
✅ **Visual Distinction**: Color-coded badges for instant recognition
✅ **Educational**: Each anomaly explains the attack method and impact

---

## Files Modified

1. `ai_encryption_validator.py` - Core anomaly detection logic
   - Enhanced `_check_session_anomalies()` with role-specific detection
   - Improved `_detect_timing_attacks()` to separate sender/receiver
   - Enhanced `_detect_pattern_attacks()` to distinguish attack types
   - Updated `_detect_ml_anomalies()` with role-specific ML classification

2. `templates/status.html` - User interface
   - Added role-specific colored badges
   - Enhanced information display (5 indicators vs 3)
   - Better labeling and visual hierarchy
   - Added ML detection badge

---

## Future Enhancements

- [ ] Add geolocation data to impossible travel detection
- [ ] Implement automatic key rotation on critical attacks
- [ ] Add email/SMS notifications for critical anomalies
- [ ] Create detailed attack timeline visualization
- [ ] Add attack correlation (detect multi-vector attacks)
- [ ] Implement automated response actions based on attack type
