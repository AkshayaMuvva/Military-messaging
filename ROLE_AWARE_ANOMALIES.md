# 🎯 Role-Aware Anomaly Detection System

## Overview
The system now **distinguishes between SENDER and RECEIVER roles** when detecting security threats. Different warnings and recommended actions are shown based on whether a user is:
- **SENDER** (encrypting and sending messages)
- **RECEIVER** (decrypting and reading messages)
- **MIXED** (both sending and receiving)

---

## 🆕 NEW Anomaly Types Added

### 1. 📤 SENDER-SPECIFIC ANOMALIES

#### **Message Flooding Attack**
- **Type**: `message_flooding_sender`
- **What**: Sender is sending too many messages in a short time
- **How Detected**: 20+ encrypt operations in 60 seconds
- **Why Dangerous**: Spam attack, system abuse, recipient harassment
- **What to Do (SENDER)**: 
  - Rate limit message sending
  - Implement CAPTCHA verification
  - Require delays between messages
  - Review account for spam activity

#### **Recipient Enumeration Attack** 
- **Type**: `recipient_enumeration_sender`
- **What**: Sender is probing/testing many different recipient accounts
- **How Detected**: Sending to 5+ different recipients in 5 minutes
- **Why Dangerous**: Privacy violation, discovering valid accounts, preparing targeted attacks
- **What to Do (SENDER)**:
  - Implement CAPTCHA after 3 different recipients
  - Rate limit recipient testing
  - Require email verification for new contacts
  - Monitor for pattern abuse

---

### 2. 📥 RECEIVER-SPECIFIC ANOMALIES

#### **Brute Force Attack on Receiver**
- **Type**: `brute_force_attack_receiver`
- **What**: Someone trying to decrypt messages they shouldn't have access to
- **How Detected**: 10+ decryption attempts in 60 seconds
- **Why Dangerous**: Unauthorized access to private messages
- **What to Do (RECEIVER)**:
  - Lock message access temporarily
  - Require 2FA for message reading
  - Verify user identity before allowing decryption

#### **Credential Stuffing on Receiver**
- **Type**: `credential_stuffing_receiver`
- **What**: Multiple failed attempts to decrypt messages (wrong keys/passwords)
- **How Detected**: 5+ failed decryption attempts in 1 hour, user primarily reads messages
- **Why Dangerous**: Someone trying to access messages meant for another user
- **What to Do (RECEIVER)**:
  - Lock account immediately
  - Force password reset
  - Notify legitimate user
  - Invalidate all message access tokens

#### **Message Interception Attack** 🆕
- **Type**: `message_interception_receiver`
- **What**: Attempting to read messages from many different senders (suspicious pattern)
- **How Detected**: Reading messages from 4+ different senders with 2+ failures in 10 minutes
- **Why Dangerous**: Man-in-the-middle attack, session hijacking, unauthorized access
- **What to Do (RECEIVER)**:
  - Verify user identity immediately
  - Check for session hijacking
  - Invalidate all sessions
  - Require re-authentication
  - Alert legitimate message owners

---

### 3. 🔀 MIXED ROLE ANOMALIES

#### **Generic Credential Stuffing**
- **Type**: `credential_stuffing_mixed`
- **What**: Multiple authentication failures for user doing both sending and receiving
- **How Detected**: 5+ failed attempts in 1 hour, mixed activity
- **Why Dangerous**: Account compromise in progress
- **What to Do (MIXED)**:
  - Lock account immediately
  - Force password reset
  - Notify user via alternate channel
  - Alert security team

---

## 📊 Enhanced Existing Anomalies with Role Context

### **Timing Side-Channel Attacks** (Now Role-Aware)
- **Receiver Version**: `timing_side_channel_attack_receiver`
  - Target: Analyzing decryption timing to infer keys
  - Defense: Add random delays to message retrieval, use constant-time decryption
  
- **Sender Version**: `timing_side_channel_attack_sender`
  - Target: Analyzing encryption timing
  - Defense: Add timing jitter to message sending, batch messages randomly

### **Traffic Analysis Attacks** (Now Role-Aware)
- **Receiver Version**: `traffic_analysis_attack_receiver`
  - Target: Analyzing reading patterns
  - Defense: Use random access delays, read decoy messages
  
- **Sender Version**: `traffic_analysis_attack_sender`
  - Target: Analyzing sent message sizes
  - Defense: Enable message padding, add dummy traffic, use fixed-size blocks

---

## 🔍 How It Works

### Role Detection
The system automatically determines a user's primary role:
```python
total_encrypts = count of encrypt operations
total_decrypts = count of decrypt operations

if total_decrypts > total_encrypts:
    role = "RECEIVER"
elif total_encrypts > total_decrypts:
    role = "SENDER"
else:
    role = "MIXED"
```

### Different Warnings
Each anomaly now shows:
- **👤 Role**: SENDER, RECEIVER, or MIXED
- **🎯 Attack Pattern**: Role-specific explanation
- **🔍 Target**: What the attacker is targeting based on role
- **🛡️ Recommended Action**: Role-specific countermeasures

---

## 💡 Key Benefits

### ✅ No More Generic Warnings
**Before**:
- "CREDENTIAL ATTACK: Failed attempts detected"
- Same message for both sender and receiver

**After**:
- **For Receiver**: "RECEIVER ATTACK - CREDENTIAL STUFFING: Unauthorized user trying to access someone else's messages"
- **For Sender**: "SENDER ATTACK - MESSAGE FLOODING: Spam/flooding attack detected"

### ✅ Actionable Guidance
Each role gets **specific instructions**:
- **Receivers**: Lock message access, verify identity, invalidate tokens
- **Senders**: Rate limit sending, implement CAPTCHA, require delays
- **System**: Role-appropriate defenses

### ✅ Better Threat Detection
New anomalies catch attacks that were previously invisible:
- Recipient enumeration (discovering valid accounts)
- Message interception (reading messages from many senders)
- Role-specific timing and traffic analysis

---

## 📈 Total Anomaly Types

### Summary
- **Previous**: 8 generic anomaly types
- **Now**: 15+ role-specific anomaly types
- **New Types**: 3 completely new attack patterns
- **Enhanced**: All timing/traffic attacks now role-aware

### Complete List
1. `brute_force_attack_receiver` ✅ RECEIVER
2. `message_flooding_sender` ✅ SENDER
3. `credential_stuffing_receiver` ✅ RECEIVER
4. `credential_stuffing_mixed` ✅ MIXED
5. `recipient_enumeration_sender` 🆕 SENDER
6. `message_interception_receiver` 🆕 RECEIVER
7. `timing_side_channel_attack_receiver` ✅ RECEIVER
8. `timing_side_channel_attack_sender` ✅ SENDER
9. `timing_side_channel_attack_mixed` ✅ MIXED
10. `traffic_analysis_attack_receiver` ✅ RECEIVER
11. `traffic_analysis_attack_sender` ✅ SENDER
12. `traffic_analysis_attack_mixed` ✅ MIXED
13. `session_hijacking_attempt` (applies to both)
14. `impossible_travel_attack` (applies to both)
15. `cache_timing_attack` (applies to both)
16. `known_plaintext_attack` (applies to both)

---

## 🎯 Summary of Changes

### What Was Missing
1. ❌ No distinction between sender and receiver threats
2. ❌ Same generic warnings for both roles
3. ❌ No detection of recipient enumeration
4. ❌ No detection of message interception
5. ❌ No role-specific countermeasures

### What's Fixed
1. ✅ Clear role identification (SENDER/RECEIVER/MIXED)
2. ✅ Role-specific threat descriptions
3. ✅ New anomaly: Recipient enumeration (SENDER)
4. ✅ New anomaly: Message interception (RECEIVER)
5. ✅ New anomaly: Message flooding (SENDER)
6. ✅ Role-specific recommended actions
7. ✅ Enhanced timing/traffic analysis with role context

---

## 🚀 Next Steps

### For Users
- Check the status page: `http://127.0.0.1:5001/status`
- Look for anomalies with role badges: **👤 Role: SENDER/RECEIVER**
- Follow role-specific recommendations

### For Developers
- Anomalies now include role context in descriptions
- Use `anomaly['indicators']` to see role-specific details
- Action items are tailored to sender/receiver behavior

### For Security Teams
- Monitor for new anomaly types (recipient enumeration, message interception)
- Review role-specific patterns in threat reports
- Implement role-based rate limiting strategies
