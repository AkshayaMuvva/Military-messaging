# 🌐 How to View Detailed Anomaly Information on the Website

## 📍 Where to Find Anomaly Details

### **Step 1: Access the Status Page**
1. Open your web browser
2. Navigate to: **http://127.0.0.1:5001/status**
3. You'll see the security dashboard

---

## 🔍 What You'll See on the Status Page

### **Location: "Encryption Anomaly Detection" Card**
This card is on the status page and shows ALL the enhanced anomaly information.

---

## 📊 Information Displayed (WHAT, HOW, WHY, WHAT TO DO)

### **1. WHAT - Attack Type Name**
```
┌─────────────────────────────────────────────┐
│ CREDENTIAL STUFFING           95% CONFIDENCE│  ← Attack Type & Confidence
└─────────────────────────────────────────────┘
```
**Location**: Top of each anomaly card in UPPERCASE
**Example**: "CREDENTIAL STUFFING", "BRUTE FORCE ATTACK", "SESSION HIJACKING ATTEMPT"

---

### **2. HOW & WHY - Detailed Description**
```
🔴 CREDENTIAL ATTACK: 8 failed decryption attempts 
in 1 hour (normal: <5)
```
**Location**: Just below the attack type
**Shows**:
- 🔴 Severity indicator (emoji)
- Attack name
- Specific numbers (what triggered it)
- Normal vs abnormal comparison

**Examples**:
- `🚨 BRUTE FORCE ATTEMPT: 15 rapid decryption attempts detected in 60 seconds (normal: <10)`
- `🌍 IMPOSSIBLE TRAVEL: 6 different IP addresses in 1 hour (attack type: Account sharing or compromise)`
- `⏱️ TIMING ATTACK: Unusual timing pattern detected - 52% variance from normal (attack type: Side-channel analysis)`

---

### **3. HOW - Threat Indicators (Attack Method)**
```
🔍 Threat Indicators:
   ❌ 8 failed decrypt attempts in past hour
   🔑 Pattern: Multiple wrong passwords/keys
   🌐 Source IP: 203.0.113.45
   💥 Risk: Account compromise in progress
```
**Location**: Expandable section under description
**Shows**:
- **Specific metrics** (how many, how fast, from where)
- **Attack pattern** (what the attacker is doing)
- **Attack method** (HOW the attack works)
- **Risk level** (WHY it's dangerous)

**Example Indicators**:
```
🔍 Threat Indicators:
   🔀 Multiple sessions: 6 unique session IDs
   ⏰ Time window: Past hour
   🎯 Attack type: Session hijacking/fixation
   🔍 Method: Stealing or predicting session tokens
   🌐 Current IP: 10.0.5.100
   💥 Risk: Unauthorized account access
```

---

### **4. WHAT TO DO - Recommended Action**
```
💡 Recommended Action:
   🚨 CRITICAL: Lock account immediately, force password 
   reset, notify user, alert security team
```
**Location**: Bottom section of each anomaly
**Shows**:
- **Urgency level**: 🚨 CRITICAL, ⚠️ URGENT, 🛡️ IMMEDIATE, ⚙️ DEFENSE
- **Specific steps** to take (exactly what to do)
- **Technical countermeasures** (how to prevent future attacks)

**Example Actions**:
- `🛡️ IMMEDIATE: Rate limit user, require multi-factor authentication, log IP address`
- `⚙️ DEFENSE: Add random timing jitter (50-100ms), use constant-time algorithms`
- `🚨 IMMEDIATE: Invalidate all sessions, force re-login, enable 2FA`

---

## 🖼️ Complete Example of What Users See

```
┌───────────────────────────────────────────────────────────┐
│                                                           │
│  CREDENTIAL STUFFING                    95% CONFIDENCE    │
│                                                           │
│  🔴 CREDENTIAL ATTACK: 8 failed decryption attempts      │
│  in 1 hour (normal: <5)                                  │
│                                                           │
│  🔍 Threat Indicators:                                   │
│     ❌ 8 failed decrypt attempts in past hour           │
│     🔑 Pattern: Multiple wrong passwords/keys           │
│     🌐 Source IP: 203.0.113.45                          │
│     💥 Risk: Account compromise in progress             │
│                                                           │
│  💡 Recommended Action:                                  │
│     🚨 CRITICAL: Lock account immediately, force        │
│     password reset, notify user, alert security team    │
│                                                           │
└───────────────────────────────────────────────────────────┘
```

---

## 📋 Summary Statistics Shown

**At the top of the Encryption Anomaly Detection card:**

| Metric | Description | Example |
|--------|-------------|---------|
| **ML Model Status** | Is ML detection active? | ✅ Trained |
| **Monitoring** | Real-time monitoring status | 🟢 Active |
| **Total Events Logged** | All encryption events tracked | 1,234 |
| **Anomalies (24h)** | Total anomalies in 24 hours | 23 |
| **Recent Anomalies (1h)** | Anomalies in last hour | 5 |
| **Users Monitored** | Number of users being tracked | 4 |

**Severity Breakdown:**
```
🚨 Anomaly Severity (1h)
   CRITICAL    17
   HIGH         6
   MEDIUM       0
   LOW          0
```

---

## 🎯 Real-World Example: What a User Sees

### **Scenario: Brute Force Attack Detected**

**On the Status Page, user sees:**

```
⚠️ Recent Critical Anomalies

┌─────────────────────────────────────────────────────┐
│ BRUTE FORCE ATTACK                     90% CONFIDENCE│
├─────────────────────────────────────────────────────┤
│ 🚨 BRUTE FORCE ATTEMPT: 15 rapid decryption         │
│ attempts detected in 60 seconds (normal: <10)       │
│                                                      │
│ 🔍 Threat Indicators:                               │
│  • ⚡ 15 decrypt attempts in 1 minute               │
│  • 📊 Normal threshold: 10 per minute               │
│  • 🎯 Attack pattern: Automated password/key        │
│       guessing                                       │
│                                                      │
│ 💡 Recommended Action:                              │
│  🛡️ IMMEDIATE: Rate limit user, require multi-     │
│  factor authentication, log IP address              │
└─────────────────────────────────────────────────────┘
```

**The user immediately understands:**
- ✅ **WHAT**: Someone is trying a brute force attack
- ✅ **HOW**: 15 rapid decryption attempts (automated password guessing)
- ✅ **WHY**: This is dangerous because it's an unauthorized access attempt
- ✅ **WHAT TO DO**: Enable rate limiting and multi-factor authentication

---

## 🚀 How to Access Right Now

### **Option 1: Direct Link**
1. Server must be running (it is!)
2. Click or navigate to: **http://127.0.0.1:5001/status**
3. Scroll down to "Encryption Anomaly Detection" card

### **Option 2: From Main Page**
1. Go to: **http://127.0.0.1:5001**
2. Login to your account
3. Click on "System Status" or navigate to `/status`
4. Look for the orange-bordered card labeled "🔍 Encryption Anomaly Detection"

---

## 📱 Visual Layout on Status Page

```
┌─────────────────────────────────────────────────────┐
│                   STATUS PAGE                        │
├─────────────────────────────────────────────────────┤
│                                                      │
│  [ML Threat Assessment Card]                        │
│  [Encryption Anomaly Detection Card] ← YOU ARE HERE  │
│  [Security Monitoring Card]                         │
│  [System Metrics Card]                              │
│                                                      │
└─────────────────────────────────────────────────────┘
```

---

## 🔄 Real-Time Updates

**The anomaly information updates automatically:**
- New anomalies appear immediately
- Old anomalies (>1 hour) are archived
- Severity counts update in real-time
- ML detection runs every 30 seconds

**To see changes:**
- Refresh the page (F5)
- Or the page auto-updates if you have JavaScript enabled

---

## 📖 Additional Resources

### **For More Details:**
- **Complete Guide**: Read `ANOMALY_DETECTION_GUIDE.md` (400+ lines)
- **Technical Summary**: Read `ANOMALY_ENHANCEMENT_SUMMARY.md`
- **Live Demo**: Run `python demo_enhanced_anomalies.py`

### **Understanding Each Attack Type:**
All 8 attack types are explained in detail in `ANOMALY_DETECTION_GUIDE.md`:
1. Brute Force Attack
2. Credential Stuffing
3. Timing Side-Channel Attack
4. Traffic Analysis Attack
5. Cache Timing Attack
6. Known-Plaintext Attack
7. Session Hijacking Attempt
8. Impossible Travel Attack

---

## ✅ Quick Test

**Want to see it in action right now?**

1. **Run the demo** (creates test anomalies):
   ```cmd
   python demo_enhanced_anomalies.py
   ```

2. **Open the status page**:
   ```
   http://127.0.0.1:5001/status
   ```

3. **Scroll to "Encryption Anomaly Detection"**

4. **You'll see the test anomalies** with full WHAT/HOW/WHY/WHAT TO DO details!

---

## 🎨 Visual Highlights

**Color Coding:**
- 🔴 **Red/Critical**: Immediate action needed
- 🟠 **Orange/High**: Serious threat, investigate
- 🟡 **Yellow/Medium**: Monitor closely
- 🟢 **Green/Low**: Informational

**Icons Used:**
- 🚨 CRITICAL urgency
- ⚠️ WARNING/URGENT
- 🛡️ IMMEDIATE action
- ⚙️ DEFENSE measures
- 💡 RECOMMENDED action
- 🔍 THREAT indicators
- 🎯 ATTACK type
- 💥 RISK level

---

## 🎯 Summary

### **Where**: 
http://127.0.0.1:5001/status → "Encryption Anomaly Detection" card

### **What You See**:
- ✅ Attack type name (WHAT)
- ✅ Detailed description (HOW & WHY it happened)
- ✅ Threat indicators (HOW the attack works)
- ✅ Recommended actions (WHAT TO DO)
- ✅ Confidence score (How sure we are)

### **All 4 Questions Answered**:
1. **WHAT** - Attack type clearly labeled
2. **HOW** - Method explained in indicators
3. **WHY** - Risk level and danger explained
4. **WHAT TO DO** - Specific actionable steps

**Everything is visible on the website in a user-friendly format!** 🎉
