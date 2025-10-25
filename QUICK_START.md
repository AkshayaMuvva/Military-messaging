# 🚀 Quick Start Guide

## Installation

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Verify Installation

```bash
python check_compatibility.py
```

### 3. Start the Application

```bash
python app.py
```

The application will start on `http://127.0.0.1:5001`

---

## First Time Setup

### Step 1: Register a User

1. Navigate to `http://127.0.0.1:5001`
2. Click "Register New User"
3. Enter a User ID and optional alias
4. Save your QR code and fingerprint (for key exchange)

### Step 2: Send a Secure Message

1. Go to "Send Message"
2. Enter recipient ID
3. Type your message
4. Set TTL (time-to-live in minutes)
5. Click "Encrypt & Send"
6. Share the secure link with recipient

### Step 3: Read Messages

1. Go to "Inbox" to see messages sent to you
2. Or use the secure link provided by sender
3. Message self-destructs after reading

### Step 4: Monitor System Status

1. Go to "System Status" to view:
   - Quantum crypto status
   - Metadata protection level
   - Real-time threat assessment
   - AI intrusion detection
   - Tor integration
   - Security metrics

---

## Security Features Overview

### 🔐 Quantum-Resistant Encryption
- **Status:** Always active
- **Algorithm:** Kyber-Dilithium Hybrid
- **Protection:** Against future quantum attacks

### 🛡️ Metadata Protection
- **Level:** MAXIMUM (configurable)
- **Features:** 
  - Removes identifying information
  - Adds random timing delays
  - Injects dummy traffic
  - Normalizes message sizes

### ⚡ Real-Time Threat Assessment
- **Monitoring:** Every request analyzed
- **Response:** Automatic blocking of critical threats
- **AI:** Behavioral profiling and anomaly detection

### 💥 Self-Destructing Messages
- **Storage:** Memory-only (never on disk)
- **Destruction:** After reading or TTL expiry
- **Wiping:** 4-pass secure memory wipe

---

## Configuration

### Security Levels

Edit in `app.py`:

```python
# Metadata protection level
self.metadata_protection.set_protection_level("maximum")
# Options: "low", "medium", "high", "maximum"

# Quantum crypto security level
self.quantum_crypto = QuantumResistantCrypto(security_level=3)
# Options: 1 (AES-128), 3 (AES-192), 5 (AES-256)
```

### Tor Integration

For production deployment with Tor:

1. Install Tor:
   ```bash
   # Windows (with Chocolatey)
   choco install tor
   
   # Or download from https://www.torproject.org/
   ```

2. The app will automatically use Tor if available

---

## Testing

### Test Message Flow

1. Register User A: "alice"
2. Register User B: "bob"
3. Alice sends message to "bob"
4. Bob checks inbox
5. Bob clicks message link
6. Message displays and self-destructs
7. Link becomes invalid

### Test Security Features

1. Check `/status` for all security metrics
2. Try rapid requests (rate limiting triggers)
3. Send multiple messages (see metadata protection)
4. Monitor threat assessment scores

---

## Troubleshooting

### "Tor not available"
- Normal in development mode
- App works with fallback mode
- For production, install Tor daemon

### "Failed to establish secure session"
- Ensure recipient is registered
- Check recipient ID spelling
- Both users must have generated keys

### "Message not found"
- Message may have expired (TTL)
- Message was already read (self-destructed)
- Invalid message ID

---

## Production Deployment

### Checklist

1. **Install all dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Install Tor daemon**
   - Required for full metadata protection
   - Provides .onion hidden service

3. **Configure environment**
   ```bash
   # Set production mode
   export FLASK_ENV=production
   
   # Use strong secret key
   export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
   ```

4. **Run with production server**
   ```bash
   # Using gunicorn
   gunicorn -w 4 -b 0.0.0.0:5001 app:app
   
   # Or using waitress (Windows)
   waitress-serve --port=5001 app:app
   ```

5. **Security hardening**
   - Run as non-root user
   - Use firewall rules
   - Enable HTTPS with valid certificate
   - Regular security audits

---

## Advanced Usage

### API Endpoints

```python
# Get system status
GET /status

# Emergency memory wipe
POST /emergency_wipe

# Send message
POST /send_message

# Read message
GET /read/<message_id>

# User inbox
GET /inbox
```

### Programmatic Access

```python
from app import app_instance

# Access security systems
quantum_crypto = app_instance.quantum_crypto
metadata_protection = app_instance.metadata_protection
threat_system = app_instance.threat_system

# Get statistics
stats = threat_system.get_threat_statistics()
print(f"Total assessments: {stats['total_assessments']}")
```

---

## Security Best Practices

### For Users

1. **Never share your private keys**
2. **Verify recipient fingerprints**
3. **Use strong User IDs**
4. **Set appropriate TTL**
5. **Use Tor browser for access**

### For Administrators

1. **Monitor threat assessment dashboard**
2. **Review blocked IPs regularly**
3. **Update dependencies frequently**
4. **Perform security audits**
5. **Backup configuration (not messages!)**

---

## Support

- Documentation: `ADVANCED_SECURITY_FEATURES.md`
- Project Status: `PROJECT_COMPLETION.md`
- Issues: Open on GitHub
- Security: Use emergency wipe if compromised

---

**Ready to use!** 🎉

For complete technical details, see `ADVANCED_SECURITY_FEATURES.md`
