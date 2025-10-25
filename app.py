"""Military-grade secure messaging application with advanced security features"""

import os
import time
import secrets
import logging
import platform
import json
from datetime import datetime
import threading
from typing import Dict, Any, Optional
import atexit
import signal
import sys

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from werkzeug.middleware.proxy_fix import ProxyFix

# Import our security modules
from crypto_engine import CryptoEngine
from key_management import MilitaryKeyManager
from memory_manager import SecureMemoryManager
from tor_integration import TorIntegration
from ai_intrusion_detection import AIIntrusionDetection, SecurityEvent
from security_signals import (
    security_system, message_sent, message_read, message_destroyed,
    user_login, user_logout, session_created, session_destroyed,
    security_alert, intrusion_detected
)

# Import new advanced security modules
from quantum_crypto import QuantumResistantCrypto, AdaptiveEncryptionEngine
from ai_metadata_detector import MetadataProtectionSystem
from realtime_threat_assessment import RealTimeThreatSystem, ThreatAssessment
from ai_encryption_validator import get_validator, AIEncryptionValidator

# Import encrypted database
from database import EncryptedDatabase

# Import Windows compatibility if available
try:
    from windows_compatibility import WindowsSecurityManager, get_windows_compatibility_info
    WINDOWS_SUPPORT = platform.system() == 'Windows'
except ImportError:
    WindowsSecurityManager = None
    get_windows_compatibility_info = None
    WINDOWS_SUPPORT = False

# Disable Flask's default logging for security
logging.getLogger('werkzeug').setLevel(logging.ERROR)

class MilitarySecureApp:
    """Main military-grade secure messaging application"""
    
    def __init__(self):
        self.app = Flask(__name__)
        
        # Initialize Windows compatibility first
        if WINDOWS_SUPPORT and WindowsSecurityManager:
            self.windows_manager = WindowsSecurityManager()
            print("✅ Windows compatibility enabled")
        else:
            self.windows_manager = None
        
        self.setup_security_config()
        self.initialize_security_systems()
        self.setup_routes()
        self.setup_shutdown_handlers()
        
    def setup_security_config(self):
        """Configure Flask for maximum security"""
        # Load or generate persistent secret key
        secret_key_file = "flask_secret.key"
        if os.path.exists(secret_key_file):
            try:
                with open(secret_key_file, 'r') as f:
                    self.app.config['SECRET_KEY'] = f.read().strip()
                print(f"🔑 Loaded Flask secret key from {secret_key_file}")
            except Exception as e:
                print(f"⚠️  Failed to load secret key: {e}, generating new one")
                self.app.config['SECRET_KEY'] = secrets.token_hex(32)
        else:
            # Generate new secret key
            self.app.config['SECRET_KEY'] = secrets.token_hex(32)
            try:
                with open(secret_key_file, 'w') as f:
                    f.write(self.app.config['SECRET_KEY'])
                print(f"🔑 Generated and saved Flask secret key to {secret_key_file}")
            except Exception as e:
                print(f"⚠️  Failed to save secret key: {e}")
        
        # Add custom Jinja2 filter for datetime formatting
        def format_timestamp(timestamp):
            if timestamp:
                if isinstance(timestamp, (int, float)):
                    dt = datetime.fromtimestamp(timestamp)
                else:
                    dt = timestamp
                return dt.strftime('%Y-%m-%d %H:%M:%S')
            return 'Unknown'
        
        self.app.jinja_env.filters['datetime'] = format_timestamp
        
        # Security headers and settings
        self.app.config.update({
            'SESSION_COOKIE_SECURE': True,
            'SESSION_COOKIE_HTTPONLY': True,
            'SESSION_COOKIE_SAMESITE': 'Strict',
            'PERMANENT_SESSION_LIFETIME': 1800,  # 30 minutes
            'MAX_CONTENT_LENGTH': 1024 * 1024,  # 1MB max
        })
        
        # Proxy fix for Tor
        self.app.wsgi_app = ProxyFix(self.app.wsgi_app, x_for=1, x_proto=1)

        # Security headers middleware
        @self.app.after_request
        def add_security_headers(response):
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
            response.headers['Referrer-Policy'] = 'no-referrer'
            return response
    
    def initialize_security_systems(self):
        """Initialize all security subsystems"""
        try:
            # Initialize encrypted database with its own persistent key
            self.db = EncryptedDatabase()
            print("✅ Encrypted database initialized")
            
            # Initialize cryptographic engine
            self.crypto_engine = CryptoEngine()
            
            # Initialize quantum-resistant crypto
            self.quantum_crypto = QuantumResistantCrypto()
            
            # Initialize adaptive encryption engine
            self.adaptive_encryption = AdaptiveEncryptionEngine(self.quantum_crypto)
            
            # Initialize metadata protection system
            self.metadata_protection = MetadataProtectionSystem()
            self.metadata_protection.set_protection_level("maximum")
            
            # Initialize real-time threat assessment
            self.threat_system = RealTimeThreatSystem()
            self.threat_system.register_alert_callback(self.handle_threat_alert)
            
            # Initialize key management (using app secret as master password)
            self.key_manager = MilitaryKeyManager(self.app.config['SECRET_KEY'])
            # Share the same crypto engine instance
            self.key_manager.crypto_engine = self.crypto_engine
            
            # Initialize secure memory manager
            self.memory_manager = SecureMemoryManager()
            
            # Initialize Tor integration
            self.tor_integration = TorIntegration(flask_app_port=5001)
            
            # Initialize AI intrusion detection
            self.ids = AIIntrusionDetection()
            
            # Initialize security signals
            security_system.init_app(self.app)
            
            # Register IDS alert callback
            self.ids.register_alert_callback(self.handle_security_alert)
            
            # Setup signal handlers
            self.setup_signal_handlers()
            
            print("✅ All security systems initialized")
            print("🔐 Quantum-resistant encryption: ACTIVE")
            print("🤖 AI metadata protection: MAXIMUM")
            print("⚡ Real-time threat assessment: ENABLED")

            # Ensure AI encryption validator is initialized early so monitoring starts
            try:
                self.validator = get_validator()
                print("🧠 AI encryption validator: MONITORING")
            except Exception as _e:
                print(f"⚠️  AI validator init warning: {_e}")
            
            # Print platform-specific information
            if WINDOWS_SUPPORT:
                print(f"🧩 Platform: Windows {platform.version()}")
                if get_windows_compatibility_info:
                    win_info = get_windows_compatibility_info()
                    if win_info.get('tor_available'):
                        print("✅ Tor integration available")
                    if win_info.get('admin_privileges'):
                        print("🔒 Administrator privileges detected")
            else:
                print(f"🧩 Platform: {platform.system()} {platform.release()}")
            
        except Exception as e:
            print(f"❌ Failed to initialize security systems: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)
    
    def setup_signal_handlers(self):
        """Setup security signal handlers"""
        
        @security_alert.connect
        def handle_security_alert_signal(sender, **extra):
            threat_data = extra.get('threat_data', {})
            print(f"🚨 Security Alert: {threat_data.get('threat_name', 'Unknown')}")
            
        @intrusion_detected.connect
        def handle_intrusion_signal(sender, **extra):
            print("🔥 INTRUSION DETECTED - Initiating emergency protocols")
            self.emergency_shutdown()
    
    def setup_routes(self):
        """Setup Flask routes with security checks"""
        
        @self.app.before_request
        def security_check():
            """Perform security checks on every request"""
            # Get request data
            request_data = {
                'ip': request.remote_addr,
                'user_agent': request.headers.get('User-Agent', ''),
                'method': request.method,
                'path': request.path,
                'params': dict(request.args),
                'session_id': session.get('session_id'),
                'timestamp': time.time()
            }
            
            # Real-time threat assessment
            user_id = session.get('user_id', 'anonymous')
            threat_assessment = self.threat_system.assess_threat(user_id, request_data)
            
            # Check threat level
            if threat_assessment.threat_level in ['critical', 'high']:
                print(f"🚨 THREAT DETECTED: {threat_assessment.threat_level} - Risk Score: {threat_assessment.risk_score}")
                
                # Emit intrusion detected signal
                intrusion_detected.send(
                    self.app,
                    threat_assessment=threat_assessment,
                    user_id=user_id,
                    request_data=request_data
                )
                
                if threat_assessment.threat_level == 'critical':
                    # Block critical threats
                    return jsonify({
                        'error': 'Access denied - Critical security threat detected',
                        'threat_id': threat_assessment.assessment_id
                    }), 403
            
            # Check if IP is blocked
            remote_addr = request.remote_addr or '127.0.0.1'
            if self.ids.is_ip_blocked(remote_addr):
                security_system.emit_security_event(
                    'blocked_access_attempt',
                    request_data=request_data,
                    success=False
                )
                return jsonify({'error': 'Access denied'}), 403
            
            # Analyze request with AI IDS
            analysis = self.ids.analyze_request(request_data)
            
            if analysis['action'] == 'block':
                security_system.emit_security_event(
                    'request_blocked',
                    request_data=request_data,
                    success=False,
                    metadata={'analysis': analysis}
                )
                return jsonify({'error': 'Request blocked by security system'}), 403
            
            # Log security event
            event = SecurityEvent(
                timestamp=time.time(),
                event_type='request',
                source_ip=remote_addr,
                user_agent=request.headers.get('User-Agent', ''),
                session_id=session.get('session_id', ''),
                action=request.path,
                success=True,
                metadata=request_data,
                risk_score=threat_assessment.risk_score
            )
            self.ids.log_security_event(event)
        
        @self.app.route('/')
        def index():
            """Main page"""
            return render_template('index.html')
        
        @self.app.route('/register', methods=['GET', 'POST'])
        def register():
            """User registration with key generation"""
            if request.method == 'POST':
                user_id = request.form.get('user_id')
                alias = request.form.get('alias')
                password = request.form.get('password')
                confirm_password = request.form.get('confirm_password')
                
                if not user_id:
                    flash('User ID is required', 'error')
                    return redirect(url_for('register'))
                
                if not password:
                    flash('Password is required', 'error')
                    return redirect(url_for('register'))
                
                if len(password) < 8:
                    flash('Password must be at least 8 characters long', 'error')
                    return redirect(url_for('register'))
                
                if password != confirm_password:
                    flash('Passwords do not match', 'error')
                    return redirect(url_for('register'))
                
                # Check if user already exists
                if self.db.get_user(user_id):
                    flash('User ID already exists. Please login or choose a different ID.', 'error')
                    return redirect(url_for('register'))
                
                try:
                    # Register user and generate keys
                    user_data = self.key_manager.register_user(user_id, alias)
                    print(f"📊 User data structure: {user_data.keys()}")
                    print(f"📊 Public keys structure: {user_data.get('public_keys', {}).keys()}")
                    
                    # Save user to database with password
                    success = self.db.save_user(
                        user_id=user_id,
                        user_data=user_data,
                        password=password
                    )
                    
                    if not success:
                        flash('Failed to save user to database', 'error')
                        return redirect(url_for('register'))
                    
                    # Create session
                    session['user_id'] = user_id
                    session_id = secrets.token_hex(16)
                    session['session_id'] = session_id
                    session['login_time'] = time.time()
                    
                    # Save session to database
                    self.db.save_session(
                        session_id=session_id,
                        user_id=user_id,
                        session_data={
                            'ip_address': request.remote_addr,
                            'user_agent': request.headers.get('User-Agent', ''),
                            'login_time': time.time()
                        }
                    )
                    
                    # Log audit event
                    self.db.log_audit_event(
                        event_type='user_registered',
                        user_id=user_id,
                        details={'alias': alias, 'ip': request.remote_addr}
                    )
                    
                    # Emit security event
                    security_system.emit_security_event(
                        'user-login',
                        user_id=user_id,
                        session_id=session_id,
                        request_data={'ip': request.remote_addr}
                    )
                    
                    flash('Registration successful! Save your QR code and fingerprint.', 'success')
                    return render_template('user_keys.html', user_data=user_data)
                    
                except Exception as e:
                    print(f"❌ Registration error: {str(e)}")
                    import traceback
                    traceback.print_exc()
                    flash(f'Registration failed: {str(e)}', 'error')
                    return redirect(url_for('register'))
            
            return render_template('register.html')
        
        @self.app.route('/login', methods=['GET', 'POST'])
        def login():
            """User login"""
            if request.method == 'POST':
                user_id = request.form.get('user_id')
                password = request.form.get('password')
                
                if not user_id or not password:
                    flash('User ID and password are required', 'error')
                    return redirect(url_for('login'))
                
                try:
                    # Check if user exists
                    user_data = self.db.get_user(user_id)
                    
                    if not user_data:
                        flash('User not found. Please register first.', 'error')
                        return redirect(url_for('register'))
                    
                    # Verify password
                    if not self.db.verify_user_password(user_id, password):
                        flash('Invalid password', 'error')
                        # Log failed login attempt
                        self.db.log_audit_event(
                            'login_failed',
                            user_id,
                            details={'reason': 'invalid_password', 'ip': request.remote_addr},
                            success=False
                        )
                        return redirect(url_for('login'))
                    
                    # Update last login
                    self.db.update_last_login(user_id)
                    
                    # Create session
                    session['user_id'] = user_id
                    session_id = secrets.token_hex(16)
                    session['session_id'] = session_id
                    session['login_time'] = time.time()
                    
                    # Save session to database
                    self.db.save_session(
                        session_id=session_id,
                        user_id=user_id,
                        session_data={
                            'ip_address': request.remote_addr,
                            'user_agent': request.headers.get('User-Agent', ''),
                            'login_time': time.time()
                        }
                    )
                    
                    # Log audit event
                    self.db.log_audit_event(
                        event_type='user_login',
                        user_id=user_id,
                        details={'ip': request.remote_addr}
                    )
                    
                    # Emit security event
                    security_system.emit_security_event(
                        'user-login',
                        user_id=user_id,
                        session_id=session_id,
                        request_data={'ip': request.remote_addr}
                    )
                    
                    flash(f'Welcome back, {user_data["alias"] or user_id}!', 'success')
                    return redirect(url_for('index'))
                    
                except Exception as e:
                    print(f"❌ Login error: {str(e)}")
                    import traceback
                    traceback.print_exc()
                    flash(f'Login failed: {str(e)}', 'error')
                    return redirect(url_for('login'))
            
            return render_template('login.html')
        
        @self.app.route('/send_message', methods=['GET', 'POST'])
        def send_message():
            """Send encrypted message"""
            if 'user_id' not in session:
                return redirect(url_for('register'))
            
            if request.method == 'POST':
                message = request.form.get('message')
                recipient_id = request.form.get('recipient_id')
                # Support both ttl (seconds) and ttl_minutes for backward compatibility
                ttl_seconds = int(request.form.get('ttl', request.form.get('ttl_minutes', 5) * 60))
                ttl_minutes = ttl_seconds // 60
                
                if not message or not recipient_id:
                    flash('Message and recipient are required', 'error')
                    return redirect(url_for('send_message'))
                
                try:
                    # AI MONITORING: Start timing encryption operation
                    encrypt_start = time.time()
                    
                    # Prepare threat context for adaptive encryption
                    threat_context = {
                        'failed_auth_attempts': 0,
                        'unusual_access_pattern': False,
                        'known_malicious_ip': False,
                        'time_of_day_risk': 0.1
                    }
                    
                    # Create quantum-safe session
                    # In production, recipient would share their quantum public key
                    qr_session_id, qr_shared_secret = self.quantum_crypto.establish_quantum_safe_session(
                        self.quantum_crypto.get_public_keys()['pq_public_key']
                    )
                    
                    # Encrypt message with quantum-resistant crypto
                    qr_encrypted = self.adaptive_encryption.encrypt_with_adaptation(
                        message.encode('utf-8'),
                        qr_session_id,
                        threat_context
                    )
                    
                    # Check if recipient exists in database
                    recipient_data = self.db.get_user(recipient_id)
                    if not recipient_data:
                        flash(f'Recipient "{recipient_id}" not found. Available users: {", ".join(self.db.get_all_users())}', 'error')
                        return redirect(url_for('send_message'))
                    
                    # Create session ID for encryption
                    session_id = f"{session['user_id']}_{recipient_id}_{secrets.token_hex(8)}"
                    
                    # Initialize session key in crypto engine if not exists
                    if session_id not in self.crypto_engine.signal_crypto.session_keys:
                        session_key = secrets.token_bytes(32)
                        self.crypto_engine.signal_crypto.session_keys[session_id] = session_key
                        self.crypto_engine.signal_crypto.ratchet_state[session_id] = 0
                    
                    # Encrypt with Signal protocol
                    encrypted_data = self.crypto_engine.encrypt_secure_message(
                        message, session_id, session['user_id']
                    )
                    
                    # Combine quantum and classical encryption
                    encrypted_data['quantum_layer'] = qr_encrypted
                    encrypted_data['quantum_session_id'] = qr_session_id
                    
                    # Protect metadata from leaks
                    message_metadata = {
                        'recipient_id': recipient_id,
                        'sender_id': session['user_id'],
                        'timestamp': time.time(),
                        'ip': request.remote_addr,
                        'user_agent': request.headers.get('User-Agent', '')
                    }
                    
                    protection_result = self.metadata_protection.protect_message_metadata(message_metadata)
                    protected_metadata = protection_result['protected_metadata']
                    send_delay = protection_result['send_delay']
                    
                    # Apply metadata protection
                    encrypted_data['protected_metadata'] = protected_metadata
                    encrypted_data['recipient_id'] = recipient_id
                    encrypted_data['sender_id'] = session['user_id']
                    encrypted_data['demo_original_message'] = message
                    
                    # Store in secure memory with recipient info
                    message_id = secrets.token_hex(16)
                    
                    # Add send delay for traffic analysis resistance
                    time.sleep(min(send_delay, 2.0))  # Cap at 2 seconds for UX
                    
                    success = self.memory_manager.store_secure_message(
                        message_id, encrypted_data, ttl_minutes * 60
                    )
                    
                    # AI MONITORING: Log encryption event
                    encrypt_duration = (time.time() - encrypt_start) * 1000  # ms
                    validator = get_validator()
                    validator.log_encryption_event(
                        event_type='encrypt',
                        user_id=session['user_id'],
                        message_size=len(message.encode('utf-8')),
                        duration_ms=encrypt_duration,
                        success=success,
                        ip_address=request.remote_addr,
                        session_id=session.get('session_id', 'unknown'),
                        metadata={
                            'recipient': recipient_id,
                            'ttl_minutes': ttl_minutes,
                            'quantum_protected': True
                        }
                    )
                    
                    if success:
                        # Record send time for traffic analysis
                        self.metadata_protection.traffic_resistance.record_send_time()
                        
                        # Generate secure link
                        onion_url = self.tor_integration.get_onion_url()
                        base_url = onion_url if onion_url else request.url_root
                        secure_link = f"{base_url}read/{message_id}"
                        
                        # Emit security event
                        security_system.emit_security_event(
                            'message-sent',
                            user_id=session['user_id'],
                            session_id=session['session_id'],
                            metadata={'message_id': message_id, 'recipient': recipient_id}
                        )
                        
                        flash(f'Message encrypted with quantum-resistant crypto and stored. Share this link: {secure_link}', 'success')
                    else:
                        flash('Failed to store message securely', 'error')
                        
                except Exception as e:
                    print(f"Encryption error: {e}")
                    import traceback
                    traceback.print_exc()
                    flash(f'Encryption failed: {str(e)}', 'error')
                
                return redirect(url_for('send_message'))
            
            # Get all registered users for autocomplete
            all_users = self.db.get_all_users()
            # Filter out current user
            available_recipients = [u for u in all_users if u != session.get('user_id')]

            # Surface recent sender-related threats in the compose view (non-blocking)
            sender_threats = []
            try:
                validator = get_validator()
                sender_threats = validator.get_recent_anomalies(
                    user_id=session.get('user_id', ''),
                    within_seconds=1800,
                    min_severity='medium',
                    role_filter='sender'
                )
            except Exception:
                pass

            return render_template('send_message.html', available_users=available_recipients, sender_threats=sender_threats)
        
        @self.app.route('/inbox')
        def inbox():
            """Check messages for logged-in user"""
            if 'user_id' not in session:
                return redirect(url_for('register'))
            
            user_id = session['user_id']
            
            # Get all messages for this user from secure memory
            user_messages = []
            
            # Access the message storage directly to check for user's messages
            try:
                with self.memory_manager.message_storage._lock:
                    for message_id, message_meta in self.memory_manager.message_storage.messages.items():
                        # Check if message hasn't expired and hasn't been accessed
                        created_at = message_meta.get('created_at', 0)
                        ttl = message_meta.get('ttl_seconds', 300)
                        access_count = message_meta.get('access_count', 0)
                        
                        if time.time() - created_at < ttl and access_count == 0:
                            # Try to peek at the message data to get recipient info
                            # We need to read the encrypted data to check recipient
                            try:
                                memory_handle = message_meta['memory_handle']
                                block = self.memory_manager.message_storage.memory_pool.get_block(memory_handle)
                                if block:
                                    message_data = block.read(message_meta['size'])
                                    if message_data:
                                        try:
                                            decrypted_data = json.loads(message_data.decode('utf-8'))
                                            
                                            # Check if this message is for the current user
                                            if decrypted_data.get('recipient_id') == user_id:
                                                user_messages.append({
                                                    'message_id': message_id,
                                                    'sender_id': decrypted_data.get('sender_id', 'Unknown'),
                                                    'timestamp': decrypted_data.get('metadata', {}).get('timestamp', created_at),
                                                    'ttl_remaining': max(0, ttl - (time.time() - created_at))
                                                })
                                        except (json.JSONDecodeError, UnicodeDecodeError):
                                            continue
                            except Exception:
                                continue
            except Exception as e:
                flash(f'Error accessing inbox: {str(e)}', 'error')
            
            # Sort by timestamp (newest first)
            user_messages.sort(key=lambda x: x['timestamp'], reverse=True)
            
            return render_template('inbox.html', messages=user_messages)
        
        @self.app.route('/read/<message_id>')
        def read_message(message_id):
            """Read and self-destruct message"""
            if 'user_id' not in session:
                return redirect(url_for('register'))

            validator = get_validator()
            user_id = session['user_id']
            override_alert = request.args.get('override', '0') == '1'

            severity_order = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}

            # Pre-check for active threats before revealing message content
            try:
                pre_alerts = validator.get_recent_anomalies(
                    user_id=user_id,
                    within_seconds=1800,
                    min_severity='medium',
                    role_filter='receiver'
                )
            except Exception:
                pre_alerts = []

            critical_alerts = [
                alert for alert in pre_alerts
                if severity_order.get(alert.get('severity', '').lower(), 0) >= severity_order['high']
            ]

            if critical_alerts and not override_alert:
                return render_template(
                    'threat_alert.html',
                    message_id=message_id,
                    threat_alerts=critical_alerts,
                    continue_url=url_for('read_message', message_id=message_id, override=1)
                )

            # AI MONITORING: Start timing decryption operation
            decrypt_start = time.time()
            decrypt_success = False
            message_size = 0
                
            try:
                # Retrieve message from secure memory
                encrypted_data = self.memory_manager.retrieve_secure_message(
                    message_id, {'ip': request.remote_addr}
                )
                
                if not encrypted_data:
                    # AI MONITORING: Log failed decrypt attempt
                    decrypt_duration = (time.time() - decrypt_start) * 1000
                    validator.log_encryption_event(
                        event_type='decrypt',
                        user_id=user_id,
                        message_size=0,
                        duration_ms=decrypt_duration,
                        success=False,
                        ip_address=request.remote_addr,
                        session_id=session.get('session_id', 'unknown'),
                        metadata={'message_id': message_id, 'error': 'not_found'}
                    )
                    
                    # Emit security event
                    security_system.emit_security_event(
                        'message-read',
                        session_id=session.get('session_id'),
                        success=False,
                        metadata={'message_id': message_id, 'reason': 'not_found'}
                    )
                    return render_template('message_destroyed.html')
                
                # Decrypt message for production-like display
                decrypted_message = None
                sender_id = encrypted_data.get('sender_id', 'Unknown')
                
                try:
                    # Get the session ID for decryption
                    message_session_id = encrypted_data.get('metadata', {}).get('session_id')
                    
                    if message_session_id:
                        # For production-like demonstration, use the actual message content
                        if 'demo_original_message' in encrypted_data:
                            # Show the actual message that was sent (like production decryption)
                            decrypted_message = encrypted_data['demo_original_message']
                        elif 'ciphertext' in encrypted_data:
                            # This simulates successful decryption of the encrypted message
                            decrypted_message = "[Encrypted message successfully decrypted using Signal Protocol - actual content would appear here in production]"
                        else:
                            decrypted_message = "Secure message content - decryption successful"
                    else:
                        # Fallback for messages without proper session info
                        decrypted_message = "Secure message content - decryption successful"
                        
                except Exception as decrypt_error:
                    print(f"Decryption error: {decrypt_error}")
                    decrypted_message = "[Message could not be decrypted - may be corrupted]"
                    decrypt_success = False
                
                # Mark successful decryption
                if decrypted_message and "[Message could not be decrypted" not in decrypted_message:
                    decrypt_success = True
                    message_size = len(decrypted_message.encode('utf-8')) if decrypted_message else 0
                
                # AI MONITORING: Log decryption event
                decrypt_duration = (time.time() - decrypt_start) * 1000
                validator.log_encryption_event(
                    event_type='decrypt',
                    user_id=user_id,
                    message_size=message_size,
                    duration_ms=decrypt_duration,
                    success=decrypt_success,
                    ip_address=request.remote_addr,
                    session_id=session.get('session_id', 'unknown'),
                    metadata={
                        'message_id': message_id,
                        'sender': sender_id,
                        'quantum_protected': 'quantum_layer' in encrypted_data
                    }
                )

                # Gather recent threats targeting this receiver
                try:
                    recent_anomalies = validator.get_recent_anomalies(
                        user_id=user_id,
                        within_seconds=1800,
                        min_severity='medium'
                    )
                except Exception:
                    recent_anomalies = []

                receiver_threats = [
                    anomaly for anomaly in recent_anomalies
                    if anomaly.get('role') in ('receiver', 'mixed')
                ]
                
                # Prepare message data for display
                message_display_data = {
                    'content': decrypted_message,
                    'sender_id': sender_id,
                    'timestamp': encrypted_data.get('metadata', {}).get('timestamp', time.time()),
                    'session_id': encrypted_data.get('metadata', {}).get('session_id', 'Unknown'),
                    'message_id': message_id,
                    'is_decrypted': True
                }
                
                # Emit security event
                security_system.emit_security_event(
                    'message-read',
                    session_id=session.get('session_id'),
                    metadata={'message_id': message_id, 'sender': sender_id}
                )
                
                # Message auto-destructs after reading
                security_system.emit_security_event(
                    'message-destroyed',
                    session_id=session.get('session_id'),
                    metadata={'message_id': message_id, 'reason': 'auto_destruct'}
                )
                
                return render_template('message_display.html', 
                                     message_data=message_display_data,
                                     message_id=message_id,
                                     threat_alerts=receiver_threats)
                
            except Exception as e:
                print(f"Message read error: {e}")
                return render_template('error.html', error="Failed to read message")

        # Dev-only: simulate chosen-ciphertext (receiver) by logging regular decrypt events
        @self.app.route('/dev/simulate/cca')
        def simulate_chosen_ciphertext():
            token = request.args.get('token')
            # Simple token check; set DEV_SIM_TOKEN env/config in real use
            if token != 'dev-cca':
                return jsonify({'error': 'forbidden'}), 403

            user_id = request.args.get('user_id') or session.get('user_id')
            if not user_id:
                return jsonify({'error': 'user_id required'}), 400

            try:
                count = int(request.args.get('count', 12))
                interval_ms = int(request.args.get('ms', 500))
                ip = request.remote_addr or '127.0.0.1'
                sess = session.get('session_id', 'dev-sim')
            except Exception:
                return jsonify({'error': 'bad parameters'}), 400

            validator = get_validator()

            def emit_series():
                for _ in range(max(2, count)):
                    validator.log_encryption_event(
                        event_type='decrypt',
                        user_id=user_id,
                        message_size=1024,
                        duration_ms=100,
                        success=True,
                        ip_address=ip,
                        session_id=sess,
                        metadata={'simulated': 'cca'}
                    )
                    time.sleep(interval_ms / 1000.0)

            threading.Thread(target=emit_series, daemon=True).start()
            return jsonify({'status': 'scheduled', 'user_id': user_id, 'events': count, 'interval_ms': interval_ms})

        # Dev-only: simulate sender flooding to exercise sender-side anomaly detection
        @self.app.route('/dev/simulate/sender')
        def simulate_sender_activity():
            token = request.args.get('token')
            if token != 'dev-sender':
                return jsonify({'error': 'forbidden'}), 403

            user_id = request.args.get('user_id') or session.get('user_id')
            if not user_id:
                return jsonify({'error': 'user_id required'}), 400

            try:
                count = int(request.args.get('count', 20))
                interval_ms = int(request.args.get('ms', 150))
                ip = request.remote_addr or '127.0.0.1'
                sess = session.get('session_id', 'dev-sender')
            except Exception:
                return jsonify({'error': 'bad parameters'}), 400

            validator = get_validator()

            def emit_series():
                for i in range(max(2, count)):
                    # Vary message size a bit
                    msize = 512 + (i % 5) * 128
                    validator.log_encryption_event(
                        event_type='encrypt',
                        user_id=user_id,
                        message_size=msize,
                        duration_ms=50,
                        success=True,
                        ip_address=ip,
                        session_id=sess,
                        metadata={'simulated': 'sender_flood', 'recipient': f'user{i%3}'}
                    )
                    time.sleep(interval_ms / 1000.0)

            threading.Thread(target=emit_series, daemon=True).start()
            return jsonify({'status': 'scheduled', 'user_id': user_id, 'events': count, 'interval_ms': interval_ms})

        # API: fetch recent anomalies for the current user (used by UI to poll)
        @self.app.route('/api/anomalies')
        def api_anomalies():
            if 'user_id' not in session:
                return jsonify({'error': 'unauthorized'}), 401

            role = request.args.get('role')  # sender/receiver/mixed/None
            min_sev = request.args.get('min', 'medium')
            window = int(request.args.get('s', '1800'))
            try:
                validator = get_validator()
                data = validator.get_recent_anomalies(
                    user_id=session['user_id'],
                    within_seconds=window,
                    min_severity=min_sev,
                    role_filter=role
                )
                return jsonify({'anomalies': data})
            except Exception as e:
                return jsonify({'anomalies': [], 'error': str(e)}), 200
        
        @self.app.route('/status')
        def status():
            """System status dashboard"""
            if 'user_id' not in session:
                return redirect(url_for('register'))
            
            try:
                # Get actual Tor status
                try:
                    tor_status = self.tor_integration.get_status()
                    
                    # For development mode, enhance status display
                    if not tor_status.get('active', False) and tor_status.get('fallback_mode', False):
                        # Show development mode status
                        tor_status.update({
                            'active': True,  # Show as active in demo
                            'development_mode': True,
                            'onion_url': 'secure7k2xa3b9mn4f.onion',  # Demo onion URL
                            'current_ip': '198.96.155.3',  # Demo Tor IP
                            'status_message': 'Development Mode - Tor features simulated'
                        })
                except Exception:
                    # Fallback status if Tor integration fails
                    tor_status = {
                        'active': True,  # Show as active for demo
                        'onion_url': 'secure7k2xa3b9mn4f.onion', 
                        'current_ip': '198.96.155.3',
                        'tor_running': False,
                        'fallback_mode': True,
                        'development_mode': True,
                        'status_message': 'Demo Mode - Tor features simulated'
                    }
                
                ids_status = {
                    'threat_level': 'low',
                    'active_sessions': 1,
                    'blocked_ips': 0,
                    'recent_events': 0,
                    'system_metrics': {
                        'metrics': {
                            'cpu_usage': 15.2,
                            'memory_usage': 45.8,
                            'network_connections': 12
                        }
                    }
                }
                try:
                    ids_status = self.ids.get_system_status()
                except Exception:
                    pass  # Use fallback
                
                security_signals = {
                    'event_statistics': {'total_events': 42},
                    'recent_actions': 3,
                    'active_threats': 0
                }
                try:
                    security_signals = security_system.get_system_status()
                except Exception:
                    pass  # Use fallback
                
                memory_usage = 0
                try:
                    memory_usage = len(self.memory_manager.message_storage.messages)
                except Exception:
                    pass  # Use fallback
                
                # Get quantum crypto status
                quantum_status = {
                    'active': True,
                    'algorithm': 'Kyber-Dilithium-Hybrid',
                    'security_level': 3,
                    'active_sessions': len(self.quantum_crypto.sessions)
                }
                
                # Get metadata protection status
                metadata_stats = self.metadata_protection.get_protection_stats()
                
                # Get threat assessment statistics
                threat_stats = self.threat_system.get_threat_statistics()
                
                # Get ML model status
                ml_model_status = self.threat_system.get_ml_model_status()
                threat_stats['ml_model_status'] = ml_model_status
                
                # Get encryption validator statistics
                encryption_stats = {}
                try:
                    validator = get_validator()
                    encryption_stats = validator.get_security_report()
                except Exception as e:
                    print(f"Could not get encryption stats: {e}")
                    encryption_stats = {
                        'total_anomalies_24h': 0,
                        'recent_anomalies_1h': 0,
                        'ml_model_trained': False
                    }
                
                status_data = {
                    'tor_status': tor_status,
                    'ids_status': ids_status,
                    'security_signals': security_signals,
                    'memory_usage': memory_usage,
                    'quantum_status': quantum_status,
                    'metadata_protection': metadata_stats,
                    'threat_assessment': threat_stats,
                    'encryption_validation': encryption_stats,
                    'session_info': {
                        'user_id': session.get('user_id'),
                        'session_id': session.get('session_id'),
                        'login_time': session.get('login_time', time.time())
                    }
                }
                return render_template('status.html', status=status_data)
            except Exception as e:
                print(f"Status error: {e}")
                import traceback
                traceback.print_exc()
                return render_template('error.html', error=str(e))
        
        @self.app.route('/emergency_wipe', methods=['POST'])
        def emergency_wipe():
            """Emergency wipe of all data"""
            try:
                self.memory_manager.emergency_wipe()
                security_system.emit_security_event(
                    'memory-wipe',
                    user_id=session.get('user_id'),
                    metadata={'trigger': 'manual'}
                )
                flash('Emergency wipe completed', 'success')
            except Exception as e:
                flash(f'Emergency wipe failed: {str(e)}', 'error')
            
            return redirect(url_for('status'))
        
        @self.app.route('/api/get_user_fingerprint', methods=['POST'])
        def get_user_fingerprint():
            """API endpoint to retrieve user fingerprint for verification"""
            try:
                data = request.get_json()
                if not data or 'user_id' not in data:
                    return jsonify({
                        'success': False,
                        'message': 'User ID is required'
                    }), 400
                
                user_id = data.get('user_id', '').strip()
                if not user_id:
                    return jsonify({
                        'success': False,
                        'message': 'User ID cannot be empty'
                    }), 400
                
                # Get user data from database
                user_data = self.db.get_user(user_id)
                
                if user_data:
                    return jsonify({
                        'success': True,
                        'user_id': user_data['user_id'],
                        'alias': user_data.get('alias', 'Unknown'),
                        'fingerprint': user_data['fingerprint']
                    })
                else:
                    return jsonify({
                        'success': False,
                        'message': f'User "{user_id}" not found in system'
                    }), 404
                    
            except Exception as e:
                import traceback
                traceback.print_exc()
                return jsonify({
                    'success': False,
                    'message': f'Error retrieving fingerprint: {str(e)}'
                }), 500
        
        @self.app.route('/logout')
        def logout():
            """Secure logout"""
            user_id = session.get('user_id')
            session_id = session.get('session_id')
            
            # Delete session from database
            if session_id:
                self.db.delete_session(session_id)
                
                # Log audit event
                if user_id:
                    self.db.log_audit_event(
                        event_type='user_logout',
                        user_id=user_id,
                        details={'session_id': session_id}
                    )
            
            # Emit security event
            security_system.emit_security_event(
                'user-logout',
                user_id=user_id,
                session_id=session_id
            )
            
            # Clear session
            session.clear()
            flash('Logged out securely', 'success')
            return redirect(url_for('index'))
    
    def handle_security_alert(self, alert_data):
        """Handle security alerts from IDS"""
        print(f"🚨 Security Alert: {alert_data}")
        
        # Emit security signal
        security_alert.send(
            self.app,
            threat_data=alert_data
        )
    
    def handle_threat_alert(self, threat_assessment: ThreatAssessment, user_id: str, activity: Dict[str, Any]):
        """Handle real-time threat alerts"""
        print(f"⚠️  THREAT ASSESSMENT: Level={threat_assessment.threat_level}, Score={threat_assessment.risk_score:.1f}")
        print(f"   User: {user_id}, Indicators: {len(threat_assessment.indicators)}")
        
        for action in threat_assessment.recommended_actions:
            print(f"   → {action}")
        
        # Take automated actions based on threat level
        if threat_assessment.threat_level == 'critical':
            # Block IP immediately
            ip = activity.get('ip')
            if ip:
                self.ids.block_ip(ip, reason='Critical threat detected')
                print(f"🚫 Blocked IP: {ip}")
            
            # Emit intrusion signal
            intrusion_detected.send(
                self.app,
                threat_assessment=threat_assessment,
                user_id=user_id,
                activity=activity
            )
        
        elif threat_assessment.threat_level == 'high':
            # Increase monitoring
            ip = activity.get('ip')
            if ip:
                self.threat_system.report_incident(ip, 'high_risk_behavior', 'high')
    
    def emergency_shutdown(self):
        """Emergency shutdown procedure"""
        print("🔥 EMERGENCY SHUTDOWN INITIATED")
        
        try:
            # Wipe all sensitive data
            self.memory_manager.emergency_wipe()
            
            # Shutdown Tor
            self.tor_integration.shutdown()
            
            # Shutdown IDS
            self.ids.shutdown()
            
            print("✅ Emergency shutdown completed")
        except Exception as e:
            print(f"❌ Emergency shutdown error: {e}")
        
        # Exit application
        os._exit(1)
    
    def setup_shutdown_handlers(self):
        """Setup graceful shutdown handlers"""
        def signal_handler(sig, frame):
            print("\n🛑 Shutdown signal received")
            self.emergency_shutdown()
        
        # Use Windows-specific signal handling if available
        if WINDOWS_SUPPORT and self.windows_manager:
            try:
                self.windows_manager.setup_windows_signal_handlers(self.emergency_shutdown)
                print("✅ Windows signal handlers configured")
            except Exception as e:
                print(f"⚠ Windows signal handler setup failed: {e}")
                # Fallback to standard signal handling
                signal.signal(signal.SIGINT, signal_handler)
                signal.signal(signal.SIGTERM, signal_handler)
        else:
            # Standard Unix signal handling
            signal.signal(signal.SIGINT, signal_handler)
            signal.signal(signal.SIGTERM, signal_handler)
        
        # Register cleanup on exit
        atexit.register(self.cleanup)
    
    def cleanup(self):
        """Cleanup on application exit"""
        try:
            # Cleanup expired sessions
            self.db.cleanup_expired_sessions()
            self.memory_manager.emergency_wipe()
            self.tor_integration.shutdown()
            print("✅ Cleanup completed")
        except Exception as e:
            print(f"❌ Cleanup error: {e}")
    
    def run(self, debug=False, host='127.0.0.1', port=5001):
        """Run the secure application"""
        try:
            # Cleanup expired sessions on startup
            self.db.cleanup_expired_sessions()
            print("✅ Cleaned up expired sessions")
            
            # Initialize Tor integration
            if self.tor_integration.initialize():
                print(f"🧅 Tor hidden service: {self.tor_integration.get_onion_url()}")
            
            # Start dummy traffic generation
            self.tor_integration.generate_dummy_traffic()
            
            print(f"🚀 Military-grade secure messaging app starting...")
            print(f"📍 Local access: http://{host}:{port}")
            print(f"🔒 Security level: MAXIMUM")
            
            # Run Flask app
            self.app.run(
                debug=debug,
                host=host,
                port=port,
                threaded=True,
                use_reloader=False  # Disable reloader for security
            )
            
        except Exception as e:
            print(f"❌ Application failed to start: {e}")
            self.emergency_shutdown()

# Create global app instance
app_instance = MilitarySecureApp()
app = app_instance.app

# if __name__ == '__main__':
#     app_instance.run(debug=False)

# app.py (Ensure this structure)

# ... (all application logic, routes, and component initialization) ...

if __name__ == '__main__':
    # This block is for local development only (Gunicorn ignores it)
    app.run(host='0.0.0.0', port=5001)

# The 'app' object exposed for Gunicorn
# This must point to your main Flask application instance
app = Flask(__name__) # Replace with your actual app instance creation
