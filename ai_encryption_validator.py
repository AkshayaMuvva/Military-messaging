"""
AI-Driven Encryption Validation and Anomaly Detection System

This module provides real-time monitoring of encryption processes and detects
anomalies that could indicate:
- Attempted decryption attacks
- Pattern analysis attacks
- Timing attacks
- Side-channel attacks
- Unusual encryption/decryption patterns
"""

import time
import threading
import hashlib
import secrets
import json
import numpy as np
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
import logging
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pickle
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class EncryptionEvent:
    """Represents an encryption/decryption event"""
    event_id: str
    timestamp: float
    event_type: str  # 'encrypt' or 'decrypt'
    user_id: str
    message_size: int
    duration_ms: float
    success: bool
    ip_address: str
    session_id: str
    metadata: Dict[str, Any]


@dataclass
class AnomalyDetection:
    """Detected anomaly in encryption patterns"""
    anomaly_id: str
    severity: str  # 'low', 'medium', 'high', 'critical'
    anomaly_type: str
    description: str
    detected_at: float
    user_id: str
    confidence: float  # 0.0 to 1.0
    indicators: List[str]
    recommended_action: str


class AIEncryptionValidator:
    """
    AI-driven encryption validator that monitors encryption operations
    and detects anomalies without user access
    """
    
    def __init__(self):
        self.encryption_events = deque(maxlen=10000)
        self.user_patterns = defaultdict(lambda: {
            'encrypt_times': deque(maxlen=100),
            'decrypt_times': deque(maxlen=100),
            'message_sizes': deque(maxlen=100),
            'failed_attempts': deque(maxlen=50),
            'timing_patterns': deque(maxlen=200),
        })
        self.anomalies = deque(maxlen=1000)
        self.threat_indicators = defaultdict(int)
        self.monitoring_active = False
        self.monitor_thread = None
        self.lock = threading.Lock()
        self._severity_order = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        # Action playbooks per anomaly type (high-level, non-technical guidance)
        self._playbooks = {
            'brute_force_attack_receiver': [
                'Temporarily lock message access and require 2FA for reads',
                'Notify the account owner via an alternate channel',
                'Enable rate limiting for decryption attempts',
                'Review access logs for repeated failed reads from same IPs'
            ],
            'credential_stuffing_receiver': [
                'Lock the account and force immediate password reset',
                'Invalidate all active sessions and access tokens',
                'Alert the security team and start an incident record',
                'Advise the user to check other accounts for reuse'
            ],
            'credential_stuffing_mixed': [
                'Force global logout and rotate credentials',
                'Enable step-up verification for next login',
                'Audit recent send and read history for abuse',
                'Block suspicious IP ranges temporarily'
            ],
            'chosen_ciphertext_attack_receiver': [
                'Introduce randomized delay on reads to break timing patterns',
                'Reduce read rate (e.g., 1 per minute) for the next hour',
                'Rotate receiver-side decryption keys',
                'Escalate to crypto team for side-channel review'
            ],
            'message_flooding_sender': [
                'Rate limit sending and require CAPTCHA',
                'Freeze bulk sending until manual review',
                'Scan recent recipients for spam complaints'
            ],
            'impossible_travel_receiver': [
                'Suspend message retrieval until ownership confirmed',
                'Require step-up verification',
                'Flag unfamiliar locations in account alerts'
            ],
            'impossible_travel_sender': [
                'Pause outgoing messages pending identity check',
                'Review sent items for impersonation',
                'Restrict sending to trusted regions temporarily'
            ],
            'impossible_travel_mixed': [
                'Lock account and force re-enrollment on trusted device',
                'Rotate keys and credentials',
                'Open an incident and monitor for lateral movement'
            ],
        }
        
        # ML Components - Isolation Forest for anomaly detection
        self.ml_model = None
        self.scaler = StandardScaler()
        self.model_trained = False
        # Lowered threshold so the ML model can train during demos/smaller test runs
        # Previously 100; now 30 to allow quicker bootstrapping
        self.min_samples_for_training = 30  # Minimum events before training
        self.model_path = 'ai_encryption_model.pkl'
        self.scaler_path = 'ai_encryption_scaler.pkl'
        
        # Baseline thresholds for anomaly detection
        self.thresholds = {
            'max_decrypt_attempts_per_min': 10,
            'max_failed_decrypts_per_hour': 5,
            'unusual_timing_variance': 0.5,  # 50% variance from baseline
            'rapid_succession_ms': 100,  # Messages within 100ms
            'pattern_repetition_threshold': 5,
            'session_duration_max_hours': 24,
        }
        
        # Load pre-trained model if exists
        self._load_model()
        
        logger.info("AI Encryption Validator initialized with ML anomaly detection")
    
    def start_monitoring(self):
        """Start background monitoring thread"""
        if not self.monitoring_active:
            self.monitoring_active = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            logger.info("Encryption monitoring started")
    
    def stop_monitoring(self):
        """Stop background monitoring"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        logger.info("Encryption monitoring stopped")
    
    def _monitor_loop(self):
        """Background monitoring loop"""
        iteration = 0
        while self.monitoring_active:
            try:
                # Rule-based detection (every iteration)
                self._analyze_recent_patterns()
                self._detect_timing_attacks()
                self._detect_pattern_attacks()
                self._cleanup_old_data()
                
                # ML-based detection (every 6 iterations = 30 seconds)
                iteration += 1
                if iteration % 6 == 0:
                    self._detect_ml_anomalies()
                
                # Retrain ML model (every 120 iterations = 10 minutes)
                if iteration % 120 == 0:
                    event_count = len(self.encryption_events)
                    if event_count >= self.min_samples_for_training:
                        self._train_ml_model()
                
                time.sleep(5)  # Check every 5 seconds
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
    
    def log_encryption_event(self, event_type: str, user_id: str, message_size: int,
                            duration_ms: float, success: bool, ip_address: str,
                            session_id: str, metadata: Optional[Dict] = None):
        """
        Log an encryption/decryption event for analysis
        This runs silently without user knowledge
        """
        event = EncryptionEvent(
            event_id=secrets.token_hex(16),
            timestamp=time.time(),
            event_type=event_type,
            user_id=user_id,
            message_size=message_size,
            duration_ms=duration_ms,
            success=success,
            ip_address=ip_address,
            session_id=session_id,
            metadata=metadata or {}
        )
        
        with self.lock:
            self.encryption_events.append(event)
            
            # Update user patterns
            profile = self.user_patterns[user_id]
            if event_type == 'encrypt':
                profile['encrypt_times'].append(event.timestamp)
            else:
                profile['decrypt_times'].append(event.timestamp)
            
            profile['message_sizes'].append(message_size)
            profile['timing_patterns'].append(duration_ms)
            
            if not success:
                profile['failed_attempts'].append(event.timestamp)
            
            # Track session changes for session hijacking detection
            if session_id not in profile.get('known_sessions', set()):
                if 'known_sessions' not in profile:
                    profile['known_sessions'] = set()
                profile['known_sessions'].add(session_id)
        
        # Real-time anomaly detection
        self._check_immediate_threats(event, user_id)
        self._check_session_anomalies(event, user_id)
        self._check_recipient_enumeration(event, user_id)
        self._check_message_interception(event, user_id)
    
    def _check_recipient_enumeration(self, event: EncryptionEvent, user_id: str):
        """Detect recipient enumeration attacks (SENDER-SPECIFIC)"""
        if event.event_type != 'encrypt':
            return
        
        current_time = time.time()
        profile = self.user_patterns[user_id]
        
        # Track recipients from metadata
        if 'recipients_tried' not in profile:
            profile['recipients_tried'] = deque(maxlen=100)
        
        recipient = event.metadata.get('recipient', 'unknown')
        if recipient != 'unknown':
            profile['recipients_tried'].append((current_time, recipient, event.success))
        
        # Check for rapid recipient probing (trying many different recipients)
        recent_attempts = [(t, r, s) for t, r, s in profile['recipients_tried'] 
                          if current_time - t < 300]  # Last 5 minutes
        
        if len(recent_attempts) > 10:
            unique_recipients = len(set(r for _, r, _ in recent_attempts))
            failed_recipients = sum(1 for _, _, s in recent_attempts if not s)
            
            if unique_recipients > 5:  # Trying many different recipients
                self._create_anomaly(
                    user_id=user_id,
                    severity='high',
                    anomaly_type='recipient_enumeration_sender',
                    description=f"🔍 SENDER ATTACK - RECIPIENT ENUMERATION: Probing {unique_recipients} different recipients in 5 minutes (attack type: User discovery)",
                    confidence=0.85,
                    indicators=[
                        f"👤 Role: SENDER (sending to multiple recipients)",
                        f"📤 Different recipients contacted: {unique_recipients}",
                        f"❌ Failed deliveries: {failed_recipients}",
                        "🎯 Attack pattern: Discovering valid user accounts",
                        "🔍 Method: Systematic probing of usernames/IDs",
                        "📍 Risk: Privacy violation, account discovery, targeted attacks"
                    ],
                    recommended_action="🛡️ SENDER ACTION: Implement CAPTCHA after 3 different recipients, rate limit recipient testing, require email verification for new contacts, monitor for pattern abuse"
                )
    
    def _check_message_interception(self, event: EncryptionEvent, user_id: str):
        """Detect message interception attempts (RECEIVER-SPECIFIC)"""
        if event.event_type != 'decrypt':
            return
        
        current_time = time.time()
        profile = self.user_patterns[user_id]
        
        # Track message IDs and senders
        if 'messages_accessed' not in profile:
            profile['messages_accessed'] = deque(maxlen=100)
        
        message_id = event.metadata.get('message_id', 'unknown')
        sender = event.metadata.get('sender', 'unknown')
        
        if message_id != 'unknown':
            profile['messages_accessed'].append((current_time, message_id, sender, event.success))
        
        # Check for accessing messages from many different senders (potential interception)
        recent_reads = [(t, m, s, success) for t, m, s, success in profile['messages_accessed'] 
                       if current_time - t < 600]  # Last 10 minutes
        
        if len(recent_reads) > 8:
            unique_senders = len(set(s for _, _, s, _ in recent_reads if s != 'unknown'))
            failed_reads = sum(1 for _, _, _, success in recent_reads if not success)
            
            if unique_senders > 4 and failed_reads > 2:  # Reading from many senders with failures
                self._create_anomaly(
                    user_id=user_id,
                    severity='critical',
                    anomaly_type='message_interception_receiver',
                    description=f"🚨 RECEIVER ATTACK - MESSAGE INTERCEPTION: Attempting to read messages from {unique_senders} different senders (attack type: Man-in-the-middle)",
                    confidence=0.9,
                    indicators=[
                        f"👤 Role: RECEIVER (reading messages)",
                        f"📥 Different senders: {unique_senders} unique accounts",
                        f"❌ Failed read attempts: {failed_reads}",
                        f"📊 Total messages accessed: {len(recent_reads)}",
                        "🎯 Attack pattern: Intercepting messages meant for others",
                        "🔍 Method: MITM attack, session hijacking, or unauthorized access",
                        "💥 Risk: Privacy breach, unauthorized message access"
                    ],
                    recommended_action="🚨 RECEIVER CRITICAL: Verify user identity immediately, check for session hijacking, invalidate all sessions, require re-authentication, alert legitimate message owners"
                )
    
    def _check_session_anomalies(self, event: EncryptionEvent, user_id: str):
        """Detect session-based attacks"""
        profile = self.user_patterns[user_id]
        current_time = time.time()
        
        # Determine user role
        recent_events_for_role = [e for e in self.encryption_events 
                                 if e.user_id == user_id and current_time - e.timestamp < 3600]
        encrypt_count = sum(1 for e in recent_events_for_role if e.event_type == 'encrypt')
        decrypt_count = sum(1 for e in recent_events_for_role if e.event_type == 'decrypt')
        
        is_primarily_sender = encrypt_count > decrypt_count
        is_primarily_receiver = decrypt_count > encrypt_count
        
        # Check for session switching (potential session hijacking)
        if 'known_sessions' in profile and len(profile['known_sessions']) > 3:
            recent_events = [e for e in self.encryption_events 
                           if e.user_id == user_id and current_time - e.timestamp < 3600]
            
            if len(recent_events) > 5:
                unique_sessions = len(set(e.session_id for e in recent_events))
                if unique_sessions > 3:
                    # Role-specific session hijacking detection
                    if is_primarily_receiver:
                        anomaly_type = 'session_hijacking_receiver'
                        role_desc = "RECEIVER"
                        attack_desc = "🚨 RECEIVER SESSION HIJACKING: Attacker trying to hijack session to READ your incoming messages"
                        risk_detail = f"💥 Risk: Attacker gains access to {decrypt_count} incoming messages in your inbox"
                        action = "🚨 RECEIVER CRITICAL: Invalidate all sessions immediately, force re-login, enable 2FA for message reading, review which messages were accessed"
                    elif is_primarily_sender:
                        anomaly_type = 'session_hijacking_sender'
                        role_desc = "SENDER"
                        attack_desc = "🚨 SENDER SESSION HIJACKING: Attacker trying to hijack session to SEND messages on your behalf"
                        risk_detail = f"💥 Risk: Attacker could send {encrypt_count} unauthorized messages pretending to be you"
                        action = "🚨 SENDER CRITICAL: Invalidate all sessions immediately, force re-login, enable 2FA for sending, notify your contacts of potential impersonation"
                    else:
                        anomaly_type = 'session_hijacking_mixed'
                        role_desc = "MIXED (Send & Receive)"
                        attack_desc = "🚨 FULL ACCOUNT SESSION HIJACKING: Attacker has complete access to both sending and receiving"
                        risk_detail = "💥 Risk: Complete account takeover - both reading messages AND sending as you"
                        action = "🚨 CRITICAL: Lock account immediately, invalidate ALL sessions, force password reset, enable 2FA, notify ALL contacts, review entire message history"
                    
                    self._create_anomaly(
                        user_id=user_id,
                        severity='critical',
                        anomaly_type=anomaly_type,
                        description=f"{attack_desc} - {unique_sessions} different sessions in 1 hour (Attack type: Session Token Theft)",
                        confidence=0.9,
                        indicators=[
                            f"� User Role: {role_desc}",
                            f"�🔀 Multiple sessions detected: {unique_sessions} unique session IDs",
                            f"📊 Recent activity: {encrypt_count} sends, {decrypt_count} reads",
                            f"⏰ Time window: Past hour ({len(recent_events)} total operations)",
                            "🎯 Attack type: Session hijacking/fixation/cookie theft",
                            "🔍 Method: Stolen session tokens, XSS, CSRF, or network interception",
                            f"🌐 Current IP: {event.ip_address}",
                            risk_detail
                        ],
                        recommended_action=action
                    )
        
        # Check for geographic anomalies (if IP changes dramatically)
        recent_ips = [e.ip_address for e in self.encryption_events 
                     if e.user_id == user_id and current_time - e.timestamp < 3600]
        
        if len(recent_ips) > 5 and len(set(recent_ips)) > 3:
            # Role-specific impossible travel detection
            if is_primarily_receiver:
                anomaly_type = 'impossible_travel_receiver'
                role_desc = "RECEIVER"
                attack_desc = f"🌍 RECEIVER IMPOSSIBLE TRAVEL: Reading messages from {len(set(recent_ips))} different locations simultaneously"
                risk_detail = f"💥 Risk: Someone else is accessing and reading your {decrypt_count} incoming messages from another location"
                action = "⚠️ RECEIVER ACTION: Verify login locations, logout all devices, check message read history, enable geographic restrictions for inbox access"
            elif is_primarily_sender:
                anomaly_type = 'impossible_travel_sender'
                role_desc = "SENDER"
                attack_desc = f"🌍 SENDER IMPOSSIBLE TRAVEL: Sending messages from {len(set(recent_ips))} different locations simultaneously"
                risk_detail = f"💥 Risk: Unauthorized person sending {encrypt_count} messages pretending to be you from another location"
                action = "⚠️ SENDER ACTION: Verify login locations, logout all devices, check sent message history, notify recipients of potential impersonation, enable geographic restrictions"
            else:
                anomaly_type = 'impossible_travel_mixed'
                role_desc = "MIXED (Send & Receive)"
                attack_desc = f"🌍 FULL ACCOUNT IMPOSSIBLE TRAVEL: Account accessed from {len(set(recent_ips))} different locations - complete compromise"
                risk_detail = "💥 Risk: Multiple attackers OR coordinated attack accessing both inbox AND sending capabilities"
                action = "🚨 CRITICAL: Lock account immediately, force logout ALL devices, verify ALL login locations, review complete message history, enable strict geographic restrictions, consider account migration"
            
            self._create_anomaly(
                user_id=user_id,
                severity='high',
                anomaly_type=anomaly_type,
                description=f"{attack_desc} (Attack type: Account Sharing, Credential Theft, or Distributed Attack)",
                confidence=0.85,
                indicators=[
                    f"👤 User Role: {role_desc}",
                    f"🌐 Different IP addresses: {len(set(recent_ips))} unique locations",
                    f"📍 Recent IPs: {', '.join(list(set(recent_ips))[:3])}...",
                    f"📊 Activity from all IPs: {encrypt_count} sends, {decrypt_count} reads",
                    "🎯 Attack type: Impossible travel, credential sharing, or account takeover",
                    "🔍 Method: Simultaneous access from geographically impossible locations (faster than physically possible)",
                    "⏰ Timeframe: All within 1 hour - physically impossible to travel between these locations",
                    risk_detail
                ],
                recommended_action=action
            )
    
    def _check_immediate_threats(self, event: EncryptionEvent, user_id: str):
        """Check for immediate security threats"""
        profile = self.user_patterns[user_id]
        current_time = time.time()
        
        # RECEIVER-SPECIFIC THREAT: Rapid decryption attempts (potential brute force)
        if event.event_type == 'decrypt':
            recent_decrypts = [t for t in profile['decrypt_times'] 
                             if current_time - t < 60]
            if len(recent_decrypts) > self.thresholds['max_decrypt_attempts_per_min']:
                self._create_anomaly(
                    user_id=user_id,
                    severity='high',
                    anomaly_type='brute_force_attack_receiver',
                    description=f"🚨 RECEIVER ATTACK - BRUTE FORCE: {len(recent_decrypts)} rapid decryption attempts in 60 seconds (normal: <{self.thresholds['max_decrypt_attempts_per_min']})",
                    confidence=0.9,
                    indicators=[
                        f"👤 Role: RECEIVER (trying to read messages)",
                        f"⚡ {len(recent_decrypts)} decrypt attempts in 1 minute",
                        f"📊 Normal threshold: {self.thresholds['max_decrypt_attempts_per_min']} per minute",
                        "🎯 Attack pattern: Automated password/key guessing on incoming messages",
                        "📍 Risk: Attempting to decrypt messages not meant for this user"
                    ],
                    recommended_action="🛡️ RECEIVER ACTION: Lock message access temporarily, require 2FA for message reading, verify user identity before allowing decryption"
                )
        
        # SENDER-SPECIFIC THREAT: Rapid encryption attempts (potential message flooding)
        if event.event_type == 'encrypt':
            recent_encrypts = [t for t in profile['encrypt_times'] 
                             if current_time - t < 60]
            if len(recent_encrypts) > self.thresholds['max_decrypt_attempts_per_min'] * 2:  # Higher threshold for sending
                self._create_anomaly(
                    user_id=user_id,
                    severity='high',
                    anomaly_type='message_flooding_sender',
                    description=f"🚨 SENDER ATTACK - MESSAGE FLOODING: {len(recent_encrypts)} messages sent in 60 seconds (normal: <{self.thresholds['max_decrypt_attempts_per_min'] * 2})",
                    confidence=0.85,
                    indicators=[
                        f"👤 Role: SENDER (sending messages)",
                        f"📤 {len(recent_encrypts)} encrypt/send operations in 1 minute",
                        f"📊 Normal threshold: {self.thresholds['max_decrypt_attempts_per_min'] * 2} per minute",
                        "🎯 Attack pattern: Spam/flooding attack or automated bot",
                        "📍 Risk: System abuse, recipient harassment, resource exhaustion"
                    ],
                    recommended_action="🛡️ SENDER ACTION: Rate limit sending, implement CAPTCHA verification, require delay between messages, review account for spam activity"
                )
        
        # RECEIVER-SPECIFIC THREAT: Failed decryption patterns (wrong keys/credentials)
        recent_failures = [t for t in profile['failed_attempts'] 
                          if current_time - t < 3600]
        if len(recent_failures) > self.thresholds['max_failed_decrypts_per_hour']:
            # Check if user is primarily a receiver
            recent_events = [e for e in self.encryption_events 
                           if e.user_id == user_id and current_time - e.timestamp < 3600]
            decrypt_count = sum(1 for e in recent_events if e.event_type == 'decrypt')
            
            if decrypt_count > len(recent_events) / 2:  # More than 50% are decrypt operations
                self._create_anomaly(
                    user_id=user_id,
                    severity='critical',
                    anomaly_type='credential_stuffing_receiver',
                    description=f"🔴 RECEIVER ATTACK - CREDENTIAL STUFFING: {len(recent_failures)} failed decryption attempts in 1 hour (normal: <{self.thresholds['max_failed_decrypts_per_hour']})",
                    confidence=0.95,
                    indicators=[
                        f"👤 Role: RECEIVER (attempting to read messages)",
                        f"❌ {len(recent_failures)} failed decrypt attempts in past hour",
                        "🔑 Pattern: Multiple wrong passwords/decryption keys",
                        f"🌐 Source IP: {event.ip_address}",
                        "💥 Risk: Unauthorized user trying to access someone else's messages"
                    ],
                    recommended_action="🚨 RECEIVER CRITICAL: Lock account immediately, force password reset, notify legitimate user, alert security team, invalidate all message access tokens"
                )
            else:
                # Generic credential attack (mixed sender/receiver activity)
                self._create_anomaly(
                    user_id=user_id,
                    severity='critical',
                    anomaly_type='credential_stuffing_mixed',
                    description=f"🔴 CREDENTIAL ATTACK: {len(recent_failures)} failed authentication attempts in 1 hour (normal: <{self.thresholds['max_failed_decrypts_per_hour']})",
                    confidence=0.95,
                    indicators=[
                        f"👤 Role: MIXED (both sending and receiving activity)",
                        f"❌ {len(recent_failures)} failed attempts in past hour",
                        "🔑 Pattern: Multiple authentication failures",
                        f"🌐 Source IP: {event.ip_address}",
                        "💥 Risk: Account compromise in progress"
                    ],
                    recommended_action="🚨 CRITICAL: Lock account immediately, force password reset, notify user via alternate channel, alert security team"
                )
    
    def _analyze_recent_patterns(self):
        """Analyze recent encryption patterns for anomalies"""
        with self.lock:
            for user_id, profile in self.user_patterns.items():
                # Determine user's primary role (sender vs receiver)
                total_encrypts = len(profile['encrypt_times'])
                total_decrypts = len(profile['decrypt_times'])
                is_primarily_sender = total_encrypts > total_decrypts
                is_primarily_receiver = total_decrypts > total_encrypts
                
                # Analyze timing patterns
                if len(profile['timing_patterns']) > 20:
                    timings = list(profile['timing_patterns'])
                    avg_timing = sum(timings) / len(timings)
                    
                    # Check for unusual timing variance (possible timing attack)
                    recent_timings = timings[-10:]
                    recent_avg = sum(recent_timings) / len(recent_timings)
                    
                    if avg_timing > 0:
                        variance = abs(recent_avg - avg_timing) / avg_timing
                        if variance > self.thresholds['unusual_timing_variance']:
                            # Role-specific timing attack detection
                            role_info = "RECEIVER" if is_primarily_receiver else "SENDER" if is_primarily_sender else "MIXED"
                            action = (
                                "⚙️ RECEIVER DEFENSE: Messages are already encrypted; timing attacks target decryption - use constant-time algorithms, add random delays (50-100ms) to message retrieval"
                                if is_primarily_receiver else
                                "⚙️ SENDER DEFENSE: Add random timing jitter to message sending (50-100ms), use constant-time encryption, batch messages randomly"
                                if is_primarily_sender else
                                "⚙️ DEFENSE: Add random timing jitter (50-100ms), use constant-time algorithms, monitor for correlation patterns"
                            )
                            
                            self._create_anomaly(
                                user_id=user_id,
                                severity='medium',
                                anomaly_type=f'timing_side_channel_attack_{role_info.lower()}',
                                description=f"⏱️ {role_info} TIMING ATTACK: Unusual timing pattern detected - {variance:.1%} variance from normal (attack type: Side-channel analysis)",
                                confidence=0.7,
                                indicators=[
                                    f"👤 Role: {role_info}",
                                    f"⏰ Normal timing: {avg_timing:.2f}ms",
                                    f"📊 Recent timing: {recent_avg:.2f}ms",
                                    f"📈 Variance: {variance:.1%} (threshold: {self.thresholds['unusual_timing_variance']:.1%})",
                                    "🎯 Attack type: Timing side-channel",
                                    f"🔍 Target: {'Decryption operations' if is_primarily_receiver else 'Encryption operations' if is_primarily_sender else 'Mixed operations'}"
                                ],
                                recommended_action=action
                            )
                
                # Analyze message size patterns (detect pattern analysis attacks)
                if len(profile['message_sizes']) > 10:
                    sizes = list(profile['message_sizes'])
                    unique_sizes = len(set(sizes))
                    
                    # If many messages have identical sizes, could be pattern attack
                    if unique_sizes < len(sizes) / 5:
                        # Role-specific pattern analysis
                        role_info = "RECEIVER" if is_primarily_receiver else "SENDER" if is_primarily_sender else "MIXED"
                        action = (
                            "🛡️ RECEIVER DEFENSE: Incoming messages already have padding; attacker may be analyzing your reading patterns - use random access delays, read decoy messages"
                            if is_primarily_receiver else
                            "🛡️ SENDER DEFENSE: Enable message padding before sending, add random dummy traffic, use fixed-size message blocks (e.g., 1KB, 4KB, 16KB)"
                            if is_primarily_sender else
                            "🛡️ DEFENSE: Enable message padding, add random dummy traffic, use fixed-size message blocks"
                        )
                        
                        self._create_anomaly(
                            user_id=user_id,
                            severity='medium',
                            anomaly_type=f'traffic_analysis_attack_{role_info.lower()}',
                            description=f"🔍 {role_info} TRAFFIC ANALYSIS: Repetitive message patterns detected - {unique_sizes} unique sizes from {len(sizes)} messages (attack type: Pattern fingerprinting)",
                            confidence=0.6,
                            indicators=[
                                f"👤 Role: {role_info}",
                                f"📦 Unique message sizes: {unique_sizes}",
                                f"📨 Total messages analyzed: {len(sizes)}",
                                f"📊 Diversity ratio: {(unique_sizes/len(sizes)):.1%} (normal: >20%)",
                                "🎯 Attack type: Traffic analysis",
                                f"🔍 Target: {'Analyzing received message sizes' if is_primarily_receiver else 'Analyzing sent message sizes' if is_primarily_sender else 'Analyzing message size patterns'}"
                            ],
                            recommended_action=action
                        )
    
    def _detect_timing_attacks(self):
        """Detect sophisticated timing-based attacks"""
        current_time = time.time()
        
        with self.lock:
            recent_events = [e for e in self.encryption_events 
                           if current_time - e.timestamp < 300]  # Last 5 minutes
            
            if len(recent_events) < 10:
                return
            
            # Group by user
            user_events = defaultdict(list)
            for event in recent_events:
                user_events[event.user_id].append(event)
            
            for user_id, events in user_events.items():
                # Check for rapid succession (potential side-channel attack)
                encrypt_events = [e for e in events if e.event_type == 'encrypt']
                decrypt_events = [e for e in events if e.event_type == 'decrypt']
                
                # Check decrypt timing attacks (RECEIVER)
                if len(decrypt_events) >= 5:
                    time_diffs = []
                    for i in range(1, len(decrypt_events)):
                        diff = (decrypt_events[i].timestamp - decrypt_events[i-1].timestamp) * 1000
                        time_diffs.append(diff)
                    
                    rapid_count = sum(1 for d in time_diffs if d < self.thresholds['rapid_succession_ms'])
                    
                    if rapid_count >= 3:
                        self._create_anomaly(
                            user_id=user_id,
                            severity='high',
                            anomaly_type='cache_timing_attack_receiver',
                            description=f"⚡ RECEIVER CACHE TIMING ATTACK: {rapid_count} rapid decryption attempts in <{self.thresholds['rapid_succession_ms']}ms intervals (Attack type: CPU Cache Side-Channel Analysis)",
                            confidence=0.85,
                            indicators=[
                                f"👤 Role: RECEIVER (attempting to read encrypted messages)",
                                f"⏱️ Rapid decrypt operations: {rapid_count} in <{self.thresholds['rapid_succession_ms']}ms each",
                                f"📊 Total decrypt attempts: {len(decrypt_events)} in 5 minutes",
                                f"🎯 Attack type: Cache timing side-channel on decryption keys",
                                "🔍 Method: Measuring CPU cache hits/misses during decryption to extract private keys",
                                "🔬 Technique: Statistical analysis of decryption timing variations to reveal key bits",
                                "� Risk: CRITICAL - Could extract receiver's private decryption key, allowing attacker to read ALL past and future messages",
                                "⚠️ Impact: Automated attack - likely using specialized timing analysis tools"
                            ],
                            recommended_action="🚨 RECEIVER CRITICAL: Implement strict rate limiting (max 1 decrypt/sec), use constant-time decryption algorithms, enable CPU cache-line flushing, rotate decryption keys immediately, add random timing jitter (100-500ms), consider hardware security module (HSM)"
                        )
                
                # Check encrypt timing attacks (SENDER)
                if len(encrypt_events) >= 5:
                    time_diffs = []
                    for i in range(1, len(encrypt_events)):
                        diff = (encrypt_events[i].timestamp - encrypt_events[i-1].timestamp) * 1000
                        time_diffs.append(diff)
                    
                    rapid_count = sum(1 for d in time_diffs if d < self.thresholds['rapid_succession_ms'])
                    
                    if rapid_count >= 3:
                        self._create_anomaly(
                            user_id=user_id,
                            severity='high',
                            anomaly_type='cache_timing_attack_sender',
                            description=f"⚡ SENDER CACHE TIMING ATTACK: {rapid_count} rapid encryption attempts in <{self.thresholds['rapid_succession_ms']}ms intervals (Attack type: CPU Cache Side-Channel Analysis)",
                            confidence=0.85,
                            indicators=[
                                f"� Role: SENDER (encrypting/sending messages)",
                                f"⏱️ Rapid encrypt operations: {rapid_count} in <{self.thresholds['rapid_succession_ms']}ms each",
                                f"📊 Total encrypt attempts: {len(encrypt_events)} in 5 minutes",
                                f"🎯 Attack type: Cache timing side-channel on encryption process",
                                "🔍 Method: Measuring CPU cache behavior during encryption to infer patterns",
                                "🔬 Technique: Analyzing encryption timing to reveal message characteristics or keys",
                                "💥 Risk: HIGH - Could reveal encryption patterns, message characteristics, or compromise future messages",
                                "⚠️ Impact: Automated attack targeting sender's encryption process"
                            ],
                            recommended_action="� SENDER CRITICAL: Implement strict rate limiting (max 1 encrypt/sec), use constant-time encryption algorithms, add random timing delays (100-500ms), enable CPU cache protection, consider message batching with random intervals"
                        )
    
    def _detect_pattern_attacks(self):
        """Detect pattern-based cryptanalysis attempts"""
        with self.lock:
            for user_id, profile in self.user_patterns.items():
                # Determine user role
                encrypt_count = len(profile['encrypt_times'])
                decrypt_count = len(profile['decrypt_times'])
                is_sender = encrypt_count > decrypt_count
                is_receiver = decrypt_count > encrypt_count
                
                # Check for repetitive encryption operations (SENDER - known-plaintext attack)
                if len(profile['encrypt_times']) >= 20:
                    encrypt_times = list(profile['encrypt_times'])
                    
                    # Check for periodic patterns
                    time_gaps = []
                    for i in range(1, len(encrypt_times)):
                        gap = encrypt_times[i] - encrypt_times[i-1]
                        time_gaps.append(gap)
                    
                    if len(time_gaps) >= 10:
                        # Check if gaps are suspiciously regular
                        avg_gap = sum(time_gaps) / len(time_gaps)
                        regular_gaps = sum(1 for g in time_gaps if abs(g - avg_gap) < avg_gap * 0.1)
                        
                        if regular_gaps >= self.thresholds['pattern_repetition_threshold']:
                            self._create_anomaly(
                                user_id=user_id,
                                severity='high',
                                anomaly_type='known_plaintext_attack_sender',
                                description=f"🔄 SENDER KNOWN-PLAINTEXT ATTACK: Suspicious regular encryption pattern - {regular_gaps} periodic intervals detected (Attack type: Cryptanalysis on encryption algorithm)",
                                confidence=0.8,
                                indicators=[
                                    f"👤 Role: SENDER (encrypting/sending messages)",
                                    f"🔁 Regular operation intervals detected: {regular_gaps} out of {len(time_gaps)} gaps",
                                    f"⏰ Average time gap: {avg_gap:.2f} seconds (unusually consistent)",
                                    f"📊 Total encrypt operations analyzed: {len(encrypt_times)}",
                                    f"🎯 Attack type: Known-plaintext cryptanalysis on sender's encryption",
                                    "🔍 Method: Encrypting known/predictable data repeatedly to analyze cipher patterns and extract encryption keys",
                                    "🔬 Technique: Statistical analysis of ciphertext patterns when plaintext is known or controlled",
                                    "📊 Pattern: Automated periodic requests suggesting bot/script activity",
                                    "💥 Risk: CRITICAL - Could break encryption algorithm, reveal sender's encryption keys, allow message forgery",
                                    "⚠️ Impact: If successful, attacker can create fake messages that appear to be from you"
                                ],
                                recommended_action="� SENDER URGENT: Rotate encryption keys IMMEDIATELY, implement random delays (1-5 sec) between sends, add CAPTCHA verification for rapid sends, use randomized initialization vectors (IV), monitor for correlation attacks, enable send rate limiting (max 1/min), consider switching encryption scheme"
                            )
                
                # Check for repetitive decryption operations (RECEIVER - chosen-ciphertext attack)
                if len(profile['decrypt_times']) >= 20:
                    decrypt_times = list(profile['decrypt_times'])
                    
                    # Check for periodic patterns
                    time_gaps = []
                    for i in range(1, len(decrypt_times)):
                        gap = decrypt_times[i] - decrypt_times[i-1]
                        time_gaps.append(gap)
                    
                    if len(time_gaps) >= 10:
                        # Check if gaps are suspiciously regular
                        avg_gap = sum(time_gaps) / len(time_gaps)
                        regular_gaps = sum(1 for g in time_gaps if abs(g - avg_gap) < avg_gap * 0.1)
                        
                        if regular_gaps >= self.thresholds['pattern_repetition_threshold']:
                            self._create_anomaly(
                                user_id=user_id,
                                severity='critical',
                                anomaly_type='chosen_ciphertext_attack_receiver',
                                description=f"🔄 RECEIVER CHOSEN-CIPHERTEXT ATTACK: Suspicious regular decryption pattern - {regular_gaps} periodic intervals detected (Attack type: Adaptive cryptanalysis on decryption)",
                                confidence=0.85,
                                indicators=[
                                    f"👤 Role: RECEIVER (decrypting/reading messages)",
                                    f"🔁 Regular operation intervals detected: {regular_gaps} out of {len(time_gaps)} gaps",
                                    f"⏰ Average time gap: {avg_gap:.2f} seconds (suspiciously consistent)",
                                    f"📊 Total decrypt operations analyzed: {len(decrypt_times)}",
                                    f"🎯 Attack type: Chosen-ciphertext adaptive cryptanalysis on receiver's decryption",
                                    "🔍 Method: Submitting crafted encrypted messages and analyzing decryption behavior to extract private keys",
                                    "🔬 Technique: Oracle attack - using decryption as 'oracle' to reveal key information through timing/errors",
                                    "📊 Pattern: Automated periodic decryption attempts suggesting advanced attack tool",
                                    "💥 Risk: CRITICAL - Could extract receiver's PRIVATE decryption key, allowing attacker to decrypt ALL messages (past & future)",
                                    "⚠️ Impact: Complete privacy breach - all encrypted communications compromised"
                                ],
                                recommended_action="🚨 RECEIVER CRITICAL: LOCK ACCOUNT IMMEDIATELY, rotate ALL cryptographic keys, implement strict rate limiting (max 1 decrypt/min), add random delays (2-10 sec), enable padding oracle protection, use authenticated encryption (AEAD), monitor for timing oracle attacks, alert security team, consider full key infrastructure reset"
                            )
    
    def _create_anomaly(self, user_id: str, severity: str, anomaly_type: str,
                       description: str, confidence: float, indicators: List[str],
                       recommended_action: str):
        """Create and log an anomaly detection"""
        anomaly = AnomalyDetection(
            anomaly_id=secrets.token_hex(16),
            severity=severity,
            anomaly_type=anomaly_type,
            description=description,
            detected_at=time.time(),
            user_id=user_id,
            confidence=confidence,
            indicators=indicators,
            recommended_action=recommended_action
        )
        
        with self.lock:
            self.anomalies.append(anomaly)
            self.threat_indicators[anomaly_type] += 1
        
        # Log critical anomalies
        if severity in ['high', 'critical']:
            logger.warning(f"ANOMALY DETECTED - {severity.upper()}: {description} (User: {user_id})")
    
    def _cleanup_old_data(self):
        """Remove old data to prevent memory bloat"""
        current_time = time.time()
        max_age = 86400  # 24 hours
        
        with self.lock:
            # Clean old anomalies
            while self.anomalies and current_time - self.anomalies[0].detected_at > max_age:
                self.anomalies.popleft()
    
    def get_security_report(self, user_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate security report (admin only - not exposed to users)
        """
        # Snapshot shared state quickly under lock to avoid long holds during rendering
        with self.lock:
            anomalies_snapshot = list(self.anomalies)
            indicators_snapshot = dict(self.threat_indicators)
            monitoring_active = self.monitoring_active
            total_events = len(self.encryption_events)
            users_monitored = len(self.user_patterns)
            model_trained = self.model_trained

        # Build views outside the lock
        if user_id:
            user_anomalies = [a for a in anomalies_snapshot if a.user_id == user_id]
        else:
            user_anomalies = anomalies_snapshot
        
        recent_anomalies = [a for a in user_anomalies 
                            if time.time() - a.detected_at < 3600]
        
        severity_counts = defaultdict(int)
        for anomaly in recent_anomalies:
            severity_counts[anomaly.severity] += 1
            
            # Group anomalies by type for summary view
            anomaly_summary = defaultdict(lambda: {
                'count': 0,
                'severity': 'low',
                'description': '',
                'indicators': [],
                'recommended_action': '',
                'confidence': 0.0,
                'latest_time': 0
            })
            
            for anomaly in recent_anomalies:
                atype = anomaly.anomaly_type
                anomaly_summary[atype]['count'] += 1
                
                # Keep the highest severity
                severity_order = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
                if severity_order.get(anomaly.severity, 0) > severity_order.get(anomaly_summary[atype]['severity'], 0):
                    anomaly_summary[atype]['severity'] = anomaly.severity
                
                # Keep the most recent description and details
                if anomaly.detected_at > anomaly_summary[atype]['latest_time']:
                    anomaly_summary[atype]['latest_time'] = anomaly.detected_at
                    anomaly_summary[atype]['description'] = anomaly.description
                    anomaly_summary[atype]['indicators'] = anomaly.indicators
                    anomaly_summary[atype]['recommended_action'] = anomaly.recommended_action
                    anomaly_summary[atype]['confidence'] = anomaly.confidence
            
            # Convert to list, sorted by severity and count
            severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
            summarized_anomalies = [
                {
                    'type': atype,
                    'count': data['count'],
                    'severity': data['severity'],
                    'description': data['description'],
                    'confidence': data['confidence'],
                    'indicators': data['indicators'],
                    'recommended_action': data['recommended_action']
                }
                for atype, data in anomaly_summary.items()
                if data['severity'] in ['critical', 'high']
            ]
            
            # Sort by severity (critical first) then by count
            summarized_anomalies.sort(
                key=lambda x: (severity_order.get(x['severity'], 0), x['count']),
                reverse=True
            )
            
            # Make status intuitive: if no data yet, show awaiting-data even if a model file exists
            if total_events == 0:
                ml_status = 'awaiting-data'
            else:
                ml_status = 'trained' if model_trained else 'training'

            return {
                'total_anomalies_24h': len(user_anomalies),
                'recent_anomalies_1h': len(recent_anomalies),
                'severity_breakdown': dict(severity_counts),
                'threat_indicators': indicators_snapshot,
                'monitoring_active': monitoring_active,
                'total_events_logged': total_events,
                'users_monitored': users_monitored,
                'ml_model_trained': model_trained,
                'ml_model_status': ml_status,
                'min_samples_for_training': self.min_samples_for_training,
                'detection_methods': ['rule-based', 'ml-isolation-forest'] if self.model_trained else ['rule-based'],
                'anomaly_summary': summarized_anomalies[:5]  # Top 5 unique anomaly types
            }
    
    def get_user_risk_score(self, user_id: str) -> Tuple[float, str]:
        """
        Calculate risk score for a user (0-100)
        Returns (score, risk_level)
        """
        with self.lock:
            user_anomalies = [a for a in self.anomalies if a.user_id == user_id]
            
            if not user_anomalies:
                return 0.0, 'safe'
            
            # Calculate weighted risk score
            score = 0.0
            severity_weights = {'low': 10, 'medium': 25, 'high': 50, 'critical': 100}
            
            for anomaly in user_anomalies:
                # Recent anomalies weighted more heavily
                age_hours = (time.time() - anomaly.detected_at) / 3600
                recency_factor = max(0.1, 1.0 - (age_hours / 24))
                
                weight = severity_weights.get(anomaly.severity, 10)
                score += weight * anomaly.confidence * recency_factor
            
            # Normalize to 0-100
            score = min(100, score / len(user_anomalies))
            
            # Determine risk level
            if score < 20:
                risk_level = 'safe'
            elif score < 40:
                risk_level = 'low'
            elif score < 60:
                risk_level = 'medium'
            elif score < 80:
                risk_level = 'high'
            else:
                risk_level = 'critical'
            
            return score, risk_level
    
    def is_user_safe(self, user_id: str) -> bool:
        """
        Quick check if user has no critical threats
        """
        score, level = self.get_user_risk_score(user_id)
        return level in ['safe', 'low']

    def _severity_rank(self, severity: str) -> int:
        """Convert severity label to numeric rank"""
        return self._severity_order.get(severity.lower(), 0)

    def _derive_role_from_type(self, anomaly_type: str) -> str:
        """Infer user role (sender/receiver/mixed) based on anomaly type name"""
        anomaly_type = (anomaly_type or '').lower()
        if 'receiver' in anomaly_type:
            return 'receiver'
        if 'sender' in anomaly_type:
            return 'sender'
        if 'mixed' in anomaly_type:
            return 'mixed'
        if 'decrypt' in anomaly_type or 'read' in anomaly_type:
            return 'receiver'
        if 'encrypt' in anomaly_type or 'send' in anomaly_type:
            return 'sender'
        return 'unknown'

    def _friendly_title_for_anomaly(self, anomaly_type: str) -> str:
        """Map internal anomaly types to human-friendly titles for the UI"""
        key = (anomaly_type or '').lower()
        mapping = {
            'brute_force_attack_receiver': 'Receiver Brute-Force Decryption Attempts',
            'message_flooding_sender': 'Sender Message Flooding Detected',
            'credential_stuffing_receiver': 'Credential Stuffing on Receiver Access',
            'credential_stuffing_mixed': 'Credential Attack on Account',
            'chosen_ciphertext_attack_receiver': 'Chosen-Ciphertext Attack Against Receiver',
            'impossible_travel_receiver': 'Impossible Travel (Receiver Access)',
            'impossible_travel_sender': 'Impossible Travel (Sender Activity)',
            'impossible_travel_mixed': 'Impossible Travel (Account Compromise)',
        }
        return mapping.get(key, anomaly_type.replace('_', ' ').title() if key else 'Security Anomaly')

    def _get_playbook(self, anomaly_type: str) -> list:
        """Return a list of recommended steps for this anomaly type, if available"""
        return list(self._playbooks.get((anomaly_type or '').lower(), []))

    def _format_anomaly_summary(self, anomaly: AnomalyDetection) -> Dict[str, Any]:
        """Convert anomaly dataclass into a UI-friendly dictionary"""
        role = self._derive_role_from_type(anomaly.anomaly_type)
        role_label = {
            'sender': '📤 Sender Threat',
            'receiver': '📥 Receiver Threat',
            'mixed': '🔄 Account-Wide Threat',
            'unknown': '❓ Threat'
        }.get(role, '❓ Threat')

        severity_label = {
            'low': '⚠️ Low',
            'medium': '🟠 Medium',
            'high': '🔴 High',
            'critical': '🚨 Critical'
        }.get(anomaly.severity.lower(), anomaly.severity.upper())

        time_since = max(0, time.time() - anomaly.detected_at)
        minutes_since = int(time_since // 60)
        seconds_since = int(time_since % 60)
        detected_ago = f"{minutes_since}m {seconds_since}s ago" if minutes_since else f"{seconds_since}s ago"

        return {
            'anomaly_id': anomaly.anomaly_id,
            'type': anomaly.anomaly_type,
            'title': self._friendly_title_for_anomaly(anomaly.anomaly_type),
            'role': role,
            'role_label': role_label,
            'severity': anomaly.severity,
            'severity_label': severity_label,
            'description': anomaly.description,
            'detected_at': anomaly.detected_at,
            'detected_ago': detected_ago,
            'confidence': anomaly.confidence,
            'indicators': anomaly.indicators,
            'recommended_action': anomaly.recommended_action,
            'playbook': self._get_playbook(anomaly.anomaly_type)
        }

    def get_recent_anomalies(self, user_id: str, within_seconds: int = 3600,
                             min_severity: str = 'medium', max_results: int = 5,
                             role_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Return recent anomalies for a user filtered by severity, time, and optional role.
        This is used by the UI to warn receivers/senders in real-time.
        """
        cutoff = time.time() - within_seconds
        min_rank = self._severity_rank(min_severity)

        with self.lock:
            relevant = [
                self._format_anomaly_summary(anomaly)
                for anomaly in reversed(self.anomalies)
                if anomaly.user_id == user_id
                and anomaly.detected_at >= cutoff
                and self._severity_rank(anomaly.severity) >= min_rank
            ]

        if role_filter:
            role_filter = role_filter.lower()
            relevant = [a for a in relevant if a['role'] == role_filter]

        return relevant[:max_results]
    
    # ============ MACHINE LEARNING METHODS ============
    
    def _extract_features(self, events: List[EncryptionEvent]) -> np.ndarray:
        """
        Extract numerical features from encryption events for ML analysis
        Features: timing, message size, success rate, temporal patterns, etc.
        """
        if not events:
            return np.array([])
        
        features = []
        for event in events:
            # Basic features
            feature_vector = [
                event.duration_ms,  # Encryption/decryption duration
                event.message_size,  # Message size
                1.0 if event.success else 0.0,  # Success/failure
                1.0 if event.event_type == 'encrypt' else 0.0,  # Event type
                hash(event.user_id) % 10000,  # User ID hash (normalized)
                hash(event.ip_address) % 10000,  # IP hash (normalized)
                time.localtime(event.timestamp).tm_hour,  # Hour of day
                time.localtime(event.timestamp).tm_wday,  # Day of week
            ]
            features.append(feature_vector)
        
        return np.array(features)
    
    def _train_ml_model(self):
        """
        Train Isolation Forest model on recent encryption events
        This learns what "normal" encryption patterns look like
        """
        with self.lock:
            events = list(self.encryption_events)
        
        if len(events) < self.min_samples_for_training:
            logger.info(f"Not enough data for training ({len(events)}/{self.min_samples_for_training})")
            return
        
        try:
            # Extract features
            features = self._extract_features(events)
            
            if features.size == 0:
                return
            
            # Scale features
            features_scaled = self.scaler.fit_transform(features)
            
            # Train Isolation Forest
            # contamination: expected proportion of outliers (1% is conservative)
            self.ml_model = IsolationForest(
                contamination=0.01,
                random_state=42,
                n_estimators=100,
                max_samples='auto',
                n_jobs=-1  # Use all CPU cores
            )
            
            self.ml_model.fit(features_scaled)
            self.model_trained = True
            
            logger.info(f"ML model trained on {len(events)} encryption events")
            
            # Save model to disk
            self._save_model()
            
        except Exception as e:
            logger.error(f"Error training ML model: {e}")
    
    def _detect_ml_anomalies(self) -> List[AnomalyDetection]:
        """
        Use ML model to detect anomalies in recent encryption events
        Returns list of detected anomalies
        """
        if not self.model_trained:
            # Try to train if we have enough data
            self._train_ml_model()
            if not self.model_trained:
                return []
        
        with self.lock:
            # Get recent events (last 100)
            recent_events = list(self.encryption_events)[-100:]
        
        if len(recent_events) < 10:
            return []
        
        try:
            # Extract and scale features
            features = self._extract_features(recent_events)
            features_scaled = self.scaler.transform(features)
            
            # Predict anomalies (-1 = anomaly, 1 = normal)
            predictions = self.ml_model.predict(features_scaled)
            
            # Get anomaly scores (more negative = more anomalous)
            anomaly_scores = self.ml_model.score_samples(features_scaled)
            
            # Create anomaly objects for detected outliers
            anomalies = []
            for i, (pred, score, event) in enumerate(zip(predictions, anomaly_scores, recent_events)):
                if pred == -1:  # Anomaly detected
                    # Convert score to confidence (0-1)
                    # Isolation Forest scores are typically between -0.5 and 0.5
                    confidence = min(1.0, abs(score) * 2)
                    
                    # Determine severity based on confidence
                    if confidence > 0.9:
                        severity = 'critical'
                    elif confidence > 0.7:
                        severity = 'high'
                    elif confidence > 0.5:
                        severity = 'medium'
                    else:
                        severity = 'low'
                    
                    # Determine role-specific anomaly type
                    if event.event_type == 'decrypt':
                        anomaly_type = 'ml_unusual_receive_pattern'
                        role = 'RECEIVER'
                        activity = 'message decryption/reading'
                        risk = 'Unusual pattern in how messages are being READ - may indicate automated scraping, bulk downloading, or unauthorized access'
                        action = '🔍 RECEIVER: Review recent read patterns, check for unauthorized access, verify device security, monitor for data exfiltration attempts'
                    elif event.event_type == 'encrypt':
                        anomaly_type = 'ml_unusual_send_pattern'
                        role = 'SENDER'
                        activity = 'message encryption/sending'
                        risk = 'Unusual pattern in how messages are being SENT - may indicate bot activity, spam automation, or account compromise'
                        action = '🔍 SENDER: Review recent sent messages, verify account ownership, check for spam/bot activity, monitor recipient patterns'
                    else:
                        anomaly_type = 'ml_detected_anomaly'
                        role = 'UNKNOWN'
                        activity = 'cryptographic operation'
                        risk = 'Unusual activity detected - further investigation needed'
                        action = '🔍 Investigate event details, monitor user activity'
                    
                    anomaly = AnomalyDetection(
                        anomaly_id=secrets.token_hex(16),
                        severity=severity,
                        anomaly_type=anomaly_type,
                        description=f"🤖 ML-DETECTED {role} ANOMALY: Unusual {activity} pattern (Attack type: Advanced/Zero-Day behavior)",
                        detected_at=time.time(),
                        user_id=event.user_id,
                        confidence=confidence,
                        indicators=[
                            f"👤 User Role: {role}",
                            f"🤖 ML Anomaly score: {score:.4f} (more negative = more unusual)",
                            f"⏱️ Operation duration: {event.duration_ms:.2f}ms",
                            f"📦 Message size: {event.message_size} bytes",
                            f"✅ Operation success: {event.success}",
                            f"🎯 Activity type: {activity}",
                            f"🔬 Detection method: Isolation Forest ML model (100 estimators)",
                            f"📊 Training data: {len(self.encryption_events)} historical events",
                            f"💡 What this means: {risk}"
                        ],
                        recommended_action=action
                    )
                    anomalies.append(anomaly)
                    
                    # Log to deque
                    with self.lock:
                        self.anomalies.append(anomaly)
                        self.threat_indicators[anomaly_type] += 1
            
            if anomalies:
                logger.warning(f"ML detected {len(anomalies)} anomalous encryption events")
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error in ML anomaly detection: {e}")
            return []
    
    def _save_model(self):
        """Save trained model and scaler to disk"""
        try:
            if self.ml_model and self.model_trained:
                with open(self.model_path, 'wb') as f:
                    pickle.dump(self.ml_model, f)
                with open(self.scaler_path, 'wb') as f:
                    pickle.dump(self.scaler, f)
                logger.info("ML model saved to disk")
        except Exception as e:
            logger.error(f"Error saving model: {e}")
    
    def _load_model(self):
        """Load pre-trained model and scaler from disk"""
        try:
            if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
                with open(self.model_path, 'rb') as f:
                    self.ml_model = pickle.load(f)
                with open(self.scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                self.model_trained = True
                logger.info("Pre-trained ML model loaded from disk")
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            self.ml_model = None
            self.model_trained = False


# Singleton instance
_validator_instance = None

def get_validator() -> AIEncryptionValidator:
    """Get singleton validator instance"""
    global _validator_instance
    if _validator_instance is None:
        _validator_instance = AIEncryptionValidator()
        _validator_instance.start_monitoring()
    return _validator_instance
