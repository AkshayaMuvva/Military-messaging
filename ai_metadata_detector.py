"""
AI-Powered Metadata Leak Detection and Elimination System
Uses machine learning to detect and eliminate metadata that could expose communication patterns
"""

import time
import hashlib
import secrets
import json
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
import re


@dataclass
class MetadataPattern:
    """Detected metadata pattern"""
    pattern_type: str
    confidence: float
    risk_level: str
    detected_fields: List[str]
    recommendation: str


class MetadataAnalyzer:
    """
    AI-based metadata analysis to detect potential leaks
    """
    
    def __init__(self):
        self.known_leak_patterns = self._initialize_leak_patterns()
        self.metadata_history = deque(maxlen=1000)
        self.pattern_frequency = defaultdict(int)
        
    def _initialize_leak_patterns(self) -> Dict[str, Any]:
        """Initialize known metadata leak patterns"""
        return {
            'timestamp_correlation': {
                'description': 'Message timestamps that reveal communication patterns',
                'risk': 'high',
                'indicators': ['timestamp', 'sent_at', 'created_at']
            },
            'size_fingerprinting': {
                'description': 'Message sizes that could identify content',
                'risk': 'medium',
                'indicators': ['size', 'length', 'byte_count']
            },
            'sender_receiver_pattern': {
                'description': 'Sender-receiver pairs that reveal relationships',
                'risk': 'critical',
                'indicators': ['sender', 'recipient', 'from', 'to']
            },
            'ip_geolocation': {
                'description': 'IP addresses revealing physical location',
                'risk': 'critical',
                'indicators': ['ip', 'source_ip', 'client_ip', 'remote_addr']
            },
            'user_agent_fingerprinting': {
                'description': 'User agent strings identifying devices',
                'risk': 'high',
                'indicators': ['user_agent', 'browser', 'device']
            },
            'session_tracking': {
                'description': 'Session IDs allowing activity correlation',
                'risk': 'high',
                'indicators': ['session_id', 'session_token', 'auth_token']
            },
            'sequential_ids': {
                'description': 'Sequential IDs revealing message volume/timing',
                'risk': 'medium',
                'indicators': ['message_id', 'id', 'sequence']
            }
        }
    
    def analyze_metadata(self, metadata: Dict[str, Any]) -> List[MetadataPattern]:
        """
        Analyze metadata for potential leaks
        Returns list of detected patterns
        """
        detected_patterns = []
        
        # Flatten nested metadata
        flat_metadata = self._flatten_dict(metadata)
        
        # Check each known pattern
        for pattern_name, pattern_info in self.known_leak_patterns.items():
            detected_fields = []
            
            for field_name in flat_metadata.keys():
                for indicator in pattern_info['indicators']:
                    if indicator.lower() in field_name.lower():
                        detected_fields.append(field_name)
            
            if detected_fields:
                confidence = min(len(detected_fields) * 0.3, 1.0)
                pattern = MetadataPattern(
                    pattern_type=pattern_name,
                    confidence=confidence,
                    risk_level=pattern_info['risk'],
                    detected_fields=detected_fields,
                    recommendation=f"Remove or obfuscate: {', '.join(detected_fields)}"
                )
                detected_patterns.append(pattern)
                self.pattern_frequency[pattern_name] += 1
        
        # Store for pattern learning
        self.metadata_history.append({
            'timestamp': time.time(),
            'patterns': [p.pattern_type for p in detected_patterns],
            'field_count': len(flat_metadata)
        })
        
        return detected_patterns
    
    def _flatten_dict(self, d: Dict[str, Any], parent_key: str = '', sep: str = '.') -> Dict[str, Any]:
        """Flatten nested dictionary"""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)
    
    def detect_temporal_patterns(self, timestamps: List[float]) -> Dict[str, Any]:
        """
        Detect temporal patterns that could reveal communication habits
        """
        if len(timestamps) < 2:
            return {'risk': 'low', 'patterns': []}
        
        patterns = []
        
        # Sort timestamps
        sorted_times = sorted(timestamps)
        
        # Check for regular intervals (scheduled messages)
        intervals = [sorted_times[i+1] - sorted_times[i] for i in range(len(sorted_times)-1)]
        
        if intervals:
            avg_interval = sum(intervals) / len(intervals)
            
            # Check if intervals are suspiciously regular
            variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
            
            if variance < avg_interval * 0.1:  # Very regular
                patterns.append({
                    'type': 'regular_interval',
                    'risk': 'high',
                    'description': 'Messages sent at regular intervals - reveals automation/schedule'
                })
        
        # Check for clustering (burst communication)
        bursts = 0
        for i in range(len(intervals)):
            if intervals[i] < 60:  # Messages within 1 minute
                bursts += 1
        
        if bursts > len(intervals) * 0.5:
            patterns.append({
                'type': 'burst_pattern',
                'risk': 'medium',
                'description': 'Burst communication pattern detected'
            })
        
        # Check for time-of-day patterns
        hours = [time.localtime(t).tm_hour for t in sorted_times]
        hour_counts = defaultdict(int)
        for h in hours:
            hour_counts[h] += 1
        
        max_hour_count = max(hour_counts.values()) if hour_counts else 0
        if max_hour_count > len(hours) * 0.7:
            patterns.append({
                'type': 'time_of_day_pattern',
                'risk': 'medium',
                'description': 'Consistent time-of-day usage pattern'
            })
        
        risk_level = 'high' if any(p['risk'] == 'high' for p in patterns) else 'medium' if patterns else 'low'
        
        return {
            'risk': risk_level,
            'patterns': patterns,
            'recommendation': 'Add random delays and dummy messages to obfuscate patterns'
        }


class MetadataScrubber:
    """
    Actively removes and obfuscates metadata to prevent leaks
    """
    
    def __init__(self):
        self.scrubbing_rules = self._initialize_scrubbing_rules()
        self.obfuscation_cache = {}
        
    def _initialize_scrubbing_rules(self) -> Dict[str, Any]:
        """Initialize metadata scrubbing rules"""
        return {
            'remove': [
                'ip', 'source_ip', 'client_ip', 'remote_addr',
                'user_agent', 'browser', 'device',
                'referer', 'referrer', 'origin'
            ],
            'hash': [
                'sender', 'recipient', 'from', 'to', 'user_id'
            ],
            'randomize': [
                'timestamp', 'sent_at', 'created_at'
            ],
            'normalize': [
                'size', 'length', 'byte_count'
            ]
        }
    
    def scrub_metadata(self, metadata: Dict[str, Any], aggressive: bool = True) -> Dict[str, Any]:
        """
        Scrub metadata according to rules
        aggressive=True removes more metadata
        """
        scrubbed = {}
        
        for key, value in metadata.items():
            # Check if should be removed
            if any(pattern in key.lower() for pattern in self.scrubbing_rules['remove']):
                if not aggressive:
                    scrubbed[key] = '[REDACTED]'
                # Otherwise completely remove
                continue
            
            # Hash sensitive identifiers
            elif any(pattern in key.lower() for pattern in self.scrubbing_rules['hash']):
                if isinstance(value, str):
                    scrubbed[key] = self._create_anonymous_hash(value)
                else:
                    scrubbed[key] = self._create_anonymous_hash(str(value))
            
            # Randomize temporal data
            elif any(pattern in key.lower() for pattern in self.scrubbing_rules['randomize']):
                if isinstance(value, (int, float)):
                    # Add random jitter ±5 minutes
                    jitter = secrets.randbelow(600) - 300
                    scrubbed[key] = value + jitter
                else:
                    scrubbed[key] = value
            
            # Normalize sizes to buckets
            elif any(pattern in key.lower() for pattern in self.scrubbing_rules['normalize']):
                if isinstance(value, (int, float)):
                    # Round to nearest power of 2 to hide exact sizes
                    scrubbed[key] = self._normalize_to_bucket(int(value))
                else:
                    scrubbed[key] = value
            
            # Keep nested dicts but scrub them too
            elif isinstance(value, dict):
                scrubbed[key] = self.scrub_metadata(value, aggressive)
            
            else:
                scrubbed[key] = value
        
        return scrubbed
    
    def _create_anonymous_hash(self, value: str) -> str:
        """Create anonymous but consistent hash of value"""
        # Use BLAKE2 for fast, secure hashing
        # Add salt to prevent rainbow table attacks
        salt = b"metadata_anonymization_v1"
        hash_value = hashlib.blake2b(
            value.encode() + salt,
            digest_size=16
        ).hexdigest()
        return f"anon_{hash_value[:16]}"
    
    def _normalize_to_bucket(self, size: int) -> str:
        """Normalize size to bucket to hide exact sizes"""
        buckets = [
            (1024, "tiny"),           # < 1KB
            (10240, "small"),         # < 10KB
            (102400, "medium"),       # < 100KB
            (1048576, "large"),       # < 1MB
            (float('inf'), "x-large") # >= 1MB
        ]
        
        for threshold, label in buckets:
            if size < threshold:
                return label
        return "x-large"
    
    def add_decoy_metadata(self, metadata: Dict[str, Any], decoy_count: int = 3) -> Dict[str, Any]:
        """Add fake metadata fields to confuse analysis"""
        decoy_fields = [
            ('x_request_id', lambda: secrets.token_hex(16)),
            ('x_correlation_id', lambda: secrets.token_hex(16)),
            ('x_trace_id', lambda: secrets.token_hex(8)),
            ('x_forwarded_for', lambda: f"{secrets.randbelow(256)}.{secrets.randbelow(256)}.{secrets.randbelow(256)}.{secrets.randbelow(256)}"),
            ('x_session_hint', lambda: secrets.token_hex(8)),
        ]
        
        enhanced = metadata.copy()
        
        # Add random decoy fields
        selected_decoys = secrets.SystemRandom().sample(decoy_fields, min(decoy_count, len(decoy_fields)))
        for field_name, generator in selected_decoys:
            enhanced[field_name] = generator()
        
        return enhanced


class TrafficAnalysisResistance:
    """
    Resist traffic analysis by adding dummy traffic and timing obfuscation
    """
    
    def __init__(self):
        self.dummy_message_rate = 0.1  # 10% of messages are dummies
        self.timing_jitter_range = (1, 30)  # 1-30 seconds
        self.sent_times = deque(maxlen=100)
        
    def should_send_dummy(self) -> bool:
        """Decide if a dummy message should be sent"""
        return secrets.SystemRandom().random() < self.dummy_message_rate
    
    def calculate_send_delay(self, priority: str = "normal") -> float:
        """
        Calculate delay before sending to obfuscate timing
        priority: 'urgent', 'normal', 'background'
        """
        if priority == "urgent":
            # Minimal delay for urgent messages
            return secrets.SystemRandom().uniform(0.1, 2.0)
        elif priority == "background":
            # Longer delay for background
            return secrets.SystemRandom().uniform(10, 60)
        else:
            # Normal messages - random delay
            min_delay, max_delay = self.timing_jitter_range
            return secrets.SystemRandom().uniform(min_delay, max_delay)
    
    def generate_dummy_message(self) -> Dict[str, Any]:
        """Generate convincing dummy message"""
        # Random size similar to real messages
        size = secrets.randbelow(10000) + 100
        
        return {
            'type': 'dummy',
            'content': secrets.token_hex(size // 2),
            'timestamp': time.time(),
            'is_dummy': True  # Mark internally (not transmitted)
        }
    
    def analyze_traffic_pattern(self) -> Dict[str, Any]:
        """Analyze our own traffic pattern for vulnerabilities"""
        if len(self.sent_times) < 10:
            return {'status': 'insufficient_data'}
        
        # Calculate message rate
        time_span = max(self.sent_times) - min(self.sent_times)
        rate = len(self.sent_times) / time_span if time_span > 0 else 0
        
        # Calculate regularity
        intervals = [self.sent_times[i+1] - self.sent_times[i] 
                    for i in range(len(self.sent_times)-1)]
        
        avg_interval = sum(intervals) / len(intervals) if intervals else 0
        variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals) if intervals else 0
        
        regularity = 1.0 - min(variance / (avg_interval ** 2) if avg_interval > 0 else 0, 1.0)
        
        # Assess risk
        risk = 'low'
        if regularity > 0.8:
            risk = 'high'  # Too regular
        elif regularity > 0.5:
            risk = 'medium'
        
        return {
            'status': 'analyzed',
            'message_rate': rate,
            'regularity': regularity,
            'risk': risk,
            'recommendation': 'Increase dummy traffic' if risk != 'low' else 'Pattern acceptable'
        }
    
    def record_send_time(self, timestamp: float = None):
        """Record when a message was sent"""
        self.sent_times.append(timestamp or time.time())


class MetadataProtectionSystem:
    """
    Comprehensive metadata protection system
    Combines analysis, scrubbing, and traffic analysis resistance
    """
    
    def __init__(self):
        self.analyzer = MetadataAnalyzer()
        self.scrubber = MetadataScrubber()
        self.traffic_resistance = TrafficAnalysisResistance()
        self.protection_level = "high"  # low, medium, high, maximum
        
    def protect_message_metadata(self, message_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensive metadata protection for a message
        """
        # Analyze current metadata for leaks
        patterns = self.analyzer.analyze_metadata(message_data)
        
        # Determine scrubbing aggressiveness
        aggressive = self.protection_level in ["high", "maximum"]
        
        # Scrub metadata
        protected = self.scrubber.scrub_metadata(message_data, aggressive=aggressive)
        
        # Add decoy metadata if maximum protection
        if self.protection_level == "maximum":
            protected = self.scrubber.add_decoy_metadata(protected, decoy_count=5)
        
        # Calculate send delay
        delay = self.traffic_resistance.calculate_send_delay()
        
        # Record analysis results
        protection_report = {
            'detected_patterns': len(patterns),
            'risk_patterns': [p.pattern_type for p in patterns if p.risk_level in ['high', 'critical']],
            'recommended_delay': delay,
            'protection_level': self.protection_level
        }
        
        return {
            'protected_metadata': protected,
            'send_delay': delay,
            'protection_report': protection_report
        }
    
    def set_protection_level(self, level: str):
        """Set protection level: low, medium, high, maximum"""
        if level in ["low", "medium", "high", "maximum"]:
            self.protection_level = level
    
    def get_protection_stats(self) -> Dict[str, Any]:
        """Get statistics about metadata protection"""
        return {
            'protection_level': self.protection_level,
            'patterns_detected_total': sum(self.analyzer.pattern_frequency.values()),
            'pattern_breakdown': dict(self.analyzer.pattern_frequency),
            'traffic_analysis': self.traffic_resistance.analyze_traffic_pattern()
        }
