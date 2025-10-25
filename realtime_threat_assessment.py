"""
Enhanced Real-Time Threat Assessment System
Uses advanced ML techniques and behavioral analysis for real-time threat detection
Includes trained machine learning models for anomaly detection
"""

import time
import json
import hashlib
import secrets
import numpy as np
import pickle
import os
from typing import Dict, List, Any, Optional, Tuple, Callable
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
import threading
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')


@dataclass
class ThreatIndicator:
    """Represents a security threat indicator"""
    indicator_type: str
    severity: str  # low, medium, high, critical
    confidence: float  # 0.0 to 1.0
    description: str
    detected_at: float
    source: str
    metadata: Dict[str, Any]


@dataclass
class ThreatAssessment:
    """Complete threat assessment result"""
    threat_level: str  # safe, low, medium, high, critical
    risk_score: float  # 0-100
    indicators: List[ThreatIndicator]
    recommended_actions: List[str]
    timestamp: float
    assessment_id: str


class BehavioralProfiler:
    """
    Creates and maintains behavioral profiles for users
    Detects deviations from normal behavior
    """
    
    def __init__(self):
        self.user_profiles = defaultdict(lambda: {
            'login_times': deque(maxlen=100),
            'message_patterns': deque(maxlen=100),
            'ip_addresses': deque(maxlen=50),
            'user_agents': deque(maxlen=20),
            'session_durations': deque(maxlen=50),
            'actions': deque(maxlen=200),
            'typical_hours': defaultdict(int),
            'typical_days': defaultdict(int),
            'average_session_duration': 0,
            'message_frequency': 0,
        })
        self._lock = threading.Lock()
    
    def update_profile(self, user_id: str, activity: Dict[str, Any]):
        """Update user behavioral profile"""
        with self._lock:
            profile = self.user_profiles[user_id]
            
            # Track login patterns
            if activity.get('type') == 'login':
                timestamp = activity.get('timestamp', time.time())
                profile['login_times'].append(timestamp)
                
                # Track typical hours and days
                local_time = time.localtime(timestamp)
                profile['typical_hours'][local_time.tm_hour] += 1
                profile['typical_days'][local_time.tm_wday] += 1
            
            # Track message patterns
            elif activity.get('type') == 'message':
                profile['message_patterns'].append({
                    'timestamp': activity.get('timestamp', time.time()),
                    'size': activity.get('size', 0),
                    'recipient': hashlib.sha256(activity.get('recipient', '').encode()).hexdigest()[:16]
                })
            
            # Track IP addresses
            if 'ip' in activity:
                profile['ip_addresses'].append(activity['ip'])
            
            # Track user agents
            if 'user_agent' in activity:
                profile['user_agents'].append(activity['user_agent'])
            
            # Track actions
            if 'action' in activity:
                profile['actions'].append({
                    'action': activity['action'],
                    'timestamp': activity.get('timestamp', time.time())
                })
    
    def detect_anomalies(self, user_id: str, current_activity: Dict[str, Any]) -> List[ThreatIndicator]:
        """
        Detect anomalies in user behavior
        Returns list of threat indicators
        """
        indicators = []
        
        with self._lock:
            profile = self.user_profiles.get(user_id)
            if not profile:
                return indicators
            
            # Check time-based anomalies
            current_time = current_activity.get('timestamp', time.time())
            local_time = time.localtime(current_time)
            hour = local_time.tm_hour
            day = local_time.tm_wday
            
            # Unusual hour
            if profile['typical_hours']:
                hour_frequency = profile['typical_hours'].get(hour, 0)
                total_logins = sum(profile['typical_hours'].values())
                hour_probability = hour_frequency / total_logins if total_logins > 0 else 0
                
                if hour_probability < 0.05 and total_logins > 20:  # Less than 5% of usual activity
                    indicators.append(ThreatIndicator(
                        indicator_type='unusual_time',
                        severity='medium',
                        confidence=0.7,
                        description=f'Activity at unusual hour: {hour}:00',
                        detected_at=time.time(),
                        source='behavioral_profiler',
                        metadata={'hour': hour, 'probability': hour_probability}
                    ))
            
            # Check IP address anomalies
            if 'ip' in current_activity:
                current_ip = current_activity['ip']
                known_ips = list(profile['ip_addresses'])
                
                if known_ips and current_ip not in known_ips and len(known_ips) > 10:
                    indicators.append(ThreatIndicator(
                        indicator_type='new_ip',
                        severity='medium',
                        confidence=0.6,
                        description=f'Login from new IP address',
                        detected_at=time.time(),
                        source='behavioral_profiler',
                        metadata={'ip': current_ip, 'known_ips_count': len(set(known_ips))}
                    ))
            
            # Check user agent anomalies
            if 'user_agent' in current_activity:
                current_ua = current_activity['user_agent']
                known_uas = list(profile['user_agents'])
                
                if known_uas and current_ua not in known_uas and len(known_uas) > 5:
                    indicators.append(ThreatIndicator(
                        indicator_type='new_device',
                        severity='low',
                        confidence=0.5,
                        description='Activity from new device/browser',
                        detected_at=time.time(),
                        source='behavioral_profiler',
                        metadata={'user_agent': current_ua[:50]}
                    ))
            
            # Check for rapid successive actions
            recent_actions = [a for a in profile['actions'] 
                            if time.time() - a['timestamp'] < 60]
            
            if len(recent_actions) > 20:
                indicators.append(ThreatIndicator(
                    indicator_type='rapid_actions',
                    severity='high',
                    confidence=0.8,
                    description=f'Unusually rapid actions: {len(recent_actions)} in 1 minute',
                    detected_at=time.time(),
                    source='behavioral_profiler',
                    metadata={'action_count': len(recent_actions)}
                ))
        
        return indicators


class NetworkThreatAnalyzer:
    """
    Analyzes network-level threats
    """
    
    def __init__(self):
        self.ip_reputation = defaultdict(lambda: {'score': 100, 'incidents': []})
        self.rate_limits = defaultdict(lambda: deque(maxlen=100))
        self.known_malicious_patterns = self._load_malicious_patterns()
        self._lock = threading.Lock()
    
    def _load_malicious_patterns(self) -> Dict[str, Any]:
        """Load known malicious patterns"""
        return {
            'sql_injection': [
                r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
                r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
                r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
            ],
            'xss': [
                r"((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)",
                r"((\%3C)|<)((\%69)|i|(\%49))((\%6D)|m|(\%4D))((\%67)|g|(\%47))",
            ],
            'path_traversal': [
                r"((\%2E)|\.){2,}((\%2F)|\/)",
                r"\.\.\/",
                r"\.\.\\",
            ],
            'command_injection': [
                r";.*(\||&)",
                r"\|.*ls",
                r"&&.*cat",
            ]
        }
    
    def analyze_request(self, request_data: Dict[str, Any]) -> List[ThreatIndicator]:
        """Analyze network request for threats"""
        indicators = []
        
        ip = request_data.get('ip', '127.0.0.1')
        
        with self._lock:
            # Check IP reputation
            rep = self.ip_reputation[ip]
            if rep['score'] < 50:
                indicators.append(ThreatIndicator(
                    indicator_type='low_reputation_ip',
                    severity='high',
                    confidence=0.8,
                    description=f'Request from low reputation IP (score: {rep["score"]})',
                    detected_at=time.time(),
                    source='network_analyzer',
                    metadata={'ip': ip, 'score': rep['score'], 'incidents': len(rep['incidents'])}
                ))
            
            # Check rate limiting
            self.rate_limits[ip].append(time.time())
            recent_requests = [t for t in self.rate_limits[ip] if time.time() - t < 60]
            
            if len(recent_requests) > 30:  # More than 30 requests per minute
                indicators.append(ThreatIndicator(
                    indicator_type='rate_limit_exceeded',
                    severity='medium',
                    confidence=0.9,
                    description=f'Rate limit exceeded: {len(recent_requests)} requests/min',
                    detected_at=time.time(),
                    source='network_analyzer',
                    metadata={'ip': ip, 'request_count': len(recent_requests)}
                ))
                
                # Reduce IP reputation
                rep['score'] = max(0, rep['score'] - 10)
                rep['incidents'].append({
                    'type': 'rate_limit',
                    'timestamp': time.time()
                })
            
            # Check for malicious patterns in request
            request_str = json.dumps(request_data)
            for attack_type, patterns in self.known_malicious_patterns.items():
                for pattern in patterns:
                    import re
                    if re.search(pattern, request_str, re.IGNORECASE):
                        indicators.append(ThreatIndicator(
                            indicator_type=f'attack_{attack_type}',
                            severity='critical',
                            confidence=0.95,
                            description=f'Possible {attack_type} attack detected',
                            detected_at=time.time(),
                            source='network_analyzer',
                            metadata={'attack_type': attack_type, 'ip': ip}
                        ))
                        
                        # Severely reduce IP reputation
                        rep['score'] = max(0, rep['score'] - 30)
                        rep['incidents'].append({
                            'type': attack_type,
                            'timestamp': time.time()
                        })
                        break
        
        return indicators
    
    def report_incident(self, ip: str, incident_type: str, severity: str):
        """Report security incident for IP"""
        with self._lock:
            rep = self.ip_reputation[ip]
            penalty = {'low': 5, 'medium': 15, 'high': 25, 'critical': 40}.get(severity, 10)
            rep['score'] = max(0, rep['score'] - penalty)
            rep['incidents'].append({
                'type': incident_type,
                'severity': severity,
                'timestamp': time.time()
            })


class AIThreatCorrelator:
    """
    Correlates multiple threat indicators to assess overall threat level
    Uses ML models for advanced anomaly detection and threat prediction
    """
    
    def __init__(self):
        self.threat_history = deque(maxlen=1000)
        self.active_threats = {}
        self._lock = threading.Lock()
        
        # ML Models for threat detection
        self.anomaly_detector = None  # Isolation Forest for anomaly detection
        self.threat_classifier = None  # Random Forest for threat classification
        self.scaler = StandardScaler()
        self.model_trained = False
        # Lowered threshold so the threat models can train during demos/smaller test runs
        self.min_samples_for_training = 20
        self.model_path = 'threat_assessment_model.pkl'
        self.scaler_path = 'threat_assessment_scaler.pkl'
        
        # Training data storage
        self.training_features = deque(maxlen=5000)
        self.training_labels = deque(maxlen=5000)
        
        # Load pre-trained models if available
        self._load_models()
    
    def _load_models(self):
        """Load pre-trained ML models if they exist"""
        try:
            if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
                with open(self.model_path, 'rb') as f:
                    models = pickle.load(f)
                    self.anomaly_detector = models.get('anomaly_detector')
                    self.threat_classifier = models.get('threat_classifier')
                
                with open(self.scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                
                self.model_trained = True
                print("✅ ML threat assessment models loaded successfully")
        except Exception as e:
            print(f"ℹ️  No pre-trained models found, will train on new data: {e}")
    
    def _save_models(self):
        """Save trained ML models"""
        try:
            models = {
                'anomaly_detector': self.anomaly_detector,
                'threat_classifier': self.threat_classifier
            }
            with open(self.model_path, 'wb') as f:
                pickle.dump(models, f)
            
            with open(self.scaler_path, 'wb') as f:
                pickle.dump(self.scaler, f)
            
            print("✅ ML threat assessment models saved successfully")
        except Exception as e:
            print(f"⚠️  Failed to save models: {e}")
    
    def _extract_ml_features(self, indicators: List[ThreatIndicator], 
                            assessment_metadata: Dict = None) -> np.ndarray:
        """Extract features for ML model from threat indicators"""
        # Feature vector: [indicator_count, avg_confidence, max_severity, 
        #                  type_diversity, critical_count, high_count, 
        #                  medium_count, low_count, attack_indicators, behavioral_indicators]
        
        if not indicators:
            return np.array([0] * 10)
        
        severity_map = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        severities = [severity_map.get(ind.severity, 0) for ind in indicators]
        confidences = [ind.confidence for ind in indicators]
        
        # Count by severity
        critical_count = sum(1 for ind in indicators if ind.severity == 'critical')
        high_count = sum(1 for ind in indicators if ind.severity == 'high')
        medium_count = sum(1 for ind in indicators if ind.severity == 'medium')
        low_count = sum(1 for ind in indicators if ind.severity == 'low')
        
        # Count attack vs behavioral indicators
        attack_count = sum(1 for ind in indicators if 'attack_' in ind.indicator_type)
        behavioral_count = sum(1 for ind in indicators if ind.indicator_type in 
                              ['unusual_time', 'new_ip', 'new_device', 'rapid_actions'])
        
        # Type diversity
        unique_types = len(set(ind.indicator_type for ind in indicators))
        
        features = [
            len(indicators),  # Total indicator count
            np.mean(confidences) if confidences else 0,  # Average confidence
            max(severities) if severities else 0,  # Max severity
            unique_types,  # Type diversity
            critical_count,
            high_count,
            medium_count,
            low_count,
            attack_count,
            behavioral_count
        ]
        
        return np.array(features)
    
    def _train_ml_models(self):
        """Train ML models on collected threat data"""
        if len(self.training_features) < self.min_samples_for_training:
            return
        
        try:
            print(f"🎓 Training ML threat models with {len(self.training_features)} samples...")
            
            X = np.array(list(self.training_features))
            y = np.array(list(self.training_labels))
            
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            
            # Train Isolation Forest for anomaly detection
            self.anomaly_detector = IsolationForest(
                contamination=0.1,  # Expect 10% anomalies
                random_state=42,
                n_estimators=100
            )
            self.anomaly_detector.fit(X_scaled)
            
            # Train Random Forest for threat classification
            if len(np.unique(y)) > 1:  # Need at least 2 classes
                self.threat_classifier = RandomForestClassifier(
                    n_estimators=100,
                    max_depth=10,
                    random_state=42
                )
                self.threat_classifier.fit(X_scaled, y)
            
            self.model_trained = True
            self._save_models()
            print("✅ ML threat models trained successfully")
            
        except Exception as e:
            print(f"⚠️  ML model training failed: {e}")
    
    def _predict_threat_with_ml(self, features: np.ndarray) -> Tuple[bool, float, str]:
        """
        Use ML models to predict if activity is anomalous
        Returns: (is_anomaly, anomaly_score, predicted_threat_level)
        """
        if not self.model_trained or self.anomaly_detector is None:
            return False, 0.0, 'unknown'
        
        try:
            # Scale features
            features_scaled = self.scaler.transform(features.reshape(1, -1))
            
            # Anomaly detection
            anomaly_pred = self.anomaly_detector.predict(features_scaled)[0]
            anomaly_score = self.anomaly_detector.score_samples(features_scaled)[0]
            is_anomaly = anomaly_pred == -1  # -1 means anomaly
            
            # Threat classification
            predicted_level = 'unknown'
            if self.threat_classifier is not None:
                threat_pred = self.threat_classifier.predict(features_scaled)[0]
                threat_levels = ['safe', 'low', 'medium', 'high', 'critical']
                if 0 <= threat_pred < len(threat_levels):
                    predicted_level = threat_levels[threat_pred]
            
            return is_anomaly, abs(anomaly_score), predicted_level
            
        except Exception as e:
            print(f"⚠️  ML prediction error: {e}")
            return False, 0.0, 'unknown'
    
    def correlate_indicators(self, indicators: List[ThreatIndicator]) -> ThreatAssessment:
        """
        Correlate multiple threat indicators into comprehensive assessment
        Uses both rule-based and ML-based analysis
        """
        if not indicators:
            return ThreatAssessment(
                threat_level='safe',
                risk_score=0,
                indicators=[],
                recommended_actions=[],
                timestamp=time.time(),
                assessment_id=secrets.token_hex(8)
            )
        
        # Extract ML features
        ml_features = self._extract_ml_features(indicators)
        
        # ML-based anomaly detection
        ml_is_anomaly = False
        ml_anomaly_score = 0.0
        ml_predicted_level = 'unknown'
        
        if self.model_trained:
            ml_is_anomaly, ml_anomaly_score, ml_predicted_level = self._predict_threat_with_ml(ml_features)
        
        # Calculate base risk score using rule-based system
        risk_score = 0
        severity_weights = {
            'low': 10,
            'medium': 25,
            'high': 50,
            'critical': 80
        }
        
        for indicator in indicators:
            weight = severity_weights.get(indicator.severity, 10)
            risk_score += weight * indicator.confidence
        
        # Apply correlation multipliers
        indicator_types = [ind.indicator_type for ind in indicators]
        
        # Multiple different attack types = more serious
        unique_types = len(set(indicator_types))
        if unique_types >= 3:
            risk_score *= 1.5
        
        # Same type repeated = potentially automated attack
        from collections import Counter
        type_counts = Counter(indicator_types)
        max_repeat = max(type_counts.values())
        if max_repeat >= 3:
            risk_score *= 1.3
        
        # ML anomaly boost
        if ml_is_anomaly:
            risk_score *= 1.2  # 20% increase if ML detects anomaly
            print(f"🤖 ML Anomaly Detected! Score: {ml_anomaly_score:.3f}, Predicted: {ml_predicted_level}")
        
        # Cap at 100
        risk_score = min(risk_score, 100)
        
        # Determine threat level (consider both rules and ML)
        if risk_score >= 75:
            threat_level = 'critical'
        elif risk_score >= 50:
            threat_level = 'high'
        elif risk_score >= 25:
            threat_level = 'medium'
        elif risk_score > 0:
            threat_level = 'low'
        else:
            threat_level = 'safe'
        
        # Override with ML prediction if it's more severe
        if ml_predicted_level != 'unknown':
            level_severity = {'safe': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
            if level_severity.get(ml_predicted_level, 0) > level_severity.get(threat_level, 0):
                threat_level = ml_predicted_level
                print(f"🤖 ML Model upgraded threat level to: {threat_level}")
        
        # Generate recommended actions
        recommended_actions = self._generate_recommendations(threat_level, indicators)
        
        assessment = ThreatAssessment(
            threat_level=threat_level,
            risk_score=risk_score,
            indicators=indicators,
            recommended_actions=recommended_actions,
            timestamp=time.time(),
            assessment_id=secrets.token_hex(8)
        )
        
        # Store in history and collect training data
        with self._lock:
            self.threat_history.append(assessment)
            
            # Add to training data
            threat_level_map = {'safe': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
            self.training_features.append(ml_features)
            self.training_labels.append(threat_level_map.get(threat_level, 0))
            
            # Train models when we hit minimum samples or every 100 samples thereafter
            sample_count = len(self.training_features)
            if sample_count == self.min_samples_for_training or \
               (sample_count > self.min_samples_for_training and sample_count % 100 == 0):
                print(f"\n🎓 Auto-training ML models with {sample_count} samples...")
                self._train_ml_models()
        
        return assessment
    
    def _generate_recommendations(self, threat_level: str, 
                                 indicators: List[ThreatIndicator]) -> List[str]:
        """Generate actionable recommendations based on threats"""
        actions = []
        
        if threat_level == 'critical':
            actions.append('IMMEDIATE: Block source IP/user')
            actions.append('IMMEDIATE: Alert security team')
            actions.append('Initiate emergency protocols')
            actions.append('Preserve forensic evidence')
        elif threat_level == 'high':
            actions.append('Block source temporarily')
            actions.append('Require additional authentication')
            actions.append('Monitor closely for escalation')
            actions.append('Log all activity for analysis')
        elif threat_level == 'medium':
            actions.append('Increase monitoring level')
            actions.append('Apply rate limiting')
            actions.append('Flag for security review')
        elif threat_level == 'low':
            actions.append('Continue monitoring')
            actions.append('Log for pattern analysis')
        
        # Add indicator-specific recommendations
        indicator_types = set(ind.indicator_type for ind in indicators)
        
        if any('attack_' in t for t in indicator_types):
            actions.append('Enable WAF rules for detected attack type')
        
        if 'rapid_actions' in indicator_types:
            actions.append('Implement CAPTCHA challenge')
        
        if 'new_ip' in indicator_types or 'new_device' in indicator_types:
            actions.append('Require identity verification')
        
        return actions


class RealTimeThreatSystem:
    """
    Comprehensive real-time threat assessment system
    Integrates all threat detection components
    """
    
    def __init__(self):
        self.behavioral_profiler = BehavioralProfiler()
        self.network_analyzer = NetworkThreatAnalyzer()
        self.correlator = AIThreatCorrelator()
        self.alert_callbacks = []
        self._lock = threading.Lock()
    
    def assess_threat(self, user_id: str, activity: Dict[str, Any]) -> ThreatAssessment:
        """
        Perform comprehensive real-time threat assessment
        """
        all_indicators = []
        
        # Update behavioral profile and detect anomalies
        self.behavioral_profiler.update_profile(user_id, activity)
        behavioral_indicators = self.behavioral_profiler.detect_anomalies(user_id, activity)
        all_indicators.extend(behavioral_indicators)
        
        # Analyze network-level threats
        network_indicators = self.network_analyzer.analyze_request(activity)
        all_indicators.extend(network_indicators)
        
        # Correlate all indicators
        assessment = self.correlator.correlate_indicators(all_indicators)
        
        # Trigger alerts if needed
        if assessment.threat_level in ['high', 'critical']:
            self._trigger_alerts(assessment, user_id, activity)
        
        return assessment
    
    def register_alert_callback(self, callback: Callable[[ThreatAssessment, str, Dict], None]):
        """Register callback for threat alerts"""
        with self._lock:
            self.alert_callbacks.append(callback)
    
    def _trigger_alerts(self, assessment: ThreatAssessment, user_id: str, activity: Dict[str, Any]):
        """Trigger registered alert callbacks"""
        with self._lock:
            for callback in self.alert_callbacks:
                try:
                    callback(assessment, user_id, activity)
                except Exception as e:
                    print(f"Error in alert callback: {e}")
    
    def report_incident(self, ip: str, incident_type: str, severity: str):
        """Report security incident"""
        self.network_analyzer.report_incident(ip, incident_type, severity)
    
    def get_threat_statistics(self) -> Dict[str, Any]:
        """Get comprehensive threat statistics including ML model info"""
        recent_assessments = list(self.correlator.threat_history)
        
        if not recent_assessments:
            return {
                'total_assessments': 0,
                'threat_distribution': {},
                'average_risk_score': 0,
                'ml_model_trained': self.correlator.model_trained,
                'ml_training_samples': len(self.correlator.training_features)
            }
        
        threat_counts = defaultdict(int)
        total_risk = 0
        
        for assessment in recent_assessments:
            threat_counts[assessment.threat_level] += 1
            total_risk += assessment.risk_score
        
        return {
            'total_assessments': len(recent_assessments),
            'threat_distribution': dict(threat_counts),
            'average_risk_score': total_risk / len(recent_assessments),
            'recent_critical_count': threat_counts['critical'],
            'recent_high_count': threat_counts['high'],
            'ml_model_trained': self.correlator.model_trained,
            'ml_training_samples': len(self.correlator.training_features),
            'ml_model_accuracy': 'Trained' if self.correlator.model_trained else 'Training...'
        }
    
    def get_ml_model_status(self) -> Dict[str, Any]:
        """Get detailed ML model status"""
        return {
            'anomaly_detector_trained': self.correlator.anomaly_detector is not None,
            'threat_classifier_trained': self.correlator.threat_classifier is not None,
            'total_training_samples': len(self.correlator.training_features),
            'model_ready': self.correlator.model_trained,
            'min_samples_required': self.correlator.min_samples_for_training,
            'models_saved': os.path.exists(self.correlator.model_path)
        }
