"""
Encrypted database for persistent storage with military-grade security
Stores user accounts, public keys, and sessions while keeping messages memory-only
"""

import sqlite3
import json
import secrets
import base64
import hashlib
from typing import Optional, Dict, Any, List
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import threading

class EncryptedDatabase:
    """Military-grade encrypted database for persistent storage"""
    
    def __init__(self, db_path: str = "secure_data.db", encryption_key: str = None):
        """
        Initialize encrypted database
        
        Args:
            db_path: Path to SQLite database file
            encryption_key: Master encryption key (generated if not provided)
        """
        self.db_path = db_path
        self.key_file = "db.key"
        self._lock = threading.Lock()
        
        # Load or generate encryption key
        if encryption_key is None:
            encryption_key = self._load_or_generate_key()
        
        self.encryption_key = self._derive_key(encryption_key)
        self.cipher = ChaCha20Poly1305(self.encryption_key)
        
        # Initialize database
        self.init_database()
    
    def _load_or_generate_key(self) -> str:
        """Load existing key from file or generate a new one"""
        if os.path.exists(self.key_file):
            # Load existing key
            try:
                with open(self.key_file, 'r') as f:
                    key = f.read().strip()
                print(f"🔑 Loaded existing database encryption key from {self.key_file}")
                return key
            except Exception as e:
                print(f"⚠️  Failed to load key file: {e}")
                print(f"🔑 Generating new database encryption key")
        
        # Generate new key
        key = base64.urlsafe_b64encode(os.urandom(32)).decode()
        
        # Save key to file
        try:
            with open(self.key_file, 'w') as f:
                f.write(key)
            print(f"🔑 Generated and saved database encryption key to {self.key_file}")
            print(f"⚠️  IMPORTANT: Keep {self.key_file} secure and backed up!")
        except Exception as e:
            print(f"⚠️  Failed to save key file: {e}")
            print(f"⚠️  Key: {key}")
        
        return key
    
    def _derive_key(self, password: str) -> bytes:
        """Derive encryption key from password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'military_secure_db_salt_v1_2025',
            iterations=100000,
        )
        return kdf.derive(password.encode())
    
    def _encrypt_data(self, data: str) -> str:
        """Encrypt data before storing"""
        nonce = os.urandom(12)
        ciphertext = self.cipher.encrypt(nonce, data.encode(), None)
        # Combine nonce + ciphertext
        encrypted = base64.b64encode(nonce + ciphertext).decode()
        return encrypted
    
    def _decrypt_data(self, encrypted: str) -> str:
        """Decrypt data after retrieval"""
        try:
            combined = base64.b64decode(encrypted)
            nonce = combined[:12]
            ciphertext = combined[12:]
            plaintext = self.cipher.decrypt(nonce, ciphertext, None)
            return plaintext.decode()
        except Exception as e:
            print(f"❌ Decryption failed: {e}")
            return None
    
    def init_database(self):
        """Initialize database schema"""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Users table - stores encrypted user data
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    password_salt TEXT NOT NULL,
                    encrypted_data TEXT NOT NULL,
                    fingerprint TEXT,
                    created_at REAL NOT NULL,
                    last_login REAL,
                    active INTEGER DEFAULT 1
                )
            ''')
            
            # Public keys table - for key exchange (not encrypted)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS public_keys (
                    user_id TEXT PRIMARY KEY,
                    identity_key TEXT NOT NULL,
                    signed_prekey TEXT NOT NULL,
                    verify_key TEXT NOT NULL,
                    quantum_public_key TEXT,
                    created_at REAL NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            ''')
            
            # Sessions table - for session management
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    encrypted_data TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    last_activity REAL NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            ''')
            
            # Audit log - security events
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    event_type TEXT NOT NULL,
                    user_id TEXT,
                    session_id TEXT,
                    ip_address TEXT,
                    success INTEGER,
                    encrypted_details TEXT
                )
            ''')
            
            # Create indices for performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id)')
            
            # Migrate existing database to add password columns if they don't exist
            try:
                cursor.execute("SELECT password_hash FROM users LIMIT 1")
            except sqlite3.OperationalError:
                # Columns don't exist, add them
                print("🔄 Migrating database: Adding password authentication columns...")
                cursor.execute("ALTER TABLE users ADD COLUMN password_hash TEXT DEFAULT ''")
                cursor.execute("ALTER TABLE users ADD COLUMN password_salt TEXT DEFAULT ''")
                print("✅ Database migration completed")
            
            conn.commit()
            conn.close()
        
        print("✅ Encrypted database initialized")
    
    def _hash_password(self, password: str, salt: bytes = None) -> tuple:
        """Hash password with PBKDF2-SHA256"""
        if salt is None:
            salt = secrets.token_bytes(32)
        
        pwd_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000  # iterations
        )
        return pwd_hash, salt
    
    def _verify_password(self, password: str, pwd_hash: bytes, salt: bytes) -> bool:
        """Verify password against stored hash"""
        new_hash, _ = self._hash_password(password, salt)
        return new_hash == pwd_hash
    
    def save_user(self, user_id: str, user_data: Dict[str, Any], password: str = None) -> bool:
        """Save user with encrypted private data and password"""
        try:
            with self._lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Hash password if provided
                if password:
                    pwd_hash, salt = self._hash_password(password)
                    pwd_hash_b64 = base64.b64encode(pwd_hash).decode()
                    salt_b64 = base64.b64encode(salt).decode()
                else:
                    # For existing users without password (backward compatibility)
                    pwd_hash_b64 = ''
                    salt_b64 = ''
                
                # Extract public keys (not encrypted - needed for key exchange)
                public_keys = user_data.get('public_keys', {})
                
                # Encrypt private data
                private_data = {
                    'alias': user_data.get('alias'),
                    'qr_code': user_data.get('qr_code'),
                    'metadata': user_data.get('metadata', {})
                }
                encrypted_data = self._encrypt_data(json.dumps(private_data))
                
                # Get created_at timestamp
                created_at = public_keys.get('created_at', datetime.now().timestamp())
                
                # Store user with password
                cursor.execute('''
                    INSERT OR REPLACE INTO users 
                    (user_id, password_hash, password_salt, encrypted_data, fingerprint, created_at, last_login, active)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                ''', (
                    user_id,
                    pwd_hash_b64,
                    salt_b64,
                    encrypted_data,
                    user_data.get('fingerprint', ''),
                    created_at,
                    datetime.now().timestamp()
                ))
                
                # Store public keys
                cursor.execute('''
                    INSERT OR REPLACE INTO public_keys
                    (user_id, identity_key, signed_prekey, verify_key, quantum_public_key, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    user_id,
                    public_keys.get('identity', ''),
                    public_keys.get('signed_prekey', ''),
                    public_keys.get('verify_key', ''),
                    public_keys.get('quantum_public_key', ''),  # May be empty for now
                    created_at
                ))
                
                conn.commit()
                conn.close()
            
            # Log audit event
            self.log_audit_event('user_created', user_id, success=True)
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to save user: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def verify_user_password(self, user_id: str, password: str) -> bool:
        """Verify user password during login"""
        try:
            with self._lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT password_hash, password_salt 
                    FROM users 
                    WHERE user_id = ? AND active = 1
                ''', (user_id,))
                
                result = cursor.fetchone()
                conn.close()
                
                if not result:
                    return False
                
                pwd_hash_b64, salt_b64 = result
                
                # Backward compatibility: if no password set, deny access
                if not pwd_hash_b64 or not salt_b64:
                    return False
                
                pwd_hash = base64.b64decode(pwd_hash_b64)
                salt = base64.b64decode(salt_b64)
                
                return self._verify_password(password, pwd_hash, salt)
                
        except Exception as e:
            print(f"❌ Password verification failed: {e}")
            return False
    
    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve and decrypt user data"""
        try:
            with self._lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Get user data
                cursor.execute('SELECT encrypted_data, fingerprint, created_at, last_login FROM users WHERE user_id = ? AND active = 1', (user_id,))
                user_row = cursor.fetchone()
                
                if not user_row:
                    conn.close()
                    return None
                
                encrypted_data, fingerprint, created_at, last_login = user_row
                
                # Get public keys
                cursor.execute('SELECT identity_key, signed_prekey, verify_key, quantum_public_key FROM public_keys WHERE user_id = ?', (user_id,))
                keys_row = cursor.fetchone()
                
                conn.close()

            if not keys_row:
                return None

            identity_key, signed_prekey, verify_key, quantum_public_key = keys_row
            
            # Decrypt private data
            decrypted_str = self._decrypt_data(encrypted_data)
            
            if not decrypted_str:
                return None
                
            private_data = json.loads(decrypted_str)
            
            # Combine data
            user_data = {
                'user_id': user_id,
                'alias': private_data.get('alias'),
                'qr_code': private_data.get('qr_code'),
                'fingerprint': fingerprint,
                'created_at': created_at,
                'last_login': last_login,
                'metadata': private_data.get('metadata', {}),
                'public_keys': {
                    'identity': identity_key,
                    'signed_prekey': signed_prekey,
                    'verify_key': verify_key,
                    'quantum_public_key': quantum_public_key,
                }
            }
            
            return user_data
            
        except Exception as e:
            print(f"❌ Failed to get user: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def user_exists(self, user_id: str) -> bool:
        """Check if user exists"""
        try:
            with self._lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute('SELECT 1 FROM users WHERE user_id = ? AND active = 1', (user_id,))
                exists = cursor.fetchone() is not None
                conn.close()
                return exists
        except Exception as e:
            print(f"❌ Failed to check user existence: {e}")
            return False
    
    def update_last_login(self, user_id: str):
        """Update user's last login time"""
        try:
            with self._lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute(
                    'UPDATE users SET last_login = ? WHERE user_id = ?',
                    (datetime.now().timestamp(), user_id)
                )
                conn.commit()
                conn.close()
        except Exception as e:
            print(f"❌ Failed to update last login: {e}")
    
    def save_session(self, session_id: str, user_id: str, session_data: Dict[str, Any], ttl_seconds: int = 1800):
        """Save encrypted session data"""
        try:
            with self._lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                encrypted_data = self._encrypt_data(json.dumps(session_data))
                now = datetime.now().timestamp()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO sessions
                    (session_id, user_id, encrypted_data, created_at, expires_at, last_activity)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    session_id,
                    user_id,
                    encrypted_data,
                    now,
                    now + ttl_seconds,
                    now
                ))
                
                conn.commit()
                conn.close()
            return True
            
        except Exception as e:
            print(f"❌ Failed to save session: {e}")
            return False
    
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve and decrypt session data"""
        try:
            with self._lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT user_id, encrypted_data, expires_at 
                    FROM sessions 
                    WHERE session_id = ?
                ''', (session_id,))
                
                row = cursor.fetchone()
                conn.close()
            
            if not row:
                return None
            
            # Check expiration
            if datetime.now().timestamp() > row[2]:
                self.delete_session(session_id)
                return None
            
            # Decrypt session data
            decrypted_str = self._decrypt_data(row[1])
            if not decrypted_str:
                return None
                
            session_data = json.loads(decrypted_str)
            session_data['user_id'] = row[0]
            
            # Update last activity
            self.update_session_activity(session_id)
            
            return session_data
            
        except Exception as e:
            print(f"❌ Failed to get session: {e}")
            return None
    
    def update_session_activity(self, session_id: str):
        """Update session last activity time"""
        try:
            with self._lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute(
                    'UPDATE sessions SET last_activity = ? WHERE session_id = ?',
                    (datetime.now().timestamp(), session_id)
                )
                conn.commit()
                conn.close()
        except Exception as e:
            print(f"❌ Failed to update session activity: {e}")
    
    def delete_session(self, session_id: str):
        """Delete session"""
        try:
            with self._lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
                conn.commit()
                conn.close()
        except Exception as e:
            print(f"❌ Failed to delete session: {e}")
    
    def cleanup_expired_sessions(self):
        """Remove expired sessions"""
        try:
            with self._lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute(
                    'DELETE FROM sessions WHERE expires_at < ?',
                    (datetime.now().timestamp(),)
                )
                deleted = cursor.rowcount
                conn.commit()
                conn.close()
            
            if deleted > 0:
                print(f"🧹 Cleaned up {deleted} expired sessions")
                
        except Exception as e:
            print(f"❌ Failed to cleanup sessions: {e}")
    
    def log_audit_event(self, event_type: str, user_id: str = None, session_id: str = None, 
                       ip_address: str = None, success: bool = True, details: Dict = None):
        """Log security audit event"""
        try:
            with self._lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                encrypted_details = None
                if details:
                    encrypted_details = self._encrypt_data(json.dumps(details))
                
                cursor.execute('''
                    INSERT INTO audit_log
                    (timestamp, event_type, user_id, session_id, ip_address, success, encrypted_details)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    datetime.now().timestamp(),
                    event_type,
                    user_id,
                    session_id,
                    ip_address,
                    1 if success else 0,
                    encrypted_details
                ))
                
                conn.commit()
                conn.close()
            
        except Exception as e:
            print(f"❌ Failed to log audit event: {e}")
    
    def get_audit_log(self, user_id: str = None, limit: int = 100) -> List[Dict]:
        """Retrieve audit log entries"""
        try:
            with self._lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                if user_id:
                    cursor.execute('''
                        SELECT * FROM audit_log 
                        WHERE user_id = ? 
                        ORDER BY timestamp DESC 
                        LIMIT ?
                    ''', (user_id, limit))
                else:
                    cursor.execute('''
                        SELECT * FROM audit_log 
                        ORDER BY timestamp DESC 
                        LIMIT ?
                    ''', (limit,))
                
                rows = cursor.fetchall()
                conn.close()
            
            events = []
            for row in rows:
                event = {
                    'id': row[0],
                    'timestamp': row[1],
                    'event_type': row[2],
                    'user_id': row[3],
                    'session_id': row[4],
                    'ip_address': row[5],
                    'success': bool(row[6]),
                }
                
                if row[7]:  # encrypted_details
                    try:
                        decrypted = self._decrypt_data(row[7])
                        if decrypted:
                            event['details'] = json.loads(decrypted)
                    except:
                        event['details'] = None
                
                events.append(event)
            
            return events
            
        except Exception as e:
            print(f"❌ Failed to get audit log: {e}")
            return []
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        try:
            with self._lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('SELECT COUNT(*) FROM users WHERE active = 1')
                total_users = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM sessions')
                active_sessions = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM audit_log')
                total_events = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM sessions WHERE expires_at < ?', 
                              (datetime.now().timestamp(),))
                expired_sessions = cursor.fetchone()[0]
                
                conn.close()
            
            return {
                'total_users': total_users,
                'active_sessions': active_sessions,
                'total_audit_events': total_events,
                'expired_sessions': expired_sessions
            }
            
        except Exception as e:
            print(f"❌ Failed to get database stats: {e}")
            return {}
    
    def get_all_users(self, active_only: bool = True) -> List[str]:
        """Get list of all user IDs"""
        try:
            with self._lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                if active_only:
                    cursor.execute('SELECT user_id FROM users WHERE active = 1')
                else:
                    cursor.execute('SELECT user_id FROM users')
                
                users = [row[0] for row in cursor.fetchall()]
                conn.close()
                return users
                
        except Exception as e:
            print(f"❌ Failed to get all users: {e}")
            return []
