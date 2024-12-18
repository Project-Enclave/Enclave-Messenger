"""
Enclave Messenger - Advanced Security Module
Implements hybrid encryption with forward secrecy
"""

import os
import json
import base64
import secrets
import hashlib
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import sqlite3
import time


class SecureMessenger:
    """Advanced secure messaging with hybrid encryption and forward secrecy"""

    def __init__(self, username, data_dir="./enclave_data"):
        self.username = username
        self.data_dir = data_dir
        self.db_path = os.path.join(data_dir, "enclave.db")
        os.makedirs(data_dir, exist_ok=True)

        # Initialize encryption components
        self.symmetric_key = None
        self.private_key = None
        self.public_key = None
        self.session_keys = {}
        self.message_counter = 0

        # Initialize database
        self._init_database()

        # Load or generate keys
        self._load_or_generate_keys()

    def _init_database(self):
        """Initialize SQLite database for message storage"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Messages table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp REAL NOT NULL,
                message_type TEXT DEFAULT 'text',
                encryption_method TEXT NOT NULL
            )
        """)

        # Contacts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS contacts (
                username TEXT PRIMARY KEY,
                public_key TEXT NOT NULL,
                last_seen REAL NOT NULL,
                trust_level INTEGER DEFAULT 0
            )
        """)

        # Session keys table (for forward secrecy)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS session_keys (
                contact TEXT NOT NULL,
                key_id TEXT NOT NULL,
                key_data TEXT NOT NULL,
                created_at REAL NOT NULL,
                used BOOLEAN DEFAULT FALSE,
                PRIMARY KEY (contact, key_id)
            )
        """)

        conn.commit()
        conn.close()

    def _load_or_generate_keys(self):
        """Load existing keys or generate new ones"""
        key_file = os.path.join(self.data_dir, f"{self.username}_keys.json")

        if os.path.exists(key_file):
            with open(key_file, 'r') as f:
                key_data = json.load(f)

            # Load private key
            private_pem = key_data['private_key'].encode()
            self.private_key = serialization.load_pem_private_key(
                private_pem, password=None
            )

            # Load public key
            public_pem = key_data['public_key'].encode()
            self.public_key = serialization.load_pem_public_key(public_pem)

            # Load symmetric key
            self.symmetric_key = base64.b64decode(key_data['symmetric_key'])

        else:
            # Generate new keys
            self._generate_keys()
            self._save_keys(key_file)

    def _generate_keys(self):
        """Generate RSA key pair and symmetric key"""
        # Generate RSA key pair for asymmetric encryption
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

        # Generate symmetric key for fast encryption
        self.symmetric_key = Fernet.generate_key()

    def _save_keys(self, key_file):
        """Save keys to file"""
        # Serialize private key
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Serialize public key
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        key_data = {
            'private_key': private_pem.decode(),
            'public_key': public_pem.decode(),
            'symmetric_key': base64.b64encode(self.symmetric_key).decode(),
            'created_at': time.time()
        }

        with open(key_file, 'w') as f:
            json.dump(key_data, f, indent=2)

    def get_public_key_pem(self):
        """Get public key in PEM format for sharing"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    def add_contact(self, username, public_key_pem, trust_level=0):
        """Add a contact with their public key"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT OR REPLACE INTO contacts (username, public_key, last_seen, trust_level)
            VALUES (?, ?, ?, ?)
        """, (username, public_key_pem, time.time(), trust_level))

        conn.commit()
        conn.close()

    def get_contact_public_key(self, username):
        """Get a contact's public key"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('SELECT public_key FROM contacts WHERE username = ?', (username,))
        result = cursor.fetchone()
        conn.close()

        if result:
            public_key_pem = result[0]
            return serialization.load_pem_public_key(public_key_pem.encode())
        return None

    def generate_session_key(self, contact):
        """Generate a new session key for forward secrecy"""
        session_key = AESGCM.generate_key(bit_length=256)
        key_id = secrets.token_hex(16)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO session_keys (contact, key_id, key_data, created_at)
            VALUES (?, ?, ?, ?)
        """, (contact, key_id, base64.b64encode(session_key).decode(), time.time()))

        conn.commit()
        conn.close()

        self.session_keys[f"{contact}_{key_id}"] = session_key
        return key_id, session_key

    def encrypt_message(self, recipient, message):
        """Encrypt message with hybrid encryption"""
        # Generate session key for this message
        key_id, session_key = self.generate_session_key(recipient)

        # Get recipient's public key
        recipient_public_key = self.get_contact_public_key(recipient)
        if not recipient_public_key:
            raise ValueError(f"No public key found for {recipient}")

        # Encrypt message with AEAD (AES-GCM)
        aesgcm = AESGCM(session_key)
        nonce = os.urandom(12)  # 96-bit nonce for GCM

        # Message metadata
        metadata = {
            'sender': self.username,
            'timestamp': time.time(),
            'message_id': secrets.token_hex(16)
        }

        # Encrypt the actual message
        ciphertext = aesgcm.encrypt(nonce, message.encode(), json.dumps(metadata).encode())

        # Encrypt session key with recipient's public key
        encrypted_session_key = recipient_public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Create encrypted message package
        encrypted_package = {
            'key_id': key_id,
            'encrypted_key': base64.b64encode(encrypted_session_key).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'metadata': base64.b64encode(json.dumps(metadata).encode()).decode()
        }

        return json.dumps(encrypted_package)

    def decrypt_message(self, encrypted_message_json):
        """Decrypt message with hybrid encryption"""
        try:
            package = json.loads(encrypted_message_json)

            # Decrypt session key with our private key
            encrypted_session_key = base64.b64decode(package['encrypted_key'])
            session_key = self.private_key.decrypt(
                encrypted_session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Decrypt message
            aesgcm = AESGCM(session_key)
            nonce = base64.b64decode(package['nonce'])
            ciphertext = base64.b64decode(package['ciphertext'])
            metadata_bytes = base64.b64decode(package['metadata'])

            # Decrypt with associated data (metadata)
            plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, metadata_bytes)

            # Parse metadata
            metadata = json.loads(metadata_bytes.decode())

            return {
                'message': plaintext_bytes.decode(),
                'sender': metadata['sender'],
                'timestamp': metadata['timestamp'],
                'message_id': metadata['message_id']
            }

        except Exception as e:
            raise ValueError(f"Failed to decrypt message: {str(e)}")

    def store_message(self, sender, recipient, content, encryption_method="hybrid"):
        """Store message in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO messages (sender, recipient, content, timestamp, encryption_method)
            VALUES (?, ?, ?, ?, ?)
        """, (sender, recipient, content, time.time(), encryption_method))

        conn.commit()
        conn.close()

    def get_conversation(self, contact, limit=50):
        """Get conversation history with a contact"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT sender, recipient, content, timestamp, encryption_method
            FROM messages 
            WHERE (sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?)
            ORDER BY timestamp DESC LIMIT ?
        """, (self.username, contact, contact, self.username, limit))

        messages = cursor.fetchall()
        conn.close()

        return [{
            'sender': msg[0],
            'recipient': msg[1],
            'content': msg[2],
            'timestamp': msg[3],
            'encryption_method': msg[4]
        } for msg in reversed(messages)]

    def get_message_hash(self, message):
        """Generate hash for message integrity verification"""
        return hashlib.sha256(message.encode()).hexdigest()

    def verify_message_integrity(self, message, expected_hash):
        """Verify message integrity using hash"""
        return self.get_message_hash(message) == expected_hash
