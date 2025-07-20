"""
MongoDB Models for Secure Messaging App

This module defines the MongoDB models for users, messages, and authentication
using PyMongo and Flask-PyMongo.
"""

from datetime import datetime, timezone, timedelta
from flask_pymongo import PyMongo
from flask_login import UserMixin
from flask_bcrypt import Bcrypt
from bson import ObjectId
import json

mongo = PyMongo()
bcrypt = Bcrypt()

class User(UserMixin):
    """User model for authentication and profile management."""
    
    def __init__(self, user_data=None):
        if user_data:
            self.id = str(user_data.get('_id'))
            self.username = user_data.get('username')
            self.email = user_data.get('email')
            self.password_hash = user_data.get('password_hash')
            self.display_name = user_data.get('display_name')
            self.created_at = user_data.get('created_at')
            self.last_seen = user_data.get('last_seen')
            self.is_online = user_data.get('is_online', False)
            self.public_key_pem = user_data.get('public_key_pem')
            self.private_key_pem = user_data.get('private_key_pem')
        else:
            self.id = None
            self.username = None
            self.email = None
            self.password_hash = None
            self.display_name = None
            self.created_at = None
            self.last_seen = None
            self.is_online = False
            self.public_key_pem = None
            self.private_key_pem = None
    
    def get_id(self):
        return self.id
    
    @staticmethod
    def create_user(username, email, password, display_name=None):
        """Create a new user."""
        from core.rsa_module import generate_rsa_keypair_pem
        
        # Generate RSA keys for the user
        private_key_pem, public_key_pem = generate_rsa_keypair_pem()
        
        user_doc = {
            'username': username,
            'email': email,
            'password_hash': bcrypt.generate_password_hash(password).decode('utf-8'),
            'display_name': display_name or username,
            'created_at': datetime.now(timezone.utc),
            'last_seen': datetime.now(timezone.utc),
            'is_online': False,
            'public_key_pem': public_key_pem,
            'private_key_pem': private_key_pem  # In production, encrypt this
        }
        
        result = mongo.db.users.insert_one(user_doc)
        user_doc['_id'] = result.inserted_id
        return User(user_doc)
    
    @staticmethod
    def find_by_username(username):
        """Find user by username."""
        user_data = mongo.db.users.find_one({'username': username})
        return User(user_data) if user_data else None
    
    @staticmethod
    def find_by_email(email):
        """Find user by email."""
        user_data = mongo.db.users.find_one({'email': email})
        return User(user_data) if user_data else None
    
    @staticmethod
    def find_by_id(user_id):
        """Find user by ID."""
        try:
            if isinstance(user_id, str):
                user_id = ObjectId(user_id)
            user_data = mongo.db.users.find_one({'_id': user_id})
            return User(user_data) if user_data else None
        except:
            return None
    
    @staticmethod
    def get_all_users(exclude_user_id=None):
        """Get all users except the specified one."""
        query = {}
        if exclude_user_id:
            if isinstance(exclude_user_id, str):
                exclude_user_id = ObjectId(exclude_user_id)
            query['_id'] = {'$ne': exclude_user_id}
        
        users = []
        for user_data in mongo.db.users.find(query):
            users.append(User(user_data))
        return users
    
    @staticmethod
    def get_online_users(exclude_user_id=None):
        """Get all online users except the specified one."""
        query = {'is_online': True}
        if exclude_user_id:
            if isinstance(exclude_user_id, str):
                exclude_user_id = ObjectId(exclude_user_id)
            query['_id'] = {'$ne': exclude_user_id}
        
        users = []
        for user_data in mongo.db.users.find(query):
            users.append(User(user_data))
        return users
    
    def check_password(self, password):
        """Check if provided password matches stored hash."""
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def update_last_seen(self):
        """Update last seen timestamp."""
        mongo.db.users.update_one(
            {'_id': ObjectId(self.id)},
            {'$set': {
                'last_seen': datetime.now(timezone.utc),
                'is_online': True
            }}
        )
        self.last_seen = datetime.now(timezone.utc)
        self.is_online = True
    
    def set_online_status(self, is_online=True):
        """Update online status."""
        mongo.db.users.update_one(
            {'_id': ObjectId(self.id)},
            {'$set': {
                'is_online': is_online,
                'last_seen': datetime.now(timezone.utc)
            }}
        )
        self.is_online = is_online
        self.last_seen = datetime.now(timezone.utc)
    
    def get_unread_count(self):
        """Get count of unread messages."""
        return mongo.db.messages.count_documents({
            'recipient_id': ObjectId(self.id),
            'is_read': False
        })
    
    def get_sent_messages(self, limit=50):
        """Get messages sent by this user."""
        messages = []
        cursor = mongo.db.messages.find({
            'sender_id': ObjectId(self.id)
        }).sort('timestamp', -1).limit(limit)
        
        for msg_data in cursor:
            messages.append(Message(msg_data))
        return messages
    
    def get_received_messages(self, limit=50):
        """Get messages received by this user."""
        messages = []
        cursor = mongo.db.messages.find({
            'recipient_id': ObjectId(self.id)
        }).sort('timestamp', -1).limit(limit)
        
        for msg_data in cursor:
            messages.append(Message(msg_data))
        return messages
    
    def regenerate_rsa_keys(self):
        """Regenerate RSA key pair for the user."""
        from core.rsa_module import generate_rsa_keypair_pem
        
        private_key_pem, public_key_pem = generate_rsa_keypair_pem()
        
        mongo.db.users.update_one(
            {'_id': ObjectId(self.id)},
            {'$set': {
                'public_key_pem': public_key_pem,
                'private_key_pem': private_key_pem
            }}
        )
        
        self.public_key_pem = public_key_pem
        self.private_key_pem = private_key_pem
        
        return {
            'public_key_pem': public_key_pem,
            'private_key_pem': private_key_pem
        }
    
    def to_dict(self):
        """Convert user to dictionary."""
        return {
            'id': self.id,
            'username': self.username,
            'display_name': self.display_name,
            'email': self.email,
            'is_online': self.is_online,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class Message:
    """Message model for encrypted steganographic communications."""
    
    def __init__(self, message_data=None):
        if message_data:
            self.id = str(message_data.get('_id'))
            self.sender_id = str(message_data.get('sender_id'))
            self.recipient_id = str(message_data.get('recipient_id'))
            self.cloudinary_public_id = message_data.get('cloudinary_public_id')
            self.cloudinary_url = message_data.get('cloudinary_url')
            self.encrypted_aes_key = message_data.get('encrypted_aes_key')
            self.hmac_signature = message_data.get('hmac_signature')
            self.cover_image_name = message_data.get('cover_image_name', 'uploaded_image.png')
            self.timestamp = message_data.get('timestamp')
            self.is_read = message_data.get('is_read', False)
        else:
            self.id = None
            self.sender_id = None
            self.recipient_id = None
            self.cloudinary_public_id = None
            self.cloudinary_url = None
            self.encrypted_aes_key = None
            self.hmac_signature = None
            self.cover_image_name = 'uploaded_image.png'
            self.timestamp = None
            self.is_read = False
    
    @staticmethod
    def create_message(sender_id, recipient_id, cloudinary_public_id, cloudinary_url,
                      encrypted_aes_key, hmac_signature, cover_image_name=None):
        """Create a new steganographic message."""
        message_doc = {
            'sender_id': ObjectId(sender_id),
            'recipient_id': ObjectId(recipient_id),
            'cloudinary_public_id': cloudinary_public_id,
            'cloudinary_url': cloudinary_url,
            'encrypted_aes_key': encrypted_aes_key,
            'hmac_signature': hmac_signature,
            'cover_image_name': cover_image_name or 'uploaded_image.png',
            'timestamp': datetime.now(timezone.utc),
            'is_read': False
        }
        
        result = mongo.db.messages.insert_one(message_doc)
        message_doc['_id'] = result.inserted_id
        return Message(message_doc)
    
    @staticmethod
    def find_by_id(message_id):
        """Find message by ID."""
        try:
            if isinstance(message_id, str):
                message_id = ObjectId(message_id)
            message_data = mongo.db.messages.find_one({'_id': message_id})
            return Message(message_data) if message_data else None
        except:
            return None
    
    def mark_as_read(self):
        """Mark message as read and update timestamp."""
        if not self.is_read:
            mongo.db.messages.update_one(
                {'_id': ObjectId(self.id)},
                {'$set': {
                    'is_read': True,
                    'read_at': datetime.now(timezone.utc),
                    'delivery_status': 'read'
                }}
            )
            self.is_read = True
            self.read_at = datetime.now(timezone.utc)
            self.delivery_status = 'read'
    
    def get_sender(self):
        """Get sender user object."""
        return User.find_by_id(self.sender_id)
    
    def get_recipient(self):
        """Get recipient user object."""
        return User.find_by_id(self.recipient_id)
    
    def get_message_size(self):
        """Calculate approximate message size for display."""
        content_size = len(self.encrypted_content) if self.encrypted_content else 0
        image_size = len(self.stego_image_data) if self.stego_image_data else 0
        return content_size + image_size
    
    def is_steganographic(self):
        """Check if message uses steganography."""
        return self.message_type == 'steganographic' and self.stego_image_data is not None
    
    def to_dict(self):
        """Convert message to dictionary for JSON serialization."""
        sender = self.get_sender()
        recipient = self.get_recipient()
        
        return {
            'id': self.id,
            'sender': sender.username if sender else 'Unknown',
            'sender_display': sender.display_name if sender else 'Unknown',
            'recipient': recipient.username if recipient else 'Unknown',
            'subject': self.subject,
            'message_type': self.message_type,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'is_read': self.is_read,
            'delivery_status': self.delivery_status,
            'has_image': self.is_steganographic()
        }


class LoginAttempt:
    """Track login attempts for security monitoring."""
    
    @staticmethod
    def log_attempt(username, ip_address, success, user_agent=None):
        """Log a login attempt."""
        attempt_doc = {
            'username': username,
            'ip_address': ip_address,
            'success': success,
            'timestamp': datetime.now(timezone.utc),
            'user_agent': user_agent
        }
        mongo.db.login_attempts.insert_one(attempt_doc)
        return attempt_doc
    
    @staticmethod
    def get_recent_failures(username, hours=1):
        """Get recent failed login attempts for a username."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        return mongo.db.login_attempts.count_documents({
            'username': username,
            'success': False,
            'timestamp': {'$gt': cutoff}
        })


class UserSession:
    """Track active user sessions."""
    
    @staticmethod
    def create_session(user_id, session_token, ip_address, user_agent):
        """Create a new user session."""
        session_doc = {
            'user_id': ObjectId(user_id),
            'session_token': session_token,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'created_at': datetime.now(timezone.utc),
            'last_activity': datetime.now(timezone.utc),
            'is_active': True
        }
        mongo.db.user_sessions.insert_one(session_doc)
        return session_doc
    
    @staticmethod
    def update_activity(session_token):
        """Update last activity timestamp."""
        mongo.db.user_sessions.update_one(
            {'session_token': session_token},
            {'$set': {'last_activity': datetime.now(timezone.utc)}}
        )
    
    @staticmethod
    def terminate_session(session_token):
        """Terminate a session."""
        mongo.db.user_sessions.update_one(
            {'session_token': session_token},
            {'$set': {'is_active': False}}
        )
    
    @staticmethod
    def cleanup_expired(hours=24):
        """Remove sessions older than specified hours."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        result = mongo.db.user_sessions.delete_many({
            'last_activity': {'$lt': cutoff}
        })
        return result.deleted_count


# Database initialization and indexes
def init_db():
    """Initialize database indexes for better performance."""
    try:
        # Test connection first
        mongo.db.list_collection_names()
        
        # User indexes
        mongo.db.users.create_index('username', unique=True)
        mongo.db.users.create_index('email', unique=True)
        mongo.db.users.create_index('is_online')
        
        # Message indexes
        mongo.db.messages.create_index([('recipient_id', 1), ('timestamp', -1)])
        mongo.db.messages.create_index([('sender_id', 1), ('timestamp', -1)])
        mongo.db.messages.create_index([('recipient_id', 1), ('is_read', 1)])
        
        # Login attempt indexes
        mongo.db.login_attempts.create_index([('username', 1), ('timestamp', -1)])
        
        # Session indexes
        mongo.db.user_sessions.create_index('session_token', unique=True)
        mongo.db.user_sessions.create_index([('user_id', 1), ('is_active', 1)])
        mongo.db.user_sessions.create_index('last_activity')
        
        print("Database indexes created successfully")
        return True
    except Exception as e:
        print(f"Database initialization error: {e}")
        print("Running in offline mode - database operations will be mocked")
        return False