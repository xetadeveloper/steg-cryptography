#!/usr/bin/env python3
"""
Fallback models for development when MongoDB Atlas is not accessible
These classes provide the same interface but store data in memory for testing
"""

from datetime import datetime, timezone, timedelta
from flask_bcrypt import Bcrypt
from flask_login import UserMixin
import hashlib
import secrets
from bson.objectid import ObjectId

# In-memory storage for development
users_store = {}
messages_store = {}
sessions_store = {}
login_attempts_store = {}

# Initialize bcrypt
bcrypt = Bcrypt()

class User(UserMixin):
    """Fallback User model for development."""
    
    def __init__(self, user_data):
        self.id = str(user_data.get('_id', ObjectId()))
        self.username = user_data.get('username')
        self.email = user_data.get('email')
        self.display_name = user_data.get('display_name', self.username)
        self.password_hash = user_data.get('password_hash')
        self.public_key_pem = user_data.get('public_key_pem', '')
        self.private_key_pem = user_data.get('private_key_pem', '')
        self.is_online = user_data.get('is_online', False)
        self.last_seen = user_data.get('last_seen', datetime.now(timezone.utc))
        self.created_at = user_data.get('created_at', datetime.now(timezone.utc))
    
    def get_id(self):
        return self.id
    
    @staticmethod
    def create_user(username, email, password, display_name=None):
        """Create a new user with hashed password."""
        # Generate RSA keypair for the user
        from core.rsa_module import generate_rsa_keypair_pem
        private_key_pem, public_key_pem = generate_rsa_keypair_pem()
        
        user_id = str(ObjectId())
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        
        user_data = {
            '_id': user_id,
            'username': username,
            'email': email,
            'display_name': display_name or username,
            'password_hash': password_hash,
            'public_key_pem': public_key_pem,
            'private_key_pem': private_key_pem,
            'is_online': False,
            'last_seen': datetime.now(timezone.utc),
            'created_at': datetime.now(timezone.utc)
        }
        
        users_store[user_id] = user_data
        return User(user_data)
    
    @staticmethod
    def find_by_username(username):
        """Find user by username."""
        for user_data in users_store.values():
            if user_data['username'] == username:
                return User(user_data)
        return None
    
    @staticmethod
    def find_by_id(user_id):
        """Find user by ID."""
        user_data = users_store.get(user_id)
        return User(user_data) if user_data else None
    
    @staticmethod
    def get_all_users(exclude_user_id=None):
        """Get all users except the excluded one."""
        users = []
        for user_data in users_store.values():
            if exclude_user_id and user_data['_id'] == exclude_user_id:
                continue
            users.append(User(user_data))
        return users
    
    @staticmethod
    def get_online_users(exclude_user_id=None):
        """Get all online users."""
        users = []
        for user_data in users_store.values():
            if exclude_user_id and user_data['_id'] == exclude_user_id:
                continue
            if user_data.get('is_online', False):
                users.append(User(user_data))
        return users
    
    def verify_password(self, password):
        """Verify password against hash."""
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def update_last_seen(self):
        """Update user's last seen timestamp."""
        if self.id in users_store:
            users_store[self.id]['last_seen'] = datetime.now(timezone.utc)
            users_store[self.id]['is_online'] = True
            self.last_seen = users_store[self.id]['last_seen']
            self.is_online = True
    
    def get_received_messages(self, limit=10):
        """Get messages received by this user."""
        messages = []
        for msg_data in messages_store.values():
            if msg_data.get('recipient_id') == self.id:
                messages.append(Message(msg_data))
        
        # Sort by timestamp, newest first
        messages.sort(key=lambda x: x.timestamp, reverse=True)
        return messages[:limit] if limit else messages
    
    def get_sent_messages(self, limit=10):
        """Get messages sent by this user."""
        messages = []
        for msg_data in messages_store.values():
            if msg_data.get('sender_id') == self.id:
                messages.append(Message(msg_data))
        
        # Sort by timestamp, newest first
        messages.sort(key=lambda x: x.timestamp, reverse=True)
        return messages[:limit] if limit else messages
    
    def get_unread_count(self):
        """Get count of unread messages."""
        count = 0
        for msg_data in messages_store.values():
            if msg_data.get('recipient_id') == self.id and not msg_data.get('is_read', False):
                count += 1
        return count


class Message:
    """Fallback Message model for development."""
    
    def __init__(self, message_data):
        self.id = str(message_data.get('_id', ObjectId()))
        self.sender_id = message_data.get('sender_id')
        self.recipient_id = message_data.get('recipient_id')
        self.subject = message_data.get('subject', '')
        self.encrypted_content = message_data.get('encrypted_content')
        self.encrypted_aes_key = message_data.get('encrypted_aes_key')
        self.hmac_signature = message_data.get('hmac_signature')
        self.message_type = message_data.get('message_type', 'text')
        self.stego_image_data = message_data.get('stego_image_data')
        self.cover_image_name = message_data.get('cover_image_name')
        self.hmac_key_hint = message_data.get('hmac_key_hint', 'default_hmac_key')
        self.is_read = message_data.get('is_read', False)
        self.timestamp = message_data.get('timestamp', datetime.now(timezone.utc))
        self.delivery_status = message_data.get('delivery_status', 'sent')
    
    @staticmethod
    def create_message(sender_id, recipient_id, encrypted_content, encrypted_aes_key, 
                      hmac_signature, message_type='text', subject='', 
                      stego_image_data=None, cover_image_name=None, hmac_key_hint='default_hmac_key'):
        """Create a new encrypted message."""
        message_id = str(ObjectId())
        message_data = {
            '_id': message_id,
            'sender_id': sender_id,
            'recipient_id': recipient_id,
            'subject': subject,
            'encrypted_content': encrypted_content,
            'encrypted_aes_key': encrypted_aes_key,
            'hmac_signature': hmac_signature,
            'message_type': message_type,
            'stego_image_data': stego_image_data,
            'cover_image_name': cover_image_name,
            'hmac_key_hint': hmac_key_hint,
            'is_read': False,
            'timestamp': datetime.now(timezone.utc),
            'delivery_status': 'delivered'
        }
        
        messages_store[message_id] = message_data
        return Message(message_data)
    
    @staticmethod
    def find_by_id(message_id):
        """Find message by ID."""
        message_data = messages_store.get(message_id)
        return Message(message_data) if message_data else None
    
    def get_sender(self):
        """Get sender user object."""
        return User.find_by_id(self.sender_id)
    
    def get_recipient(self):
        """Get recipient user object."""
        return User.find_by_id(self.recipient_id)
    
    def is_steganographic(self):
        """Check if message uses steganography."""
        return self.message_type == 'steganographic'
    
    def mark_as_read(self):
        """Mark message as read."""
        if self.id in messages_store:
            messages_store[self.id]['is_read'] = True
            messages_store[self.id]['delivery_status'] = 'read'
            self.is_read = True
            self.delivery_status = 'read'


def init_db():
    """Initialize the fallback database with test users."""
    print("Initializing fallback database (in-memory storage)")
    
    # Create test users if they don't exist
    if not users_store:
        # Create test1
        user1 = User.create_user(
            username='test1',
            email='test1@example.com',
            password='test123',
            display_name='Test User 1'
        )
        print(f"Created test user: test1 (ID: {user1.id})")
        
        # Create test2
        user2 = User.create_user(
            username='test2',
            email='test2@example.com',
            password='test123',
            display_name='Test User 2'
        )
        print(f"Created test user: test2 (ID: {user2.id})")
        
        # Mark users as online for demo
        user1.update_last_seen()
        user2.update_last_seen()
        
        print("Test users setup complete!")
        print("You can now login with:")
        print("  Username: test1, Password: test123")
        print("  Username: test2, Password: test123")
    
    return True