import os
import sys
import json
import base64
from flask import Blueprint, render_template, request, jsonify, send_file, flash, redirect, url_for
from flask_login import login_required, current_user
from datetime import datetime
from werkzeug.utils import secure_filename
from PIL import Image
import io

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.encrypt_full import encrypt_full_pipeline
from core.decrypt_full import decrypt_full_pipeline

main = Blueprint('main', __name__)

# Import MongoDB models
from models import User, Message

class TempUser:
    def __init__(self, username, email, display_name):
        self.id = username  # Simple ID for now
        self.username = username
        self.email = email
        self.display_name = display_name
        self.is_online = True
        
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'display_name': self.display_name,
            'is_online': self.is_online
        }

@main.route('/')
def index():
    """Landing page - redirect to dashboard if logged in."""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return render_template('index.html')

@main.route('/dashboard')
@login_required
def dashboard():
    """User dashboard with overview and recent messages."""
    # Mock data for development
    recent_messages = []
    unread_count = 0
    sent_count = 0
    stego_count = 0
    
    # Create some demo users for online status
    online_users = [
        TempUser('alice', 'alice@example.com', 'Alice Smith'),
        TempUser('bob', 'bob@example.com', 'Bob Johnson'),
        TempUser('charlie', 'charlie@example.com', 'Charlie Brown')
    ]
    
    return render_template('messaging/dashboard.html',
                         recent_messages=recent_messages,
                         unread_count=unread_count,
                         sent_count=sent_count,
                         stego_count=stego_count,
                         online_users=online_users)

@main.route('/update_status', methods=['POST'])
@login_required
def update_status():
    """Update user's online status."""
    return {'status': 'updated'}

@main.route('/compose')
@login_required
def compose():
    """Message composition page."""
    recipient_username = request.args.get('recipient')
    message_type = request.args.get('type', 'text')
    
    # Mock users for development
    users = [
        TempUser('alice', 'alice@example.com', 'Alice Smith'),
        TempUser('bob', 'bob@example.com', 'Bob Johnson'),
        TempUser('charlie', 'charlie@example.com', 'Charlie Brown')
    ]
    
    return render_template('messaging/compose.html',
                         users=users,
                         recipient_username=recipient_username,
                         message_type=message_type)

@main.route('/inbox')
@login_required
def inbox():
    """User inbox with all received messages."""
    messages = []  # Empty for now
    return render_template('messaging/inbox.html', messages=messages)

@main.route('/sent')
@login_required
def sent():
    """User sent messages."""
    messages = []  # Empty for now
    return render_template('messaging/sent.html', messages=messages)

@main.route('/message/<message_id>')
@login_required
def view_message(message_id):
    """View and decrypt a specific message."""
    # Mock message for development
    class MockMessage:
        def __init__(self):
            self.id = message_id
            self.subject = "Demo Encrypted Message"
            self.timestamp = datetime.now()
            self.is_read = False
            self.encrypted_aes_key = "dGVzdF9lbmNyeXB0ZWRfa2V5"  # Base64 encoded demo
            self.hmac_signature = "dGVzdF9obWFjX3NpZ25hdHVyZQ=="  # Base64 encoded demo
            self.message_type = "text"
            self.stego_image_data = None
            
        def get_sender(self):
            return TempUser('alice', 'alice@example.com', 'Alice Smith')
            
        def is_steganographic(self):
            return self.message_type == 'steganographic'
            
        def mark_as_read(self):
            self.is_read = True
    
    message = MockMessage()
    return render_template('messaging/view_message.html', message=message)

@main.route('/api/encrypt', methods=['POST'])
def encrypt_data():
    """API endpoint for full encryption pipeline"""
    try:
        # Get form data
        message = request.form.get('message')
        rsa_public_key = request.form.get('rsa_public_key', '')
        hmac_key = request.form.get('hmac_key', 'default_hmac_key')
        
        # Get uploaded image file
        if 'image' not in request.files:
            return jsonify({'error': 'No image file provided'}), 400
        
        file = request.files['image']
        if file.filename == '':
            return jsonify({'error': 'No image file selected'}), 400
        
        if not message:
            return jsonify({'error': 'No message provided'}), 400
        
        # Read image data
        image_data = file.read()
        
        # Run encryption pipeline
        result = encrypt_full_pipeline(
            message=message,
            image_data=image_data,
            rsa_public_key_pem=rsa_public_key if rsa_public_key else None,
            hmac_key=hmac_key
        )
        
        # Convert image data to base64 for JSON response
        encoded_image = base64.b64encode(result['stego_image_data']).decode('utf-8')
        
        return jsonify({
            'success': True,
            'encrypted_aes_key': base64.b64encode(result['encrypted_aes_key']).decode('utf-8'),
            'hmac_signature': base64.b64encode(result['hmac_signature']).decode('utf-8'),
            'stego_image': encoded_image,
            'rsa_private_key': result['rsa_private_key_pem'],
            'aes_key': base64.b64encode(result['aes_key']).decode('utf-8')
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@main.route('/api/decrypt', methods=['POST'])
def decrypt_data():
    """API endpoint for full decryption pipeline"""
    try:
        # Get form data
        encrypted_aes_key = request.form.get('encrypted_aes_key')
        hmac_signature = request.form.get('hmac_signature')
        rsa_private_key = request.form.get('rsa_private_key')
        hmac_key = request.form.get('hmac_key', 'default_hmac_key')
        
        # Get uploaded stego image file
        if 'stego_image' not in request.files:
            return jsonify({'error': 'No steganographic image file provided'}), 400
        
        file = request.files['stego_image']
        if file.filename == '':
            return jsonify({'error': 'No steganographic image file selected'}), 400
        
        if not all([encrypted_aes_key, hmac_signature, rsa_private_key]):
            return jsonify({'error': 'Missing required decryption parameters'}), 400
        
        # Read stego image data
        stego_image_data = file.read()
        
        # Decode base64 inputs
        encrypted_aes_key_bytes = base64.b64decode(encrypted_aes_key)
        hmac_signature_bytes = base64.b64decode(hmac_signature)
        
        # Run decryption pipeline
        result = decrypt_full_pipeline(
            stego_image_data=stego_image_data,
            encrypted_aes_key=encrypted_aes_key_bytes,
            hmac_signature=hmac_signature_bytes,
            rsa_private_key_pem=rsa_private_key,
            hmac_key=hmac_key
        )
        
        return jsonify({
            'success': True,
            'decrypted_message': result['decrypted_message'],
            'hmac_verified': result['hmac_verified']
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@main.route('/api/generate_keys', methods=['POST'])
def generate_keys():
    """Generate RSA key pair for testing"""
    try:
        from core.rsa_module import generate_rsa_keypair
        private_key_pem, public_key_pem = generate_rsa_keypair()
        
        return jsonify({
            'success': True,
            'private_key': private_key_pem,
            'public_key': public_key_pem
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@main.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large'}), 413

@main.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error'}), 500
