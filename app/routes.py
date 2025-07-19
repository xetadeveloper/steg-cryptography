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

# Import models based on database connection status
try:
    from models import User, Message
    print("Using MongoDB models")
except:
    from models_fallback import User, Message
    print("Using fallback in-memory models")

main = Blueprint('main', __name__)

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
    # Update user's online status
    current_user.update_last_seen()
    
    # Get recent messages
    recent_messages = current_user.get_received_messages(limit=5)
    
    # Get statistics
    unread_count = current_user.get_unread_count()
    sent_messages = current_user.get_sent_messages(limit=10)
    sent_count = len(sent_messages)
    
    # Count steganographic messages
    stego_count = 0
    for msg in recent_messages:
        if msg.is_steganographic():
            stego_count += 1
    
    # Get online users
    online_users = User.get_online_users(exclude_user_id=current_user.id)
    
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
    current_user.update_last_seen()
    return {'status': 'updated'}

@main.route('/compose', methods=['GET', 'POST'])
@login_required
def compose():
    """Message composition page and handler."""
    if request.method == 'POST':
        recipient_username = request.form.get('recipient')
        subject = request.form.get('subject')
        message_content = request.form.get('message')
        message_type = request.form.get('message_type', 'text')
        hmac_key = request.form.get('hmac_key', 'default_hmac_key')
        
        if not recipient_username or not message_content:
            flash('Please select a recipient and enter a message.', 'error')
            return redirect(url_for('main.compose'))
        
        # Find recipient
        recipient = User.find_by_username(recipient_username)
        if not recipient:
            flash('Recipient not found.', 'error')
            return redirect(url_for('main.compose'))
        
        try:
            # Prepare encryption parameters
            cover_image_path = None
            stego_image_data = None
            cover_image_name = None
            
            if message_type == 'steganographic':
                # Use a default image from static folder for steganography
                cover_image_path = os.path.join('static', 'sample_image.jpg')
                if not os.path.exists(cover_image_path):
                    # Create a simple default image if none exists
                    from PIL import Image, ImageDraw
                    img = Image.new('RGB', (800, 600), color=(73, 109, 137))
                    d = ImageDraw.Draw(img)
                    d.text((10, 10), "Steganography Cover Image", fill=(255, 255, 0))
                    os.makedirs('static', exist_ok=True)
                    img.save(cover_image_path)
                
                # Read the cover image
                with open(cover_image_path, 'rb') as f:
                    cover_image_data = f.read()
                cover_image_name = 'sample_image.jpg'
            else:
                # For regular encrypted messages, use a small placeholder image
                cover_image_data = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\tpHYs\x00\x00\x0b\x13\x00\x00\x0b\x13\x01\x00\x9a\x9c\x18\x00\x00\x00\x12IDATx\x9cc```bPPP\x00\x02D\x00\x00\xa2\x00\x00\x00\x00IEND\xaeB`\x82'
            
            # Run encryption pipeline
            encryption_result = encrypt_full_pipeline(
                message=message_content,
                image_data=cover_image_data,
                rsa_public_key_pem=recipient.public_key_pem,
                hmac_key=hmac_key
            )
            
            # Create message in database
            if message_type == 'steganographic':
                stego_image_data = base64.b64encode(encryption_result['stego_image_data']).decode('utf-8')
            
            message = Message.create_message(
                sender_id=current_user.id,
                recipient_id=recipient.id,
                encrypted_content=base64.b64encode(encryption_result['encrypted_message']).decode('utf-8'),
                encrypted_aes_key=base64.b64encode(encryption_result['encrypted_aes_key']).decode('utf-8'),
                hmac_signature=base64.b64encode(encryption_result['hmac_signature']).decode('utf-8'),
                message_type=message_type,
                subject=subject,
                stego_image_data=stego_image_data,
                cover_image_name=cover_image_name,
                hmac_key_hint=hmac_key
            )
            
            flash(f'Message sent successfully to {recipient.display_name}!', 'success')
            return redirect(url_for('main.sent'))
            
        except Exception as e:
            flash(f'Failed to send message: {str(e)}', 'error')
            return redirect(url_for('main.compose'))
    
    # GET request - show compose form
    recipient_username = request.args.get('recipient')
    message_type = request.args.get('type', 'text')
    
    # Get all users except current user
    users = User.get_all_users(exclude_user_id=current_user.id)
    
    return render_template('messaging/compose.html',
                         users=users,
                         recipient_username=recipient_username,
                         message_type=message_type)

@main.route('/inbox')
@login_required
def inbox():
    """User inbox with all received messages."""
    messages = current_user.get_received_messages(limit=50)
    return render_template('messaging/inbox.html', messages=messages)

@main.route('/sent')
@login_required
def sent():
    """User sent messages."""
    messages = current_user.get_sent_messages(limit=50)
    return render_template('messaging/sent.html', messages=messages)

@main.route('/message/<message_id>')
@login_required
def view_message(message_id):
    """View and decrypt a specific message."""
    message = Message.find_by_id(message_id)
    
    if not message:
        flash('Message not found.', 'error')
        return redirect(url_for('main.inbox'))
    
    # Check if user has permission to view this message
    if message.recipient_id != current_user.id and message.sender_id != current_user.id:
        flash('You do not have permission to view this message.', 'error')
        return redirect(url_for('main.inbox'))
    
    # Mark as read if recipient is viewing
    if message.recipient_id == current_user.id:
        message.mark_as_read()
    
    return render_template('messaging/view_message.html', message=message)

@main.route('/api/decrypt', methods=['POST'])
@login_required
def decrypt_message():
    """API endpoint to decrypt a message."""
    try:
        message_id = request.form.get('message_id')
        rsa_private_key = request.form.get('rsa_private_key')
        hmac_key = request.form.get('hmac_key', 'default_hmac_key')
        
        message = Message.find_by_id(message_id)
        if not message:
            return jsonify({'error': 'Message not found'}), 404
            
        # Check permission
        if message.recipient_id != current_user.id and message.sender_id != current_user.id:
            return jsonify({'error': 'Permission denied'}), 403
        
        # Decrypt the message using recipient's private key
        encrypted_aes_key = base64.b64decode(message.encrypted_aes_key)
        hmac_signature = base64.b64decode(message.hmac_signature)
        
        if message.is_steganographic():
            # Decode steganographic image
            stego_image_data = base64.b64decode(message.stego_image_data)
            
            # Run decryption pipeline
            decryption_result = decrypt_full_pipeline(
                stego_image_data=stego_image_data,
                encrypted_aes_key=encrypted_aes_key,
                hmac_signature=hmac_signature,
                rsa_private_key_pem=rsa_private_key,
                hmac_key=hmac_key
            )
        else:
            # For regular messages, decrypt directly
            from core.decrypt_full import decrypt_message_only
            encrypted_message = base64.b64decode(message.encrypted_content)
            decryption_result = decrypt_message_only(
                encrypted_message=encrypted_message,
                encrypted_aes_key=encrypted_aes_key,
                hmac_signature=hmac_signature,
                rsa_private_key_pem=rsa_private_key,
                hmac_key=hmac_key
            )
        
        return jsonify({
            'success': True,
            'decrypted_message': decryption_result['decrypted_message'],
            'hmac_verified': decryption_result['hmac_verified']
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# API endpoints for encryption/decryption (keeping original functionality)
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
        from core.rsa_module import generate_rsa_keypair_pem
        private_key_pem, public_key_pem = generate_rsa_keypair_pem()
        
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