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

# Import MongoDB models directly (MongoDB is connected and working)
from models import User, Message
print("Using MongoDB models")

main = Blueprint('main', __name__)

@main.route('/')
def index():
    """Landing page - redirect to dashboard if logged in, otherwise show login."""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('auth.login'))

@main.route('/dashboard')
@login_required
def dashboard():
    """User dashboard with overview and recent messages."""
    # Update user's online status
    current_user.update_last_seen()
    
    # Get received and sent messages
    received_messages = current_user.get_received_messages(limit=10)
    sent_messages = current_user.get_sent_messages(limit=10)
    
    # Get statistics
    unread_count = current_user.get_unread_count()
    sent_count = len(sent_messages)
    
    # Get all users and online users
    all_users = User.get_all_users(exclude_user_id=current_user.id)
    online_users = User.get_online_users(exclude_user_id=current_user.id)
    
    return render_template('messaging/dashboard.html',
                         received_messages=received_messages,
                         sent_messages=sent_messages,
                         unread_count=unread_count,
                         sent_count=sent_count,
                         all_users=all_users,
                         online_users=online_users)

@main.route('/api/ping', methods=['POST'])
@login_required
def api_ping():
    """API endpoint for updating user status."""
    current_user.update_last_seen()
    return jsonify({'status': 'ok'})

@main.route('/update_status', methods=['POST'])
@login_required
def update_status():
    """Update user's online status."""
    current_user.update_last_seen()
    return {'status': 'updated'}

@main.route('/compose', methods=['GET', 'POST'])
@login_required
def compose():
    """Compose and send encrypted messages using Cloudinary."""
    if request.method == 'POST':
        # Handle message composition and encryption
        recipient_username = request.form.get('recipient')
        message = request.form.get('message')
        
        if not all([recipient_username, message]):
            flash('Recipient and message are required.', 'error')
            return render_template('messaging/compose.html', users=User.get_all_users(exclude_user_id=current_user.id))
        
        # Find recipient
        recipient = User.find_by_username(recipient_username)
        if not recipient:
            flash('Recipient not found.', 'error')
            return render_template('messaging/compose.html', users=User.get_all_users(exclude_user_id=current_user.id))
        
        # Handle file upload for cover image
        if 'cover_image' not in request.files:
            flash('Cover image is required.', 'error')
            return render_template('messaging/compose.html', users=User.get_all_users(exclude_user_id=current_user.id))
        
        file = request.files['cover_image']
        if file.filename == '':
            flash('No image selected.', 'error')
            return render_template('messaging/compose.html', users=User.get_all_users(exclude_user_id=current_user.id))
        
        if file and file.filename.lower().endswith(('.png', '.jpg', '.jpeg')):
            try:
                # Read and validate image
                image_data = file.read()
                image = Image.open(io.BytesIO(image_data))
                
                # Convert to PNG for consistent steganography
                if image.mode != 'RGB':
                    image = image.convert('RGB')
                
                img_buffer = io.BytesIO()
                image.save(img_buffer, format='PNG')
                image_data = img_buffer.getvalue()
                
                # Use secure messaging pipeline
                from core.secure_messaging import secure_messaging
                result = secure_messaging.send_message(
                    sender_user=current_user,
                    recipient_user=recipient,
                    message_text=message,
                    cover_image_data=image_data
                )
                
                if result['success']:
                    flash(f'Message sent successfully to {recipient.display_name}!', 'success')
                    return redirect(url_for('main.dashboard'))
                else:
                    flash(f'Failed to send message: {result["error"]}', 'error')
            
            except Exception as e:
                flash(f'Error processing image: {str(e)}', 'error')
        else:
            flash('Please upload a valid image file (PNG, JPG, JPEG).', 'error')
    
    # Get all users except current user for recipient selection
    users = User.get_all_users(exclude_user_id=current_user.id)
    return render_template('messaging/compose.html', users=users)

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
    """View and decrypt a specific message from Cloudinary."""
    message = Message.find_by_id(message_id)
    if not message:
        flash('Message not found.', 'error')
        return redirect(url_for('main.inbox'))
    
    # Check if user is authorized to view this message
    if message.recipient_id != current_user.id and message.sender_id != current_user.id:
        flash('You are not authorized to view this message.', 'error')
        return redirect(url_for('main.inbox'))
    
    # Decrypt the message if recipient is viewing
    decrypted_message = None
    decryption_error = None
    
    if message.recipient_id == current_user.id:
        from core.secure_messaging import secure_messaging
        result = secure_messaging.decrypt_message(message, current_user)
        
        if result['success']:
            decrypted_message = result['message']
            message.mark_as_read()
        else:
            decryption_error = result['error']
    
    # Get sender and recipient info
    sender = message.get_sender()
    recipient = message.get_recipient()
    
    return render_template('messaging/view_message.html',
                         message=message,
                         sender=sender,
                         recipient=recipient,
                         decrypted_message=decrypted_message,
                         decryption_error=decryption_error)



@main.route('/api/decrypt', methods=['POST'])
@login_required
def decrypt_api():
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
@login_required
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

@main.route('/api/decrypt_file', methods=['POST'])
@login_required
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
@login_required
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

@main.route('/manual-decrypt', methods=['GET', 'POST'])
@login_required 
def manual_decrypt():
    """Manual image upload and decryption interface."""
    if request.method == 'POST':
        try:
            # Get form data
            rsa_private_key = request.form.get('rsa_private_key')
            hmac_key = request.form.get('hmac_key', 'default_hmac_key')
            encrypted_aes_key = request.form.get('encrypted_aes_key')
            hmac_signature = request.form.get('hmac_signature')
            
            # Get uploaded steganographic image
            if 'stego_image' not in request.files:
                flash('Please select a steganographic image file.', 'error')
                return render_template('messaging/manual_decrypt.html')
            
            file = request.files['stego_image']
            if file.filename == '':
                flash('Please select a steganographic image file.', 'error')
                return render_template('messaging/manual_decrypt.html')
            
            if not rsa_private_key:
                flash('Please enter the RSA private key.', 'error')
                return render_template('messaging/manual_decrypt.html')
                
            # Read stego image data
            stego_image_data = file.read()
            
            # Run decryption pipeline
            if encrypted_aes_key and hmac_signature:
                # Manual decryption with provided keys
                decryption_result = decrypt_full_pipeline(
                    stego_image_data=stego_image_data,
                    encrypted_aes_key=base64.b64decode(encrypted_aes_key),
                    hmac_signature=base64.b64decode(hmac_signature),
                    rsa_private_key_pem=rsa_private_key,
                    hmac_key=hmac_key
                )
            else:
                # Try to extract everything from the image
                decryption_result = decrypt_full_pipeline(
                    stego_image_data=stego_image_data,
                    rsa_private_key_pem=rsa_private_key,
                    hmac_key=hmac_key
                )
            
            flash('Message decrypted successfully!', 'success')
            return render_template('messaging/manual_decrypt.html', 
                                 decryption_result=decryption_result,
                                 show_result=True)
            
        except Exception as e:
            flash(f'Decryption failed: {str(e)}', 'error')
            return render_template('messaging/manual_decrypt.html')
    
    return render_template('messaging/manual_decrypt.html')

@main.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large'}), 413

@main.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error'}), 500