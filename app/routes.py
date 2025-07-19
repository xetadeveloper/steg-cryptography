import os
import sys
import json
import base64
from flask import Blueprint, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
from PIL import Image
import io

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.encrypt_full import encrypt_full_pipeline
from core.decrypt_full import decrypt_full_pipeline

main = Blueprint('main', __name__)

@main.route('/')
def index():
    """Main page with encryption/decryption interface"""
    return render_template('index.html')

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
