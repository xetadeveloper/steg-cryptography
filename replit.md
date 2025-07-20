# Cryptographic Steganography Application

## Overview

This is a Flask-based web application that implements a complete cryptographic steganography pipeline. The application allows users to hide encrypted messages within images using a combination of AES-256 encryption, RSA key exchange, HMAC authentication, and LSB (Least Significant Bit) steganography techniques.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

The application follows a modular Flask architecture with clear separation between core cryptographic functionality, web interface, and testing components.

### Backend Architecture
- **Flask Framework**: Simple Python web framework for HTTP endpoints and routing
- **Modular Core**: Separate modules for each cryptographic component (AES, RSA, HMAC, Steganography)
- **Pipeline Design**: Full encryption and decryption pipelines that orchestrate all components
- **RESTful API**: JSON-based API endpoints for encryption/decryption operations

### Frontend Architecture
- **Server-side Rendering**: HTML templates using Jinja2 templating engine
- **Bootstrap Framework**: Dark theme UI components for responsive design
- **Progressive Enhancement**: JavaScript for dynamic interactions and AJAX requests
- **Component-based Templates**: Base template with block inheritance for consistent layout

## Key Components

### Core Cryptographic Modules (`core/`)
1. **AES Module** (`aes_module.py`): AES-256 encryption/decryption with CBC mode and PKCS7 padding
2. **RSA Module** (`rsa_module.py`): RSA key generation, encryption/decryption with OAEP padding
3. **HMAC Module** (`hmac_module.py`): HMAC-SHA256 signing and verification for message integrity
4. **Steganography Module** (`stego_module.py`): LSB steganography for hiding data in images
5. **Full Pipeline Modules**: Complete encryption (`encrypt_full.py`) and decryption (`decrypt_full.py`) workflows

### Web Application Layer (`app/`)
- **Flask App Factory**: Modular app creation with blueprint registration
- **Routes Module**: HTTP endpoints for encryption/decryption API and web interface
- **Template System**: HTML templates with Bootstrap styling and dark theme

### Testing Framework (`tests/`)
- **Comprehensive Unit Tests**: Individual test files for each core module
- **Pipeline Integration Tests**: End-to-end testing of full encryption/decryption workflows
- **Test Fixtures**: Reusable test data and helper functions

## Data Flow

### Encryption Pipeline
1. **Message Input**: User provides plaintext message and selects image
2. **AES Encryption**: Generate random AES-256 key and encrypt message with random IV
3. **RSA Key Exchange**: Encrypt AES key with RSA public key (generate keypair if needed)
4. **HMAC Signing**: Generate HMAC signature for encrypted message integrity
5. **Steganography**: Hide encrypted data payload in image using LSB techniques
6. **Output**: Steganographic image with hidden encrypted data and decryption keys

### Decryption Pipeline
1. **Input Processing**: Extract hidden data from steganographic image
2. **RSA Decryption**: Decrypt AES key using RSA private key
3. **HMAC Verification**: Verify message integrity using HMAC signature
4. **AES Decryption**: Decrypt original message using recovered AES key and IV
5. **Output**: Original plaintext message with verification status

## External Dependencies

### Python Cryptography Libraries
- **cryptography**: Primary library for AES, RSA, and cryptographic primitives
- **PIL (Pillow)**: Image processing for steganography operations
- **hmac/hashlib**: Built-in Python modules for HMAC operations

### Web Framework Dependencies
- **Flask**: Web framework for HTTP handling and routing
- **Werkzeug**: WSGI utilities for file uploads and security
- **Jinja2**: Template engine (included with Flask)

### Frontend Dependencies
- **Bootstrap**: CSS framework with dark theme support
- **Feather Icons**: Icon library for UI components
- **JavaScript**: Native browser APIs for dynamic interactions

## Deployment Strategy

### Development Environment
- **Local Development**: Flask development server with debug mode enabled
- **Hot Reload**: Automatic server restart on code changes
- **Environment Variables**: Session secrets and configuration via environment variables
- **Logging**: Configurable logging with file and console output

### Production Considerations
- **Session Security**: Environment-based session secret configuration
- **Error Handling**: Comprehensive error handling in API endpoints
- **File Upload Security**: Secure filename handling and file validation
- **WSGI Compatibility**: Standard Flask application structure for WSGI deployment

### Security Architecture
- **Input Validation**: Comprehensive validation of user inputs and file uploads
- **Cryptographic Best Practices**: Industry-standard algorithms and key sizes
- **Memory Management**: Secure handling of cryptographic keys and sensitive data
- **Error Messages**: Careful error handling to prevent information leakage

## Recent Updates (July 2025)

### Steganography-Only Messaging System
- **Enforced Steganography**: Removed plain encryption option - all messages must be hidden in images
- **Default Image Support**: Users can set default steganography images stored in Cloudinary
- **Automatic Key Management**: RSA keys automatically managed from user profiles (no manual input)
- **Image Preview**: Real-time preview of selected images in compose form
- **Form Validation**: Required field validation before message submission
- **Auto-Refresh Inbox**: 1-minute automatic refresh for new messages

### Security Enhancements
- **Cloudinary Integration**: Secure image storage with API key: 394723544873621
- **AES+RSA Pipeline**: Signal/WhatsApp-style encryption with automatic key exchange
- **MongoDB Atlas**: Full database functionality with Alice/Bob test accounts
- **Session Management**: Secure authentication with automatic RSA key generation

The application is designed to be easily deployable on various platforms while maintaining security best practices and providing a user-friendly interface for cryptographic steganography operations.