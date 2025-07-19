#!/usr/bin/env python3
"""
Alternative entry point for the Flask Cryptographic Steganography Application.

This script provides an alternative way to run the Flask application
with additional configuration options and environment setup.
"""

import os
import sys
import logging
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def setup_environment():
    """Set up environment variables and configuration."""
    
    # Set default session secret if not provided
    if not os.environ.get("SESSION_SECRET"):
        # Generate a random secret key for development
        import secrets
        os.environ["SESSION_SECRET"] = secrets.token_hex(32)
        print("🔑 Generated development session secret")
    
    # Set other default environment variables if needed
    env_defaults = {
        'FLASK_ENV': 'development',
        'FLASK_DEBUG': '1',
    }
    
    for key, default_value in env_defaults.items():
        if not os.environ.get(key):
            os.environ[key] = default_value

def setup_logging():
    """Configure application logging."""
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('app.log', mode='a')
        ]
    )
    
    # Set specific loggers to appropriate levels
    logging.getLogger('werkzeug').setLevel(logging.INFO)
    logging.getLogger('PIL').setLevel(logging.WARNING)
    
    print("📋 Logging configured successfully")

def check_dependencies():
    """Check if all required dependencies are available."""
    required_modules = [
        'flask',
        'cryptography',
        'PIL',  # Pillow
    ]
    
    missing_modules = []
    
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing_modules.append(module)
    
    if missing_modules:
        print(f"❌ Missing required modules: {', '.join(missing_modules)}")
        print("   Please install them using: pip install -r requirements.txt")
        return False
    
    print("✅ All required dependencies are available")
    return True

def print_startup_info():
    """Print application startup information."""
    print("=" * 60)
    print("  🔐 CRYPTOGRAPHIC STEGANOGRAPHY APPLICATION")
    print("=" * 60)
    print("  Secure message hiding using:")
    print("    • AES-256-CBC encryption")
    print("    • RSA-2048-OAEP key exchange") 
    print("    • HMAC-SHA256 authentication")
    print("    • LSB steganography")
    print("=" * 60)
    print()

def print_usage_info():
    """Print usage information and available endpoints."""
    print("🌐 Available endpoints:")
    print("   • GET  /                  - Main application interface")
    print("   • POST /api/encrypt       - Encrypt and hide message")
    print("   • POST /api/decrypt       - Decrypt hidden message") 
    print("   • POST /api/generate_keys - Generate RSA key pair")
    print()
    print("📁 Project structure:")
    print("   • core/          - Cryptographic modules")
    print("   • tests/         - Unit tests")
    print("   • templates/     - HTML templates")
    print("   • static/        - Static assets")
    print("   • cli_demo.py    - Command line demo")
    print()
    print("🧪 Testing:")
    print("   • Run tests: python -m pytest tests/")
    print("   • CLI demo:  python cli_demo.py")
    print()

def run_application(host='0.0.0.0', port=5000, debug=True):
    """Run the Flask application with specified configuration."""
    
    print_startup_info()
    
    # Setup environment and logging
    setup_environment()
    setup_logging()
    
    # Check dependencies
    if not check_dependencies():
        print("❌ Cannot start application due to missing dependencies")
        sys.exit(1)
    
    # Import and run the Flask app
    try:
        from app import app
        
        print_usage_info()
        
        print(f"🚀 Starting Flask application...")
        print(f"   Host: {host}")
        print(f"   Port: {port}")
        print(f"   Debug: {debug}")
        print(f"   URL: http://{host}:{port}")
        print()
        print("   Press Ctrl+C to stop the server")
        print("=" * 60)
        
        # Run the application
        app.run(
            host=host,
            port=port,
            debug=debug,
            threaded=True,
            use_reloader=debug
        )
        
    except ImportError as e:
        print(f"❌ Failed to import Flask application: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Failed to start Flask application: {e}")
        sys.exit(1)

def main():
    """Main function with command line argument parsing."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Flask Cryptographic Steganography Application",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py                     # Run with default settings
  python run.py --port 8080        # Run on custom port
  python run.py --host 127.0.0.1   # Run on localhost only
  python run.py --no-debug         # Run without debug mode
        """
    )
    
    parser.add_argument('--host', type=str, default='0.0.0.0',
                       help='Host to bind the server to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=5000,
                       help='Port to bind the server to (default: 5000)')
    parser.add_argument('--no-debug', action='store_true',
                       help='Disable debug mode')
    parser.add_argument('--check-deps', action='store_true',
                       help='Check dependencies and exit')
    parser.add_argument('--info', action='store_true',
                       help='Show application info and exit')
    
    args = parser.parse_args()
    
    # Handle special flags
    if args.check_deps:
        setup_environment()
        if check_dependencies():
            print("✅ All dependencies are satisfied")
            sys.exit(0)
        else:
            sys.exit(1)
    
    if args.info:
        print_startup_info()
        print_usage_info()
        return
    
    # Run the application
    debug_mode = not args.no_debug
    
    try:
        run_application(
            host=args.host,
            port=args.port,
            debug=debug_mode
        )
    except KeyboardInterrupt:
        print("\n\n🛑 Application stopped by user")
    except Exception as e:
        print(f"\n\n❌ Application failed: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
