#!/usr/bin/env python3
"""
Command Line Demo for Cryptographic Steganography Application

This script demonstrates the complete encryption and decryption pipeline
from the command line, allowing users to test all cryptographic components.
"""

import sys
import os
import argparse
import base64
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.encrypt_full import encrypt_full_pipeline, get_pipeline_info
from core.decrypt_full import decrypt_full_pipeline, decrypt_from_stego_only, verify_pipeline_integrity
from core.rsa_module import generate_rsa_keypair
from core.stego_module import create_test_image, get_image_capacity
from core.aes_module import generate_aes_key

def print_banner():
    """Print application banner."""
    print("=" * 70)
    print("  🔐 CRYPTOGRAPHIC STEGANOGRAPHY CLI DEMO")
    print("=" * 70)
    print("  Secure message hiding using AES-256, RSA, HMAC, and Steganography")
    print("=" * 70)
    print()

def print_section(title):
    """Print section header."""
    print(f"\n{'='*10} {title} {'='*10}")

def demo_key_generation():
    """Demonstrate RSA key generation."""
    print_section("RSA KEY GENERATION")
    
    print("Generating RSA-2048 key pair...")
    private_key, public_key = generate_rsa_keypair()
    
    print("✓ RSA key pair generated successfully!")
    print(f"  Private key size: {len(private_key)} characters")
    print(f"  Public key size: {len(public_key)} characters")
    
    # Save keys for later use
    return private_key, public_key

def demo_image_creation():
    """Demonstrate test image creation and capacity analysis."""
    print_section("TEST IMAGE CREATION")
    
    print("Creating test image (800x600 pixels)...")
    image_data = create_test_image(800, 600, (100, 150, 200))
    
    print("✓ Test image created successfully!")
    print(f"  Image size: {len(image_data)} bytes")
    
    # Analyze capacity
    print("\nAnalyzing steganographic capacity...")
    capacity = get_image_capacity(image_data)
    
    print("✓ Capacity analysis complete!")
    print(f"  Dimensions: {capacity['width']}x{capacity['height']} pixels")
    print(f"  Total pixels: {capacity['total_pixels']:,}")
    print(f"  Maximum characters: {capacity['max_characters']:,}")
    print(f"  Usable characters: {capacity['max_characters_with_delimiter']:,}")
    
    return image_data

def demo_encryption(message, image_data, private_key=None, public_key=None):
    """Demonstrate full encryption pipeline."""
    print_section("ENCRYPTION PIPELINE")
    
    print(f"Message to encrypt: '{message}'")
    print(f"Message length: {len(message)} characters")
    print(f"Using {'provided' if public_key else 'generated'} RSA key pair")
    
    print("\nStarting encryption pipeline...")
    
    try:
        result = encrypt_full_pipeline(
            message=message,
            image_data=image_data,
            rsa_public_key_pem=public_key,
            hmac_key="demo_hmac_key"
        )
        
        print("✓ Encryption pipeline completed successfully!")
        print(f"  AES key size: {len(result['aes_key'])} bytes")
        print(f"  IV size: {len(result['iv'])} bytes")
        print(f"  Encrypted AES key size: {len(result['encrypted_aes_key'])} bytes")
        print(f"  HMAC signature size: {len(result['hmac_signature'])} bytes")
        print(f"  Steganographic image size: {len(result['stego_image_data'])} bytes")
        print(f"  Total payload size: {result['payload_length']} bytes")
        
        return result
        
    except Exception as e:
        print(f"✗ Encryption failed: {e}")
        return None

def demo_decryption(encrypt_result):
    """Demonstrate full decryption pipeline."""
    print_section("DECRYPTION PIPELINE")
    
    if not encrypt_result:
        print("✗ No encryption result available for decryption")
        return None
    
    print("Starting decryption pipeline...")
    print("Method: Full pipeline with separate components")
    
    try:
        result = decrypt_full_pipeline(
            stego_image_data=encrypt_result['stego_image_data'],
            encrypted_aes_key=encrypt_result['encrypted_aes_key'],
            hmac_signature=encrypt_result['hmac_signature'],
            rsa_private_key_pem=encrypt_result['rsa_private_key_pem'],
            hmac_key="demo_hmac_key"
        )
        
        print("✓ Decryption pipeline completed successfully!")
        print(f"  Decrypted message: '{result['decrypted_message']}'")
        print(f"  HMAC verified: {'✓' if result['hmac_verified'] else '✗'}")
        print(f"  Message length: {len(result['decrypted_message'])} characters")
        
        return result
        
    except Exception as e:
        print(f"✗ Decryption failed: {e}")
        return None

def demo_steganography_only_decryption(encrypt_result):
    """Demonstrate decryption using only steganographic image."""
    print_section("STEGANOGRAPHY-ONLY DECRYPTION")
    
    if not encrypt_result:
        print("✗ No encryption result available for decryption")
        return None
    
    print("Starting steganography-only decryption...")
    print("Method: Extract all data from steganographic image")
    
    try:
        result = decrypt_from_stego_only(
            stego_image_data=encrypt_result['stego_image_data'],
            rsa_private_key_pem=encrypt_result['rsa_private_key_pem'],
            hmac_key="demo_hmac_key"
        )
        
        print("✓ Steganography-only decryption completed successfully!")
        print(f"  Decrypted message: '{result['decrypted_message']}'")
        print(f"  HMAC verified: {'✓' if result['hmac_verified'] else '✗'}")
        print(f"  Extraction method: {result['extraction_method']}")
        
        return result
        
    except Exception as e:
        print(f"✗ Steganography-only decryption failed: {e}")
        return None

def demo_integrity_verification(encrypt_result):
    """Demonstrate pipeline integrity verification."""
    print_section("INTEGRITY VERIFICATION")
    
    if not encrypt_result:
        print("✗ No encryption result available for verification")
        return
    
    print("Verifying complete pipeline integrity...")
    
    try:
        verification = verify_pipeline_integrity(
            stego_image_data=encrypt_result['stego_image_data'],
            rsa_private_key_pem=encrypt_result['rsa_private_key_pem'],
            hmac_key="demo_hmac_key",
            expected_message=encrypt_result['original_message']
        )
        
        print("✓ Integrity verification completed!")
        print(f"  Decryption successful: {'✓' if verification['decryption_successful'] else '✗'}")
        print(f"  HMAC verified: {'✓' if verification['hmac_verified'] else '✗'}")
        print(f"  Message match: {'✓' if verification.get('expected_message_match', False) else '✗'}")
        print(f"  Pipeline integrity: {verification['pipeline_integrity']}")
        
        if verification['decryption_successful']:
            print(f"  Message length: {verification['message_length']} characters")
        
    except Exception as e:
        print(f"✗ Integrity verification failed: {e}")

def demo_pipeline_info():
    """Display pipeline information."""
    print_section("PIPELINE INFORMATION")
    
    info = get_pipeline_info()
    
    print("Encryption Pipeline Steps:")
    for i, step in enumerate(info['pipeline_steps'], 1):
        print(f"  {i}. {step}")
    
    print("\nAlgorithms Used:")
    for name, algorithm in info['algorithms_used'].items():
        print(f"  {name.replace('_', ' ').title()}: {algorithm}")
    
    print("\nSecurity Features:")
    for feature in info['security_features']:
        print(f"  • {feature}")
    
    print("\nKey Sizes:")
    for key_type, size in info['key_sizes'].items():
        print(f"  {key_type.replace('_', ' ').title()}: {size}")

def save_results_to_files(encrypt_result, output_dir="demo_output"):
    """Save demo results to files."""
    print_section("SAVING RESULTS")
    
    if not encrypt_result:
        print("✗ No results to save")
        return
    
    # Create output directory
    Path(output_dir).mkdir(exist_ok=True)
    
    try:
        # Save steganographic image
        stego_path = Path(output_dir) / "steganographic_image.png"
        with open(stego_path, 'wb') as f:
            f.write(encrypt_result['stego_image_data'])
        print(f"✓ Steganographic image saved to: {stego_path}")
        
        # Save private key
        if encrypt_result['rsa_private_key_pem']:
            private_key_path = Path(output_dir) / "private_key.pem"
            with open(private_key_path, 'w') as f:
                f.write(encrypt_result['rsa_private_key_pem'])
            print(f"✓ Private key saved to: {private_key_path}")
        
        # Save public key
        if encrypt_result['rsa_public_key_pem']:
            public_key_path = Path(output_dir) / "public_key.pem"
            with open(public_key_path, 'w') as f:
                f.write(encrypt_result['rsa_public_key_pem'])
            print(f"✓ Public key saved to: {public_key_path}")
        
        # Save encrypted components
        components_path = Path(output_dir) / "encryption_components.txt"
        with open(components_path, 'w') as f:
            f.write("ENCRYPTION COMPONENTS\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Original Message: {encrypt_result['original_message']}\n\n")
            f.write(f"Encrypted AES Key (Base64):\n{base64.b64encode(encrypt_result['encrypted_aes_key']).decode()}\n\n")
            f.write(f"HMAC Signature (Base64):\n{base64.b64encode(encrypt_result['hmac_signature']).decode()}\n\n")
            f.write(f"HMAC Key Used: {encrypt_result['hmac_key_used']}\n\n")
            f.write(f"Payload Length: {encrypt_result['payload_length']} bytes\n")
        print(f"✓ Encryption components saved to: {components_path}")
        
        print(f"\n📁 All files saved in directory: {output_dir}")
        
    except Exception as e:
        print(f"✗ Error saving files: {e}")

def interactive_demo():
    """Run interactive demo with user input."""
    print_banner()
    
    # Get user input
    print("🔤 Enter your secret message:")
    message = input("> ").strip()
    
    if not message:
        message = "Hello World! This is a secret message for cryptographic steganography testing. 🔐"
        print(f"Using default message: '{message}'")
    
    print("\n🖼️  Do you want to provide a custom image? (y/N):")
    use_custom_image = input("> ").strip().lower() in ['y', 'yes']
    
    image_data = None
    if use_custom_image:
        print("📁 Enter path to image file:")
        image_path = input("> ").strip()
        
        try:
            with open(image_path, 'rb') as f:
                image_data = f.read()
            print(f"✓ Custom image loaded: {len(image_data)} bytes")
        except Exception as e:
            print(f"✗ Error loading image: {e}")
            print("Using default test image instead")
            image_data = None
    
    if image_data is None:
        image_data = demo_image_creation()
    
    # Run demo pipeline
    print("\n🔑 Generating RSA keys...")
    private_key, public_key = demo_key_generation()
    
    print("\n🔒 Running encryption pipeline...")
    encrypt_result = demo_encryption(message, image_data, private_key, public_key)
    
    if encrypt_result:
        print("\n🔓 Running decryption pipeline...")
        decrypt_result = demo_decryption(encrypt_result)
        
        print("\n🔍 Running steganography-only decryption...")
        stego_decrypt_result = demo_steganography_only_decryption(encrypt_result)
        
        print("\n✅ Running integrity verification...")
        demo_integrity_verification(encrypt_result)
        
        print("\n💾 Do you want to save results to files? (Y/n):")
        save_files = input("> ").strip().lower() not in ['n', 'no']
        
        if save_files:
            save_results_to_files(encrypt_result)
    
    demo_pipeline_info()
    
    print("\n" + "=" * 70)
    print("  🎉 DEMO COMPLETED SUCCESSFULLY!")
    print("=" * 70)

def quick_demo():
    """Run quick demo with predefined values."""
    print_banner()
    
    message = "Quick demo: Cryptographic steganography test! 🚀"
    
    print("Running quick demonstration with predefined values...")
    print(f"Message: '{message}'")
    
    # Create components
    image_data = demo_image_creation()
    private_key, public_key = demo_key_generation()
    
    # Run pipeline
    encrypt_result = demo_encryption(message, image_data, private_key, public_key)
    
    if encrypt_result:
        demo_decryption(encrypt_result)
        demo_steganography_only_decryption(encrypt_result)
        demo_integrity_verification(encrypt_result)
    
    demo_pipeline_info()
    
    print("\n" + "=" * 70)
    print("  🎉 QUICK DEMO COMPLETED!")
    print("=" * 70)

def main():
    """Main function with command line argument parsing."""
    parser = argparse.ArgumentParser(
        description="Cryptographic Steganography CLI Demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli_demo.py                    # Interactive demo
  python cli_demo.py --quick           # Quick demo with defaults
  python cli_demo.py --info            # Show pipeline information only
  python cli_demo.py --message "Hello" # Demo with custom message
        """
    )
    
    parser.add_argument('--quick', action='store_true', 
                       help='Run quick demo with predefined values')
    parser.add_argument('--interactive', action='store_true', 
                       help='Run interactive demo (default)')
    parser.add_argument('--info', action='store_true', 
                       help='Show pipeline information only')
    parser.add_argument('--message', type=str, 
                       help='Custom message to encrypt')
    parser.add_argument('--image', type=str, 
                       help='Path to custom image file')
    parser.add_argument('--output', type=str, default='demo_output',
                       help='Output directory for saved files')
    
    args = parser.parse_args()
    
    if args.info:
        print_banner()
        demo_pipeline_info()
        return
    
    if args.quick:
        quick_demo()
        return
    
    if args.message or args.image:
        # Custom demo with provided parameters
        print_banner()
        
        message = args.message or "Custom demo message for cryptographic steganography! 🔐"
        
        # Handle custom image
        image_data = None
        if args.image:
            try:
                with open(args.image, 'rb') as f:
                    image_data = f.read()
                print(f"✓ Custom image loaded: {args.image}")
            except Exception as e:
                print(f"✗ Error loading image: {e}")
                print("Using default test image")
        
        if image_data is None:
            image_data = demo_image_creation()
        
        private_key, public_key = demo_key_generation()
        encrypt_result = demo_encryption(message, image_data, private_key, public_key)
        
        if encrypt_result:
            demo_decryption(encrypt_result)
            demo_steganography_only_decryption(encrypt_result)
            demo_integrity_verification(encrypt_result)
            save_results_to_files(encrypt_result, args.output)
        
        demo_pipeline_info()
        return
    
    # Default: interactive demo
    interactive_demo()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n❌ Demo interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Demo failed with error: {e}")
        sys.exit(1)
