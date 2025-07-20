#!/usr/bin/env python3
"""
Performance Analysis for Cryptographic Steganography Pipeline

This module provides comprehensive performance benchmarks for the encryption/decryption
pipeline including AES, RSA, HMAC, and steganography operations.
"""

import time
import sys
import os
import statistics
import json
from datetime import datetime
from PIL import Image, ImageDraw
import io
import psutil

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.encrypt_full import encrypt_full_pipeline
from core.decrypt_full import decrypt_full_pipeline
from core.aes_module import encrypt_aes, decrypt_aes
from core.rsa_module import generate_rsa_keypair_pem, encrypt_rsa, decrypt_rsa
from core.hmac_module import generate_hmac, verify_hmac
from core.stego_module import encode_message_in_image, decode_message_from_image

class PerformanceAnalyzer:
    """Comprehensive performance analysis for cryptographic operations."""
    
    def __init__(self):
        self.results = {}
        self.test_messages = [
            "Hello, World!",  # Short message
            "This is a medium-length message for testing performance." * 5,  # Medium message
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit." * 50,  # Long message
        ]
        self.message_sizes = ["short", "medium", "long"]
        
    def create_test_images(self):
        """Create test images of different sizes."""
        images = {}
        sizes = {
            'small': (400, 300),
            'medium': (800, 600),
            'large': (1200, 900)
        }
        
        for size_name, (width, height) in sizes.items():
            # Create a colorful test image
            img = Image.new('RGB', (width, height), color=(70, 130, 180))
            draw = ImageDraw.Draw(img)
            
            # Add some patterns for realism
            for i in range(0, width, 50):
                draw.line([(i, 0), (i, height)], fill=(100, 149, 237), width=2)
            for i in range(0, height, 50):
                draw.line([(0, i), (width, i)], fill=(100, 149, 237), width=2)
            
            # Convert to bytes
            img_buffer = io.BytesIO()
            img.save(img_buffer, format='PNG')
            images[size_name] = img_buffer.getvalue()
            
        return images
    
    def measure_time_and_memory(self, func, *args, **kwargs):
        """Measure execution time and memory usage of a function."""
        process = psutil.Process()
        
        # Measure memory before
        mem_before = process.memory_info().rss
        
        # Measure execution time
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        end_time = time.perf_counter()
        
        # Measure memory after
        mem_after = process.memory_info().rss
        
        return {
            'result': result,
            'execution_time': end_time - start_time,
            'memory_delta': mem_after - mem_before,
            'memory_before': mem_before,
            'memory_after': mem_after
        }
    
    def benchmark_aes_operations(self, iterations=100):
        """Benchmark AES encryption and decryption operations."""
        print("📊 Benchmarking AES Operations...")
        aes_results = {'encrypt': {}, 'decrypt': {}}
        
        for i, message in enumerate(self.test_messages):
            size_name = self.message_sizes[i]
            message_bytes = message.encode('utf-8')
            
            # Benchmark AES encryption
            encrypt_times = []
            decrypt_times = []
            
            for _ in range(iterations):
                # Encryption
                perf_data = self.measure_time_and_memory(
                    encrypt_aes, message_bytes
                )
                encrypt_times.append(perf_data['execution_time'])
                
                # Decryption
                aes_key = perf_data['result']['aes_key']
                iv = perf_data['result']['iv']
                encrypted_data = perf_data['result']['encrypted_data']
                
                decrypt_perf = self.measure_time_and_memory(
                    decrypt_aes, encrypted_data, aes_key, iv
                )
                decrypt_times.append(decrypt_perf['execution_time'])
            
            aes_results['encrypt'][size_name] = {
                'avg_time': statistics.mean(encrypt_times),
                'min_time': min(encrypt_times),
                'max_time': max(encrypt_times),
                'std_dev': statistics.stdev(encrypt_times) if len(encrypt_times) > 1 else 0,
                'message_size': len(message_bytes)
            }
            
            aes_results['decrypt'][size_name] = {
                'avg_time': statistics.mean(decrypt_times),
                'min_time': min(decrypt_times),
                'max_time': max(decrypt_times),
                'std_dev': statistics.stdev(decrypt_times) if len(decrypt_times) > 1 else 0,
                'message_size': len(message_bytes)
            }
        
        return aes_results
    
    def benchmark_rsa_operations(self, iterations=20):
        """Benchmark RSA operations (fewer iterations due to computational cost)."""
        print("🔐 Benchmarking RSA Operations...")
        
        # Generate RSA key pair
        private_key_pem, public_key_pem = generate_rsa_keypair_pem()
        
        # Test with different AES key sizes (RSA encrypts AES keys, not messages directly)
        test_data = [
            b'A' * 32,  # 256-bit AES key
            b'B' * 16,  # 128-bit key for comparison
            b'C' * 64,  # Larger data block
        ]
        data_names = ['aes_256_key', 'small_data', 'large_data']
        
        rsa_results = {'encrypt': {}, 'decrypt': {}}
        
        for i, data in enumerate(test_data):
            data_name = data_names[i]
            
            encrypt_times = []
            decrypt_times = []
            
            for _ in range(iterations):
                # RSA Encryption
                encrypt_perf = self.measure_time_and_memory(
                    encrypt_rsa, data, public_key_pem
                )
                encrypt_times.append(encrypt_perf['execution_time'])
                
                # RSA Decryption
                encrypted_data = encrypt_perf['result']
                decrypt_perf = self.measure_time_and_memory(
                    decrypt_rsa, encrypted_data, private_key_pem
                )
                decrypt_times.append(decrypt_perf['execution_time'])
            
            rsa_results['encrypt'][data_name] = {
                'avg_time': statistics.mean(encrypt_times),
                'min_time': min(encrypt_times),
                'max_time': max(encrypt_times),
                'std_dev': statistics.stdev(encrypt_times) if len(encrypt_times) > 1 else 0,
                'data_size': len(data)
            }
            
            rsa_results['decrypt'][data_name] = {
                'avg_time': statistics.mean(decrypt_times),
                'min_time': min(decrypt_times),
                'max_time': max(decrypt_times),
                'std_dev': statistics.stdev(decrypt_times) if len(decrypt_times) > 1 else 0,
                'data_size': len(data)
            }
        
        return rsa_results
    
    def benchmark_hmac_operations(self, iterations=1000):
        """Benchmark HMAC generation and verification."""
        print("🔏 Benchmarking HMAC Operations...")
        
        hmac_key = "performance_test_key"
        hmac_results = {'generate': {}, 'verify': {}}
        
        for i, message in enumerate(self.test_messages):
            size_name = self.message_sizes[i]
            
            generate_times = []
            verify_times = []
            
            for _ in range(iterations):
                # HMAC Generation
                gen_perf = self.measure_time_and_memory(
                    generate_hmac, message, hmac_key
                )
                generate_times.append(gen_perf['execution_time'])
                
                # HMAC Verification
                hmac_signature = gen_perf['result']
                verify_perf = self.measure_time_and_memory(
                    verify_hmac, message, hmac_signature, hmac_key
                )
                verify_times.append(verify_perf['execution_time'])
            
            hmac_results['generate'][size_name] = {
                'avg_time': statistics.mean(generate_times),
                'min_time': min(generate_times),
                'max_time': max(generate_times),
                'std_dev': statistics.stdev(generate_times) if len(generate_times) > 1 else 0,
                'message_size': len(message.encode('utf-8'))
            }
            
            hmac_results['verify'][size_name] = {
                'avg_time': statistics.mean(verify_times),
                'min_time': min(verify_times),
                'max_time': max(verify_times),
                'std_dev': statistics.stdev(verify_times) if len(verify_times) > 1 else 0,
                'message_size': len(message.encode('utf-8'))
            }
        
        return hmac_results
    
    def benchmark_steganography_operations(self, iterations=50):
        """Benchmark steganography encoding and decoding."""
        print("🖼️  Benchmarking Steganography Operations...")
        
        test_images = self.create_test_images()
        stego_results = {'encode': {}, 'decode': {}}
        
        for img_size, img_data in test_images.items():
            for msg_idx, message in enumerate(self.test_messages):
                test_name = f"{img_size}_{self.message_sizes[msg_idx]}"
                
                encode_times = []
                decode_times = []
                
                for _ in range(iterations):
                    # Steganography Encoding
                    encode_perf = self.measure_time_and_memory(
                        encode_message_in_image, message, img_data
                    )
                    encode_times.append(encode_perf['execution_time'])
                    
                    # Steganography Decoding
                    stego_image = encode_perf['result']
                    decode_perf = self.measure_time_and_memory(
                        decode_message_from_image, stego_image
                    )
                    decode_times.append(decode_perf['execution_time'])
                
                stego_results['encode'][test_name] = {
                    'avg_time': statistics.mean(encode_times),
                    'min_time': min(encode_times),
                    'max_time': max(encode_times),
                    'std_dev': statistics.stdev(encode_times) if len(encode_times) > 1 else 0,
                    'image_size': len(img_data),
                    'message_size': len(message.encode('utf-8'))
                }
                
                stego_results['decode'][test_name] = {
                    'avg_time': statistics.mean(decode_times),
                    'min_time': min(decode_times),
                    'max_time': max(decode_times),
                    'std_dev': statistics.stdev(decode_times) if len(decode_times) > 1 else 0,
                    'image_size': len(img_data),
                    'message_size': len(message.encode('utf-8'))
                }
        
        return stego_results
    
    def benchmark_full_pipeline(self, iterations=10):
        """Benchmark the complete encryption/decryption pipeline."""
        print("🔄 Benchmarking Full Pipeline...")
        
        test_images = self.create_test_images()
        pipeline_results = {'encrypt': {}, 'decrypt': {}}
        
        for img_size, img_data in test_images.items():
            for msg_idx, message in enumerate(self.test_messages):
                test_name = f"{img_size}_{self.message_sizes[msg_idx]}"
                
                encrypt_times = []
                decrypt_times = []
                
                for _ in range(iterations):
                    # Full Encryption Pipeline
                    encrypt_perf = self.measure_time_and_memory(
                        encrypt_full_pipeline,
                        message=message,
                        image_data=img_data,
                        hmac_key="test_key"
                    )
                    encrypt_times.append(encrypt_perf['execution_time'])
                    
                    # Full Decryption Pipeline
                    result = encrypt_perf['result']
                    decrypt_perf = self.measure_time_and_memory(
                        decrypt_full_pipeline,
                        stego_image_data=result['stego_image_data'],
                        encrypted_aes_key=result['encrypted_aes_key'],
                        hmac_signature=result['hmac_signature'],
                        rsa_private_key_pem=result['rsa_private_key_pem'],
                        hmac_key="test_key"
                    )
                    decrypt_times.append(decrypt_perf['execution_time'])
                
                pipeline_results['encrypt'][test_name] = {
                    'avg_time': statistics.mean(encrypt_times),
                    'min_time': min(encrypt_times),
                    'max_time': max(encrypt_times),
                    'std_dev': statistics.stdev(encrypt_times) if len(encrypt_times) > 1 else 0,
                    'image_size': len(img_data),
                    'message_size': len(message.encode('utf-8'))
                }
                
                pipeline_results['decrypt'][test_name] = {
                    'avg_time': statistics.mean(decrypt_times),
                    'min_time': min(decrypt_times),
                    'max_time': max(decrypt_times),
                    'std_dev': statistics.stdev(decrypt_times) if len(decrypt_times) > 1 else 0,
                    'image_size': len(img_data),
                    'message_size': len(message.encode('utf-8'))
                }
        
        return pipeline_results
    
    def run_complete_analysis(self):
        """Run complete performance analysis."""
        print("🚀 Starting Comprehensive Performance Analysis")
        print("=" * 60)
        
        start_time = time.time()
        
        # System information
        system_info = {
            'cpu_count': psutil.cpu_count(),
            'memory_total': psutil.virtual_memory().total,
            'python_version': sys.version,
            'timestamp': datetime.now().isoformat()
        }
        
        # Run all benchmarks
        self.results = {
            'system_info': system_info,
            'aes': self.benchmark_aes_operations(),
            'rsa': self.benchmark_rsa_operations(),
            'hmac': self.benchmark_hmac_operations(),
            'steganography': self.benchmark_steganography_operations(),
            'full_pipeline': self.benchmark_full_pipeline()
        }
        
        total_time = time.time() - start_time
        print(f"\n✅ Analysis completed in {total_time:.2f} seconds")
        
        return self.results
    
    def generate_report(self, results=None):
        """Generate a detailed performance report."""
        if results is None:
            results = self.results
        
        report = []
        report.append("# Cryptographic Steganography Performance Analysis Report")
        report.append("=" * 60)
        report.append(f"Generated on: {results['system_info']['timestamp']}")
        report.append(f"CPU Cores: {results['system_info']['cpu_count']}")
        report.append(f"Total Memory: {results['system_info']['memory_total'] / (1024**3):.2f} GB")
        report.append("")
        
        # AES Performance
        report.append("## AES-256 Performance")
        report.append("| Message Size | Operation | Avg Time (ms) | Min Time (ms) | Max Time (ms) | Std Dev (ms) |")
        report.append("|--------------|-----------|---------------|---------------|---------------|--------------|")
        
        for op in ['encrypt', 'decrypt']:
            for size, data in results['aes'][op].items():
                report.append(f"| {size.capitalize()} ({data['message_size']} bytes) | {op.capitalize()} | "
                             f"{data['avg_time']*1000:.3f} | {data['min_time']*1000:.3f} | "
                             f"{data['max_time']*1000:.3f} | {data['std_dev']*1000:.3f} |")
        
        report.append("")
        
        # RSA Performance
        report.append("## RSA-2048 Performance")
        report.append("| Data Type | Operation | Avg Time (ms) | Min Time (ms) | Max Time (ms) | Std Dev (ms) |")
        report.append("|-----------|-----------|---------------|---------------|---------------|--------------|")
        
        for op in ['encrypt', 'decrypt']:
            for data_type, data in results['rsa'][op].items():
                report.append(f"| {data_type} ({data['data_size']} bytes) | {op.capitalize()} | "
                             f"{data['avg_time']*1000:.3f} | {data['min_time']*1000:.3f} | "
                             f"{data['max_time']*1000:.3f} | {data['std_dev']*1000:.3f} |")
        
        report.append("")
        
        # HMAC Performance  
        report.append("## HMAC-SHA256 Performance")
        report.append("| Message Size | Operation | Avg Time (μs) | Min Time (μs) | Max Time (μs) | Std Dev (μs) |")
        report.append("|--------------|-----------|---------------|---------------|---------------|--------------|")
        
        for op in ['generate', 'verify']:
            for size, data in results['hmac'][op].items():
                report.append(f"| {size.capitalize()} ({data['message_size']} bytes) | {op.capitalize()} | "
                             f"{data['avg_time']*1000000:.1f} | {data['min_time']*1000000:.1f} | "
                             f"{data['max_time']*1000000:.1f} | {data['std_dev']*1000000:.1f} |")
        
        report.append("")
        
        # Full Pipeline Performance
        report.append("## Complete Pipeline Performance")
        report.append("| Test Case | Operation | Avg Time (s) | Min Time (s) | Max Time (s) | Std Dev (s) |")
        report.append("|-----------|-----------|--------------|--------------|--------------|--------------|")
        
        for op in ['encrypt', 'decrypt']:
            for test_case, data in results['full_pipeline'][op].items():
                report.append(f"| {test_case} | {op.capitalize()} | "
                             f"{data['avg_time']:.3f} | {data['min_time']:.3f} | "
                             f"{data['max_time']:.3f} | {data['std_dev']:.3f} |")
        
        report.append("")
        report.append("## Analysis Summary")
        report.append("- **AES-256**: Fast symmetric encryption suitable for large data")
        report.append("- **RSA-2048**: Slower asymmetric encryption used only for key exchange")
        report.append("- **HMAC-SHA256**: Very fast authentication, minimal overhead")
        report.append("- **Steganography**: Image processing adds moderate overhead")
        report.append("- **Full Pipeline**: Complete security with reasonable performance")
        
        return '\n'.join(report)
    
    def save_results(self, filename=None):
        """Save results to JSON and generate markdown report."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"performance_analysis_{timestamp}"
        
        # Save JSON data
        with open(f"{filename}.json", 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        # Save markdown report
        report = self.generate_report()
        with open(f"{filename}.md", 'w') as f:
            f.write(report)
        
        print(f"📊 Results saved to:")
        print(f"   - {filename}.json (raw data)")
        print(f"   - {filename}.md (formatted report)")
        
        return filename

def main():
    """Main function to run performance analysis."""
    analyzer = PerformanceAnalyzer()
    
    try:
        # Run complete analysis
        results = analyzer.run_complete_analysis()
        
        # Save results
        filename = analyzer.save_results()
        
        # Print summary
        print("\n" + "="*60)
        print("🎯 PERFORMANCE ANALYSIS SUMMARY")
        print("="*60)
        
        # Quick insights
        aes_avg = statistics.mean([
            results['aes']['encrypt'][size]['avg_time'] 
            for size in results['aes']['encrypt']
        ])
        rsa_avg = statistics.mean([
            results['rsa']['encrypt'][data]['avg_time'] 
            for data in results['rsa']['encrypt']
        ])
        pipeline_avg = statistics.mean([
            results['full_pipeline']['encrypt'][case]['avg_time'] 
            for case in results['full_pipeline']['encrypt']
        ])
        
        print(f"Average AES encryption time: {aes_avg*1000:.3f} ms")
        print(f"Average RSA encryption time: {rsa_avg*1000:.3f} ms")  
        print(f"Average full pipeline time: {pipeline_avg:.3f} s")
        print(f"\nDetailed report available in: {filename}.md")
        
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()