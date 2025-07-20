#!/usr/bin/env python3
"""
Script to create test users for the cryptographic steganography app.
Run this script to create test accounts that you can use to log in.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from models import User

def create_test_users():
    """Create test users for the application."""
    app = create_app()
    
    with app.app_context():
        test_users = [
            {
                'username': 'test1',
                'email': 'test1@example.com', 
                'password': 'test123',
                'display_name': 'Test User 1'
            },
            {
                'username': 'test2',
                'email': 'test2@example.com',
                'password': 'test123', 
                'display_name': 'Test User 2'
            },
            {
                'username': 'admin',
                'email': 'admin@example.com',
                'password': 'admin123',
                'display_name': 'Administrator'
            }
        ]
        
        created_count = 0
        for user_data in test_users:
            # Check if user already exists
            existing_user = User.find_by_username(user_data['username'])
            if existing_user:
                print(f"✓ User '{user_data['username']}' already exists")
                continue
                
            try:
                user = User.create_user(
                    username=user_data['username'],
                    email=user_data['email'], 
                    password=user_data['password'],
                    display_name=user_data['display_name']
                )
                print(f"✓ Created user: {user_data['username']} (password: {user_data['password']})")
                created_count += 1
                
            except Exception as e:
                print(f"✗ Failed to create user {user_data['username']}: {e}")
        
        print(f"\n✓ Created {created_count} new test users")
        print("\nYou can now login with:")
        for user_data in test_users:
            print(f"  Username: {user_data['username']} | Password: {user_data['password']}")

if __name__ == '__main__':
    create_test_users()