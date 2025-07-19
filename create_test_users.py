#!/usr/bin/env python3
"""
Script to create test users in MongoDB Atlas
"""

from app import app
from models import User

def create_test_users():
    """Create test users test1 and test2 with password test123"""
    with app.app_context():
        # Check if users already exist
        existing_test1 = User.find_by_username('test1')
        existing_test2 = User.find_by_username('test2')
        
        if existing_test1:
            print("User 'test1' already exists")
        else:
            # Create test1 user
            user1 = User.create_user(
                username='test1',
                email='test1@example.com',
                password='test123',
                display_name='Test User 1'
            )
            print(f"Created user: test1 (ID: {user1.id})")
            
        if existing_test2:
            print("User 'test2' already exists")
        else:
            # Create test2 user
            user2 = User.create_user(
                username='test2',
                email='test2@example.com',
                password='test123',
                display_name='Test User 2'
            )
            print(f"Created user: test2 (ID: {user2.id})")
            
        print("Test users setup complete!")
        print("You can now login with:")
        print("  Username: test1, Password: test123")
        print("  Username: test2, Password: test123")

if __name__ == '__main__':
    create_test_users()