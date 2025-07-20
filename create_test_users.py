
#!/usr/bin/env python3
"""
Create test users for authentication debugging
"""

import os
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from app import create_app

def create_test_users():
    """Create test users for authentication testing."""
    app = create_app()
    
    with app.app_context():
        try:
            # Import User model (will use appropriate model based on DB connection)
            if app.config.get('DB_CONNECTED'):
                from models import User
                print("Using MongoDB for test users")
            else:
                from models_fallback import User
                print("Using fallback storage for test users")
            
            # Test user data
            test_users = [
                {
                    'username': 'testuser',
                    'email': 'test@example.com',
                    'password': 'password123',
                    'display_name': 'Test User'
                },
                {
                    'username': 'alice',
                    'email': 'alice@example.com',
                    'password': 'alice123',
                    'display_name': 'Alice Smith'
                },
                {
                    'username': 'bob',
                    'email': 'bob@example.com',
                    'password': 'bob123',
                    'display_name': 'Bob Jones'
                }
            ]
            
            created_users = []
            for user_data in test_users:
                # Check if user already exists
                existing_user = User.find_by_username(user_data['username'])
                if existing_user:
                    print(f"User '{user_data['username']}' already exists")
                    created_users.append(existing_user)
                else:
                    # Create new user
                    user = User.create_user(
                        username=user_data['username'],
                        email=user_data['email'],
                        password=user_data['password'],
                        display_name=user_data['display_name']
                    )
                    created_users.append(user)
                    print(f"Created user: {user_data['username']} / {user_data['password']}")
            
            print(f"\nTest users available:")
            for user_data in test_users:
                print(f"  Username: {user_data['username']}")
                print(f"  Password: {user_data['password']}")
                print(f"  Email: {user_data['email']}")
                print(f"  Display: {user_data['display_name']}")
                print()
            
            return created_users
            
        except Exception as e:
            print(f"Error creating test users: {e}")
            import traceback
            traceback.print_exc()
            return []

if __name__ == '__main__':
    create_test_users()
