from flask import Blueprint, render_template, request, flash, redirect, url_for, session, jsonify
from flask_login import login_user, logout_user, login_required, current_user

# Import models based on database connection status
try:
    from models import User, LoginAttempt, UserSession
except:
    from models_fallback import User
    # Fallback classes for development
    class LoginAttempt:
        @staticmethod
        def get_recent_failures(username, hours=1):
            return 0
        @staticmethod  
        def record_attempt(username, success, ip_address=None):
            pass
    
    class UserSession:
        @staticmethod
        def create_session(user_id, ip_address=None, user_agent=None):
            return None
        @staticmethod
        def find_by_token(token):
            return None
import re
from datetime import datetime, timezone

auth = Blueprint('auth', __name__)

def is_valid_email(email):
    """Basic email validation."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def is_valid_username(username):
    """Username validation - alphanumeric and underscores only."""
    pattern = r'^[a-zA-Z0-9_]{3,20}$'
    return re.match(pattern, username) is not None

@auth.route('/login', methods=['GET', 'POST'])
def login():
    """User login page and handler."""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password')
        remember = bool(request.form.get('remember'))
        
        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return render_template('auth/login.html')
        
        # Check for too many failed attempts
        recent_failures = LoginAttempt.get_recent_failures(username, hours=1)
        if recent_failures >= 5:
            flash('Too many failed login attempts. Please try again later.', 'error')
            return render_template('auth/login.html')
        
        user = User.find_by_username(username)
        ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        user_agent = request.headers.get('User-Agent')
        
        # Log attempt
        LoginAttempt.log_attempt(
            username=username,
            ip_address=ip_address,
            success=user is not None and user.check_password(password),
            user_agent=user_agent
        )
        
        if user and user.check_password(password):
            # Successful login
            login_user(user, remember=remember)
            user.update_last_seen()
            
            # Create session record
            UserSession.create_session(user.id, session.sid, ip_address, user_agent)
            
            flash(f'Welcome back, {user.display_name}!', 'success')
            
            # Redirect to next page or dashboard
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('main.dashboard'))
        else:
            # Failed login
            flash('Invalid username or password.', 'error')
    
    return render_template('auth/login.html')

@auth.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page and handler."""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        display_name = request.form.get('display_name', '').strip()
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        errors = []
        
        if not username:
            errors.append('Username is required.')
        elif not is_valid_username(username):
            errors.append('Username must be 3-20 characters and contain only letters, numbers, and underscores.')
        elif User.find_by_username(username):
            errors.append('Username already taken.')
        
        if not email:
            errors.append('Email is required.')
        elif not is_valid_email(email):
            errors.append('Please enter a valid email address.')
        elif User.find_by_email(email):
            errors.append('Email already registered.')
        
        if not password:
            errors.append('Password is required.')
        elif len(password) < 6:
            errors.append('Password must be at least 6 characters long.')
        
        if password != confirm_password:
            errors.append('Passwords do not match.')
        
        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('auth/register.html')
        
        try:
            # Create new user
            user = User.create_user(
                username=username,
                email=email,
                password=password,
                display_name=display_name or username
            )
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('auth.login'))
            
        except Exception as e:
            flash('Registration failed. Please try again.', 'error')
            return render_template('auth/register.html')
    
    return render_template('auth/register.html')

@auth.route('/logout')
@login_required
def logout():
    """User logout."""
    if current_user.is_authenticated:
        # Set user offline
        current_user.set_online_status(False)
        
        # Terminate session
        UserSession.terminate_session(session.sid)
        
        username = current_user.username
        logout_user()
        flash(f'You have been logged out successfully.', 'info')
    
    return redirect(url_for('main.index'))

@auth.route('/profile')
@login_required
def profile():
    """User profile page."""
    return render_template('auth/profile.html', user=current_user)

@auth.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    """Edit user profile."""
    if request.method == 'POST':
        display_name = request.form.get('display_name', '').strip()
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        errors = []
        
        # Update display name
        if display_name and display_name != current_user.display_name:
            from models import mongo
            from bson import ObjectId
            mongo.db.users.update_one(
                {'_id': ObjectId(current_user.id)},
                {'$set': {'display_name': display_name}}
            )
            current_user.display_name = display_name
            flash('Display name updated successfully.', 'success')
        
        # Change password if provided
        if new_password:
            if not current_password:
                errors.append('Current password is required to change password.')
            elif not current_user.check_password(current_password):
                errors.append('Current password is incorrect.')
            elif len(new_password) < 6:
                errors.append('New password must be at least 6 characters long.')
            elif new_password != confirm_password:
                errors.append('New passwords do not match.')
            else:
                # Update password
                from models import bcrypt, mongo
                from bson import ObjectId
                new_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
                mongo.db.users.update_one(
                    {'_id': ObjectId(current_user.id)},
                    {'$set': {'password_hash': new_hash}}
                )
                flash('Password changed successfully.', 'success')
        
        if errors:
            for error in errors:
                flash(error, 'error')
        
        return redirect(url_for('auth.profile'))
    
    return render_template('auth/edit_profile.html')

@auth.route('/users/online')
@login_required
def online_users():
    """API endpoint to get list of online users."""
    online_users = User.get_online_users(exclude_user_id=current_user.id)
    return {
        'users': [user.to_dict() for user in online_users],
        'count': len(online_users)
    }