from functools import wraps
from flask import request, jsonify, current_app
from flask_jwt_extended import (
    create_access_token, 
    create_refresh_token, 
    get_jwt_identity, 
    verify_jwt_in_request,
    get_jwt
)
from datetime import datetime, timedelta
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from models import User, Account
from utils import validate_email, validate_password, generate_secure_token
import re

def create_tokens(user_id: int) -> dict:
    """Create access and refresh tokens for a user"""
    access_token = create_access_token(identity=user_id)
    refresh_token = create_refresh_token(identity=user_id)
    
    return {
        'access_token': access_token,
        'refresh_token': refresh_token,
        'token_type': 'Bearer'
    }

def refresh_access_token():
    """Refresh access token using refresh token"""
    try:
        current_user_id = get_jwt_identity()
        new_access_token = create_access_token(identity=current_user_id)
        
        return jsonify({
            'access_token': new_access_token,
            'token_type': 'Bearer'
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Invalid refresh token'}), 401

def token_required(f):
    """Decorator to require valid JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            verify_jwt_in_request()
            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({'error': 'Token is missing or invalid'}), 401
    
    return decorated

def admin_required(f):
    """Decorator to require admin privileges"""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            verify_jwt_in_request()
            current_user_id = get_jwt_identity()
            user = User.query.get(current_user_id)
            
            if not user or not user.is_admin:
                return jsonify({'error': 'Admin privileges required'}), 403
            
            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({'error': 'Authentication required'}), 401
    
    return decorated

def rate_limit_exempt(f):
    """Decorator to exempt endpoint from rate limiting"""
    f.rate_limit_exempt = True
    return f

def validate_user_registration(data: dict) -> tuple[bool, list]:
    """Validate user registration data"""
    errors = []
    
    # Required fields
    required_fields = ['email', 'password', 'first_name', 'last_name']
    for field in required_fields:
        if not data.get(field):
            errors.append(f"{field.replace('_', ' ').title()} is required")
    
    # Email validation
    if data.get('email'):
        if not validate_email(data['email']):
            errors.append("Invalid email format")
        elif len(data['email']) > 120:
            errors.append("Email is too long")
    
    # Password validation
    if data.get('password'):
        password_validation = validate_password(data['password'])
        if not password_validation['is_valid']:
            errors.extend(password_validation['errors'])
    
    # Name validation
    if data.get('first_name'):
        if len(data['first_name']) < 2 or len(data['first_name']) > 50:
            errors.append("First name must be between 2 and 50 characters")
        if not re.match(r'^[a-zA-Z\s\-]+$', data['first_name']):
            errors.append("First name contains invalid characters")
    
    if data.get('last_name'):
        if len(data['last_name']) < 2 or len(data['last_name']) > 50:
            errors.append("Last name must be between 2 and 50 characters")
        if not re.match(r'^[a-zA-Z\s\-]+$', data['last_name']):
            errors.append("Last name contains invalid characters")
    
    # Phone validation (optional)
    if data.get('phone'):
        from utils import validate_phone_number
        if not validate_phone_number(data['phone']):
            errors.append("Invalid phone number format")
    
    return len(errors) == 0, errors

def validate_user_login(data: dict) -> tuple[bool, list]:
    """Validate user login data"""
    errors = []
    
    if not data.get('email'):
        errors.append("Email is required")
    
    if not data.get('password'):
        errors.append("Password is required")
    
    return len(errors) == 0, errors

def authenticate_user(email: str, password: str) -> tuple[bool, str, User]:
    """Authenticate user with email and password"""
    try:
        user = User.query.filter_by(email=email).first()
        
        if not user:
            return False, "Invalid credentials", None
        
        if not user.is_active:
            return False, "Account is deactivated", None
        
        if not check_password_hash(user.password, password):
            return False, "Invalid credentials", None
        
        return True, "Authentication successful", user
        
    except Exception as e:
        return False, "Authentication error", None

def create_user_account(user_data: dict) -> tuple[bool, str, User]:
    """Create a new user account"""
    try:
        # Check if user already exists
        existing_user = User.query.filter_by(email=user_data['email']).first()
        if existing_user:
            return False, "User already exists", None
        
        # Hash password
        hashed_password = generate_password_hash(user_data['password'])
        
        # Create user
        new_user = User(
            email=user_data['email'],
            password=hashed_password,
            first_name=user_data['first_name'],
            last_name=user_data['last_name']
        )
        
        # Add optional fields
        if user_data.get('phone'):
            new_user.phone = user_data['phone']
        
        # Save user to get ID
        from app import db
        db.session.add(new_user)
        db.session.flush()
        
        # Create account
        from utils import generate_account_number
        new_account = Account(
            user_id=new_user.id,
            account_number=generate_account_number(),
            balance=0.00
        )
        
        db.session.add(new_account)
        db.session.commit()
        
        return True, "User created successfully", new_user
        
    except Exception as e:
        db.session.rollback()
        return False, f"Error creating user: {str(e)}", None

def update_user_profile(user_id: int, update_data: dict) -> tuple[bool, str]:
    """Update user profile information"""
    try:
        user = User.query.get(user_id)
        if not user:
            return False, "User not found"
        
        # Update allowed fields
        allowed_fields = ['first_name', 'last_name', 'phone']
        for field in allowed_fields:
            if field in update_data:
                setattr(user, field, update_data[field])
        
        user.updated_at = datetime.utcnow()
        db.session.commit()
        
        return True, "Profile updated successfully"
        
    except Exception as e:
        db.session.rollback()
        return False, f"Error updating profile: {str(e)}"

def change_user_password(user_id: int, current_password: str, new_password: str) -> tuple[bool, str]:
    """Change user password"""
    try:
        user = User.query.get(user_id)
        if not user:
            return False, "User not found"
        
        # Verify current password
        if not check_password_hash(user.password, current_password):
            return False, "Current password is incorrect"
        
        # Validate new password
        password_validation = validate_password(new_password)
        if not password_validation['is_valid']:
            return False, f"New password validation failed: {'; '.join(password_validation['errors'])}"
        
        # Hash and update password
        user.password = generate_password_hash(new_password)
        user.updated_at = datetime.utcnow()
        db.session.commit()
        
        return True, "Password changed successfully"
        
    except Exception as e:
        db.session.rollback()
        return False, f"Error changing password: {str(e)}"

def deactivate_user_account(user_id: int, reason: str = None) -> tuple[bool, str]:
    """Deactivate user account"""
    try:
        user = User.query.get(user_id)
        if not user:
            return False, "User not found"
        
        user.is_active = False
        user.deactivated_at = datetime.utcnow()
        user.deactivation_reason = reason
        user.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return True, "Account deactivated successfully"
        
    except Exception as e:
        db.session.rollback()
        return False, f"Error deactivating account: {str(e)}"

def get_user_permissions(user_id: int) -> list:
    """Get user permissions and roles"""
    try:
        user = User.query.get(user_id)
        if not user:
            return []
        
        permissions = []
        
        # Basic user permissions
        permissions.append('send_money')
        permissions.append('receive_money')
        permissions.append('view_transactions')
        permissions.append('update_profile')
        
        # Admin permissions
        if user.is_admin:
            permissions.extend([
                'view_all_users',
                'manage_transactions',
                'system_settings',
                'user_management'
            ])
        
        # Premium user permissions (if implemented)
        if hasattr(user, 'is_premium') and user.is_premium:
            permissions.extend([
                'higher_limits',
                'priority_support',
                'advanced_features'
            ])
        
        return permissions
        
    except Exception as e:
        return []

def log_authentication_attempt(email: str, success: bool, ip_address: str = None, user_agent: str = None):
    """Log authentication attempts for security monitoring"""
    try:
        # This would typically go to a logging service or database
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'email': email,
            'success': success,
            'ip_address': ip_address,
            'user_agent': user_agent
        }
        
        # In production, send to logging service
        print(f"AUTH_LOG: {log_entry}")
        
    except Exception as e:
        # Don't let logging errors affect authentication
        pass

def check_account_locked(user_id: int) -> tuple[bool, str]:
    """Check if user account is locked due to security reasons"""
    try:
        user = User.query.get(user_id)
        if not user:
            return True, "User not found"
        
        # Check if account is deactivated
        if not user.is_active:
            return True, "Account is deactivated"
        
        # Check for too many failed login attempts
        # This would typically be implemented with a separate table
        # For now, we'll return False (not locked)
        
        return False, "Account is active"
        
    except Exception as e:
        return True, f"Error checking account status: {str(e)}"

def generate_password_reset_token(email: str) -> tuple[bool, str, str]:
    """Generate password reset token"""
    try:
        user = User.query.filter_by(email=email).first()
        if not user:
            return False, "User not found", ""
        
        # Generate secure token
        reset_token = generate_secure_token(32)
        
        # Store token in user record (you might want a separate table for this)
        user.password_reset_token = reset_token
        user.password_reset_expires = datetime.utcnow() + timedelta(hours=1)
        user.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return True, "Reset token generated", reset_token
        
    except Exception as e:
        db.session.rollback()
        return False, f"Error generating reset token: {str(e)}", ""

def verify_password_reset_token(email: str, token: str) -> tuple[bool, str]:
    """Verify password reset token"""
    try:
        user = User.query.filter_by(email=email).first()
        if not user:
            return False, "User not found"
        
        if not user.password_reset_token or user.password_reset_token != token:
            return False, "Invalid reset token"
        
        if not user.password_reset_expires or user.password_reset_expires < datetime.utcnow():
            return False, "Reset token has expired"
        
        return True, "Token is valid"
        
    except Exception as e:
        return False, f"Error verifying token: {str(e)}" 