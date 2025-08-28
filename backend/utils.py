import re
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import jwt
from flask import current_app

def validate_email(email: str) -> bool:
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password: str) -> Dict[str, Any]:
    """Validate password strength"""
    errors = []
    
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long")
    
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")
    
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")
    
    if not re.search(r'\d', password):
        errors.append("Password must contain at least one number")
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append("Password must contain at least one special character")
    
    return {
        'is_valid': len(errors) == 0,
        'errors': errors,
        'strength': calculate_password_strength(password)
    }

def calculate_password_strength(password: str) -> str:
    """Calculate password strength level"""
    score = 0
    
    # Length score
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if len(password) >= 16:
        score += 1
    
    # Character variety score
    if re.search(r'[A-Z]', password):
        score += 1
    if re.search(r'[a-z]', password):
        score += 1
    if re.search(r'\d', password):
        score += 1
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1
    
    if score <= 2:
        return 'weak'
    elif score <= 4:
        return 'medium'
    elif score <= 6:
        return 'strong'
    else:
        return 'very_strong'

def generate_secure_token(length: int = 32) -> str:
    """Generate a secure random token"""
    return secrets.token_urlsafe(length)

def hash_data(data: str) -> str:
    """Hash data using SHA-256"""
    return hashlib.sha256(data.encode()).hexdigest()

def validate_amount(amount: str) -> Optional[float]:
    """Validate and convert amount string to float"""
    try:
        amount_float = float(amount)
        if amount_float <= 0:
            return None
        if amount_float > 999999.99:  # Maximum amount limit
            return None
        return round(amount_float, 2)
    except (ValueError, TypeError):
        return None

def format_currency(amount: float, currency: str = 'USD') -> str:
    """Format amount as currency string"""
    if currency == 'USD':
        return f"${amount:,.2f}"
    elif currency == 'EUR':
        return f"€{amount:,.2f}"
    elif currency == 'GBP':
        return f"£{amount:,.2f}"
    else:
        return f"{amount:,.2f} {currency}"

def sanitize_input(text: str, max_length: int = 1000) -> str:
    """Sanitize user input text"""
    if not text:
        return ""
    
    # Remove HTML tags
    text = re.sub(r'<[^>]+>', '', text)
    
    # Remove potentially dangerous characters
    text = re.sub(r'[<>"\']', '', text)
    
    # Limit length
    if len(text) > max_length:
        text = text[:max_length]
    
    return text.strip()

def generate_account_number() -> str:
    """Generate a unique account number"""
    timestamp = str(int(datetime.utcnow().timestamp()))[-6:]
    random_part = secrets.token_hex(2).upper()
    return f"ACC{timestamp}{random_part}"

def validate_phone_number(phone: str) -> bool:
    """Validate phone number format"""
    # Remove all non-digit characters
    digits_only = re.sub(r'\D', '', phone)
    
    # Check if it's a valid length (7-15 digits)
    if len(digits_only) < 7 or len(digits_only) > 15:
        return False
    
    return True

def mask_sensitive_data(data: str, data_type: str = 'email') -> str:
    """Mask sensitive data for display"""
    if data_type == 'email':
        if '@' in data:
            username, domain = data.split('@')
            if len(username) <= 2:
                masked_username = username
            else:
                masked_username = username[0] + '*' * (len(username) - 2) + username[-1]
            return f"{masked_username}@{domain}"
        return data
    
    elif data_type == 'phone':
        if len(data) <= 4:
            return data
        return data[:2] + '*' * (len(data) - 4) + data[-2:]
    
    elif data_type == 'account':
        if len(data) <= 4:
            return data
        return data[:4] + '*' * (len(data) - 4)
    
    return data

def calculate_transaction_fee(amount: float, transaction_type: str = 'transfer') -> float:
    """Calculate transaction fees"""
    if transaction_type == 'transfer':
        # Free for transfers between PayPal accounts
        return 0.00
    elif transaction_type == 'bank_transfer':
        # $0.25 for bank transfers
        return 0.25
    elif transaction_type == 'card_payment':
        # 2.9% + $0.30 for card payments
        return (amount * 0.029) + 0.30
    else:
        return 0.00

def is_business_hours() -> bool:
    """Check if current time is within business hours (9 AM - 5 PM EST)"""
    now = datetime.utcnow()
    # Convert to EST (UTC-5)
    est_time = now - timedelta(hours=5)
    
    # Check if it's a weekday (Monday = 0, Sunday = 6)
    if est_time.weekday() >= 5:  # Saturday or Sunday
        return False
    
    # Check if it's between 9 AM and 5 PM
    business_start = est_time.replace(hour=9, minute=0, second=0, microsecond=0)
    business_end = est_time.replace(hour=17, minute=0, second=0, microsecond=0)
    
    return business_start <= est_time <= business_end

def generate_reference_id() -> str:
    """Generate a unique reference ID for transactions"""
    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    random_part = secrets.token_hex(3).upper()
    return f"REF{timestamp}{random_part}"

def validate_iban(iban: str) -> bool:
    """Validate IBAN format (basic validation)"""
    # Remove spaces and convert to uppercase
    iban = iban.replace(' ', '').upper()
    
    # Check length (varies by country, but generally 15-34 characters)
    if len(iban) < 15 or len(iban) > 34:
        return False
    
    # Check if it starts with 2 letters (country code)
    if not re.match(r'^[A-Z]{2}', iban):
        return False
    
    # Check if the rest are alphanumeric
    if not re.match(r'^[A-Z]{2}[A-Z0-9]+$', iban):
        return False
    
    return True

def calculate_estimated_arrival(transaction_type: str) -> str:
    """Calculate estimated arrival time for transactions"""
    now = datetime.utcnow()
    
    if transaction_type == 'instant':
        return "Immediate"
    elif transaction_type == 'standard':
        # 1-3 business days
        arrival = now + timedelta(days=2)
        if arrival.weekday() >= 5:  # Weekend
            arrival += timedelta(days=2)
        return arrival.strftime("%B %d, %Y")
    elif transaction_type == 'bank_transfer':
        # 3-5 business days
        arrival = now + timedelta(days=4)
        if arrival.weekday() >= 5:  # Weekend
            arrival += timedelta(days=2)
        return arrival.strftime("%B %d, %Y")
    else:
        return "Unknown" 