from app import db
from datetime import datetime
import uuid

class User(db.Model):
    """User model for authentication and profile information"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    account = db.relationship('Account', backref='user', uselist=False, cascade='all, delete-orphan')
    sent_transactions = db.relationship('Transaction', foreign_keys='Transaction.sender_id', backref='sender')
    received_transactions = db.relationship('Transaction', foreign_keys='Transaction.recipient_id', backref='recipient')
    
    def __repr__(self):
        return f'<User {self.email}>'
    
    def to_dict(self):
        """Convert user object to dictionary"""
        return {
            'id': self.id,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'is_active': self.is_active
        }

class Account(db.Model):
    """Account model for managing user balances and account information"""
    __tablename__ = 'accounts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True)
    account_number = db.Column(db.String(20), unique=True, nullable=False, index=True)
    balance = db.Column(db.Numeric(10, 2), default=0.00, nullable=False)
    currency = db.Column(db.String(3), default='USD', nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<Account {self.account_number} - Balance: {self.balance}>'
    
    def to_dict(self):
        """Convert account object to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'account_number': self.account_number,
            'balance': float(self.balance),
            'currency': self.currency,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class Transaction(db.Model):
    """Transaction model for tracking money transfers between users"""
    __tablename__ = 'transactions'
    
    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    currency = db.Column(db.String(3), default='USD', nullable=False)
    note = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending', nullable=False)  # pending, completed, failed, cancelled
    transaction_type = db.Column(db.String(20), default='transfer', nullable=False)  # transfer, deposit, withdrawal
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    
    def __repr__(self):
        return f'<Transaction {self.transaction_id} - {self.amount} {self.currency}>'
    
    def to_dict(self):
        """Convert transaction object to dictionary"""
        return {
            'id': self.id,
            'transaction_id': self.transaction_id,
            'sender_id': self.sender_id,
            'recipient_id': self.recipient_id,
            'amount': float(self.amount),
            'currency': self.currency,
            'note': self.note,
            'status': self.status,
            'transaction_type': self.transaction_type,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }

class PaymentMethod(db.Model):
    """Payment method model for storing user payment options"""
    __tablename__ = 'payment_methods'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    method_type = db.Column(db.String(20), nullable=False)  # bank_account, credit_card, debit_card
    account_number = db.Column(db.String(50))  # Last 4 digits for cards, account number for bank
    bank_name = db.Column(db.String(100))  # For bank accounts
    card_type = db.Column(db.String(20))  # For credit/debit cards
    expiry_date = db.Column(db.Date)  # For cards
    is_default = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<PaymentMethod {self.method_type} - {self.account_number}>'
    
    def to_dict(self):
        """Convert payment method object to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'method_type': self.method_type,
            'account_number': self.account_number,
            'bank_name': self.bank_name,
            'card_type': self.card_type,
            'expiry_date': self.expiry_date.isoformat() if self.expiry_date else None,
            'is_default': self.is_default,
            'is_active': self.is_active
        }

class Notification(db.Model):
    """Notification model for user alerts and messages"""
    __tablename__ = 'notifications'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    notification_type = db.Column(db.String(20), default='info')  # info, success, warning, error
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    read_at = db.Column(db.DateTime)
    
    def __repr__(self):
        return f'<Notification {self.title} - {self.user_id}>'
    
    def to_dict(self):
        """Convert notification object to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'title': self.title,
            'message': self.message,
            'notification_type': self.notification_type,
            'is_read': self.is_read,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'read_at': self.read_at.isoformat() if self.read_at else None
        }

# Database indexes for better performance
def create_indexes():
    """Create additional database indexes"""
    # These indexes will be created automatically by SQLAlchemy
    # based on the foreign key relationships and unique constraints
    pass 