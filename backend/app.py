from flask import Flask, request, jsonify, session, render_template
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import os
from datetime import datetime, timedelta
import uuid

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///paypal_clone.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-key-change-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app)

# Import models after db initialization
from models import User, Transaction, Account

# Routes
@app.route('/')
def index():
    """Serve the main HTML page"""
    return render_template('paypal_clone.html')

@app.route('/api/register', methods=['POST'])
def register():
    """User registration endpoint"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['email', 'password', 'first_name', 'last_name']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        # Check if user already exists
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'User already exists'}), 409
        
        # Hash password
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        
        # Create new user
        new_user = User(
            email=data['email'],
            password=hashed_password,
            first_name=data['first_name'],
            last_name=data['last_name']
        )
        
        # Create user account
        new_account = Account(
            user_id=new_user.id,
            balance=0.00,
            account_number=str(uuid.uuid4())[:8].upper()
        )
        
        db.session.add(new_user)
        db.session.add(new_account)
        db.session.commit()
        
        # Generate JWT token
        access_token = create_access_token(identity=new_user.id)
        
        return jsonify({
            'message': 'User registered successfully',
            'access_token': access_token,
            'user': {
                'id': new_user.id,
                'email': new_user.email,
                'first_name': new_user.first_name,
                'last_name': new_user.last_name
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    """User login endpoint"""
    try:
        data = request.get_json()
        
        if not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password are required'}), 400
        
        # Find user by email
        user = User.query.filter_by(email=data['email']).first()
        
        if not user or not bcrypt.check_password_hash(user.password, data['password']):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Generate JWT token
        access_token = create_access_token(identity=user.id)
        
        # Get user account
        account = Account.query.filter_by(user_id=user.id).first()
        
        return jsonify({
            'message': 'Login successful',
            'access_token': access_token,
            'user': {
                'id': user.id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'account_balance': account.balance if account else 0.00,
                'account_number': account.account_number if account else None
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/profile', methods=['GET'])
@jwt_required()
def get_profile():
    """Get user profile information"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        account = Account.query.filter_by(user_id=current_user_id).first()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'user': {
                'id': user.id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'created_at': user.created_at.isoformat(),
                'account_balance': account.balance if account else 0.00,
                'account_number': account.account_number if account else None
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/send-money', methods=['POST'])
@jwt_required()
def send_money():
    """Send money to another user"""
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        
        # Validate required fields
        if not data.get('recipient_email') or not data.get('amount'):
            return jsonify({'error': 'Recipient email and amount are required'}), 400
        
        amount = float(data['amount'])
        if amount <= 0:
            return jsonify({'error': 'Amount must be greater than 0'}), 400
        
        # Find sender and recipient
        sender = User.query.get(current_user_id)
        recipient = User.query.filter_by(email=data['recipient_email']).first()
        
        if not recipient:
            return jsonify({'error': 'Recipient not found'}), 404
        
        if sender.id == recipient.id:
            return jsonify({'error': 'Cannot send money to yourself'}), 400
        
        # Get accounts
        sender_account = Account.query.filter_by(user_id=sender.id).first()
        recipient_account = Account.query.filter_by(user_id=recipient.id).first()
        
        if not sender_account or not recipient_account:
            return jsonify({'error': 'Account not found'}), 404
        
        if sender_account.balance < amount:
            return jsonify({'error': 'Insufficient funds'}), 400
        
        # Create transaction
        transaction = Transaction(
            sender_id=sender.id,
            recipient_id=recipient.id,
            amount=amount,
            note=data.get('note', ''),
            status='completed'
        )
        
        # Update account balances
        sender_account.balance -= amount
        recipient_account.balance += amount
        
        db.session.add(transaction)
        db.session.commit()
        
        return jsonify({
            'message': 'Money sent successfully',
            'transaction': {
                'id': transaction.id,
                'amount': transaction.amount,
                'recipient': recipient.email,
                'note': transaction.note,
                'timestamp': transaction.timestamp.isoformat(),
                'new_balance': sender_account.balance
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/transactions', methods=['GET'])
@jwt_required()
def get_transactions():
    """Get user transaction history"""
    try:
        current_user_id = get_jwt_identity()
        
        # Get transactions where user is sender or recipient
        transactions = Transaction.query.filter(
            (Transaction.sender_id == current_user_id) | 
            (Transaction.recipient_id == current_user_id)
        ).order_by(Transaction.timestamp.desc()).limit(50).all()
        
        transaction_list = []
        for t in transactions:
            sender = User.query.get(t.sender_id)
            recipient = User.query.get(t.recipient_id)
            
            transaction_list.append({
                'id': t.id,
                'type': 'sent' if t.sender_id == current_user_id else 'received',
                'amount': t.amount,
                'sender_email': sender.email,
                'recipient_email': recipient.email,
                'note': t.note,
                'status': t.status,
                'timestamp': t.timestamp.isoformat()
            })
        
        return jsonify({'transactions': transaction_list}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/add-funds', methods=['POST'])
@jwt_required()
def add_funds():
    """Add funds to user account (simulated)"""
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        
        amount = float(data.get('amount', 0))
        if amount <= 0:
            return jsonify({'error': 'Amount must be greater than 0'}), 400
        
        account = Account.query.filter_by(user_id=current_user_id).first()
        if not account:
            return jsonify({'error': 'Account not found'}), 404
        
        # Add funds
        account.balance += amount
        
        # Create a system transaction
        system_user = User.query.filter_by(email='system@paypal-clone.com').first()
        if not system_user:
            # Create system user if it doesn't exist
            system_user = User(
                email='system@paypal-clone.com',
                password='system',
                first_name='System',
                last_name='Account'
            )
            db.session.add(system_user)
            db.session.flush()
        
        transaction = Transaction(
            sender_id=system_user.id,
            recipient_id=current_user_id,
            amount=amount,
            note='Funds added to account',
            status='completed'
        )
        
        db.session.add(transaction)
        db.session.commit()
        
        return jsonify({
            'message': 'Funds added successfully',
            'new_balance': account.balance
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/search-users', methods=['GET'])
@jwt_required()
def search_users():
    """Search for users by email or name"""
    try:
        query = request.args.get('q', '').strip()
        if len(query) < 2:
            return jsonify({'error': 'Search query must be at least 2 characters'}), 400
        
        current_user_id = get_jwt_identity()
        
        # Search users by email or name
        users = User.query.filter(
            User.id != current_user_id,
            (User.email.contains(query)) | 
            (User.first_name.contains(query)) | 
            (User.last_name.contains(query))
        ).limit(10).all()
        
        user_list = []
        for user in users:
            user_list.append({
                'id': user.id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name
            })
        
        return jsonify({'users': user_list}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("Database tables created successfully!")
    
    app.run(debug=True, host='0.0.0.0', port=5000) 