from flask import Flask, render_template, redirect, url_for, request, flash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, Message
from cryptography_logic import encrypt_message, decrypt_message
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = b'SAMS_SECURE_RANDOM_KEY_2026'

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, 'instance')

if not os.path.exists(INSTANCE_DIR):
    os.makedirs(INSTANCE_DIR)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(INSTANCE_DIR, 'sams.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

with app.app_context():
    db.create_all()
    
    roles = [
        "Chief Information Security Officer (CISO)",
        "Director of Cyber Intelligence",
        "Security Operations Center (SOC) Chief",
        "Lead Cryptographic Administrator"
    ]
    
    for role_name in roles:
        existing_user = User.query.filter_by(username=role_name).first()
        if not existing_user:
            hashed_pw = bcrypt.generate_password_hash("123456").decode('utf-8')
            new_role = User(username=role_name, password_hash=hashed_pw)
            db.session.add(new_role)
    db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def index():
    users = User.query.filter(User.id != current_user.id).all()
    received_messages = Message.query.filter_by(receiver_id=current_user.id).order_by(Message.timestamp.desc()).all()
    
    decrypted_messages = []
    for msg in received_messages:
        sender = User.query.get(msg.sender_id)
        decrypted_text = decrypt_message(msg.encrypted_content)
        decrypted_messages.append({
            'sender': sender.username if sender else "Unknown User",
            'content': decrypted_text,
            'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M') if msg.timestamp else ""
        })
        
    return render_template('index.html', users=users, messages=decrypted_messages)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            flash('All fields are required.', 'danger')
            return redirect(url_for('register'))
            
        if User.query.filter_by(username=username).first():
            flash('Username is already registered.', 'danger')
            return redirect(url_for('register'))
            
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    receiver_id = request.form.get('receiver_id')
    message_text = request.form.get('message', '').strip()
    
    if not message_text or not receiver_id:
        flash('Message content or receiver missing.', 'danger')
        return redirect(url_for('index'))
        
    encrypted_text = encrypt_message(message_text)
    new_message = Message(sender_id=current_user.id, receiver_id=receiver_id, encrypted_content=encrypted_text)
    db.session.add(new_message)
    db.session.commit()
    flash('Message encrypted and sent successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))