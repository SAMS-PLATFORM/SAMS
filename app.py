import os
import hashlib
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet

app = Flask(__name__)
app.config['SECRET_KEY'] = 'SAMS_SUPER_SECRET_KEY_2026'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sams.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

KEY = Fernet.generate_key()
cipher_suite = Fernet(KEY)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(100), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_username = db.Column(db.String(150), nullable=False)
    sender_role = db.Column(db.String(100), nullable=False)
    recipient_role = db.Column(db.String(100), nullable=False)
    ciphertext = db.Column(db.Text, nullable=False)
    integrity_hash = db.Column(db.String(64), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def index():
    encrypted_messages = Message.query.filter_by(recipient_role=current_user.role).all()
    decrypted_messages = []
    for msg in encrypted_messages:
        try:
            decrypted_bytes = cipher_suite.decrypt(msg.ciphertext.encode())
            decrypted_text = decrypted_bytes.decode()
            decrypted_messages.append({
                'sender': msg.sender_username,
                'sender_role': msg.sender_role,
                'ciphertext': msg.ciphertext,
                'hash': msg.integrity_hash,
                'plain_text': decrypted_text
            })
        except Exception as e:
            print(f"Decryption failed: {str(e)}")
    return render_template('index.html', messages=decrypted_messages)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        role = request.form['role']
        user_exists = User.query.filter(db.func.lower(User.username) == db.func.lower(username)).first()
        if user_exists:
            flash('Account already exists! Please Log In instead.', 'error')
            return render_template('register.html', prefill_user=username)
        hashed_password = generate_password_hash(password, method='scrypt')
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! Please authenticate.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = User.query.filter(db.func.lower(User.username) == db.func.lower(username)).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Authentication Failed: Invalid Username or Password.', 'error')
            return render_template('login.html')
    return render_template('login.html')

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    recipient_role = request.form['recipient_role']
    plain_text = request.form['message_text'].strip()
    if not plain_text:
        return redirect(url_for('index'))
    ciphertext = cipher_suite.encrypt(plain_text.encode()).decode()
    sha256_hash = hashlib.sha256(plain_text.encode()).hexdigest()
    new_msg = Message(
        sender_username=current_user.username,
        sender_role=current_user.role,
        recipient_role=recipient_role,
        ciphertext=ciphertext,
        integrity_hash=sha256_hash
    )
    db.session.add(new_msg)
    db.session.commit()
    flash('Payload Encrypted and Transmitted Securely!', 'crypto_success')
    return redirect(url_for('index'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '_main_':
    with app.app_context():
        db.create_all()
    app.run(debug=True)