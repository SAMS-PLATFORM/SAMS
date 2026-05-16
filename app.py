from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import base64
import hashlib

app = Flask(__name__)
app.config['SECRET_KEY'] = 'SAMS_SUPER_SECRET_KEY_2026'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sams.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

class MessageLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_role = db.Column(db.String(50), nullable=False)
    receiver_role = db.Column(db.String(50), nullable=False)
    ciphertext = db.Column(db.Text, nullable=False)
    msg_hash = db.Column(db.String(64), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password!', 'danger')
            return redirect(url_for('login'))
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password')
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists! Please choose another one.', 'danger')
            return redirect(url_for('register'))
        
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_pw)
        
        db.session.add(new_user)
        db.session.commit()
        
        login_user(new_user)
        return redirect(url_for('dashboard'))
        
    return render_template('register.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    encrypted_text = ""
    msg_hash = ""
    original_text = ""
    sender_role = "Admin"
    target_authority = "Dean"
    
    if request.method == 'POST':
        original_text = request.form.get('payload_input', '')
        sender_role = request.form.get('sender_role', 'Admin')
        target_authority = request.form.get('target_authority', 'Dean')
        
        if original_text:
            encrypted_text = base64.b64encode(original_text.encode('utf-8')).decode('utf-8')
            msg_hash = hashlib.sha256(original_text.encode('utf-8')).hexdigest()
            
            new_log = MessageLog(
                sender_role=sender_role,
                receiver_role=target_authority,
                ciphertext=encrypted_text,
                msg_hash=msg_hash
            )
            db.session.add(new_log)
            db.session.commit()
            
    active_logs = MessageLog.query.order_by(MessageLog.id.desc()).all()
    
    return render_template('index.html', 
                           username=current_user.username, 
                           original_text=original_text,
                           encrypted_text=encrypted_text,
                           msg_hash=msg_hash,
                           sender_role=sender_role,
                           target_authority=target_authority,
                           logs=active_logs)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '_main_':
    with app.app_context():
        db.create_all()
    app.run(debug=True)