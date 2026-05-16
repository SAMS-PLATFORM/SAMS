from flask import Flask, render_template, request, redirect, url_for, session
from models import db, User, Message
from cryptography_logic import encrypt_message, generate_hash
import os

app = Flask(_name_)
app.config['SECRET_KEY'] = 'SAMS_CYBER_SECURE_TOKEN_2026'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///instance/sams.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

with app.app_context():
    db.create_all()

@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    users = User.query.filter(User.username != session['username']).all()
    messages = Message.query.filter(
        (Message.sender == session['username']) | (Message.receiver == session['username'])
    ).order_by(Message.id.desc()).all()
    
    total_sent = Message.query.filter_by(sender=session['username']).count()
    total_received = Message.query.filter_by(receiver=session['username']).count()
    
    return render_template(
        'index.html', 
        current_user=session['username'], 
        role=session['role'], 
        users=users, 
        messages=messages,
        total_sent=total_sent,
        total_received=total_received
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for('home'))
        return redirect(url_for('login', error=1))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password')
        role = request.form.get('role')
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return "Username already exists.", 400
            
        new_user = User(username=username, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/send', methods=['POST'])
def send():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    content = request.form.get('payload', '').strip()
    receiver = request.form.get('receiver')
    
    if content and receiver:
        new_msg = Message(
            sender=session['username'],
            receiver=receiver,
            ciphertext=encrypt_message(content),
            fingerprint=generate_hash(content)
        )
        db.session.add(new_msg)
        db.session.commit()
    return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if _name_ == '_main_':
    app.run(debug=True)