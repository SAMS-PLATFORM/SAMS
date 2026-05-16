from flask import Flask, request, redirect, session, render_template, url_for
from models import db, User, Message
from cryptography_logic import encrypt_message, decrypt_message, generate_hash, hash_password

app = Flask(__name__)
app.secret_key = "secretkey"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

with app.app_context():
    db.create_all()

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('notes'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        
        user_exists = User.query.filter_by(username=username).first()
        if user_exists:
            return "Username already exists! <a href='/register'>Try again</a>"
            
        new_user = User(username=username, password_hash=hash_password(password), role=role)
        db.session.add(new_user)
        db.session.commit()
        return "User registered! <a href='/login'>Login</a>"
        
    return '''
        <h2>Register (SAMS)</h2>
        <form method="post">
            Username: <input name="username" required><br>
            Password: <input name="password" type="password" required><br>
            Role: 
            <select name="role">
                <option value="Admin">Admin</option>
                <option value="Dean">Dean</option>
                <option value="Professor">Professor</option>
            </select><br><br>
            <input type="submit" value="Register">
        </form>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username, password_hash=hash_password(password)).first()
        if user:
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            print(f"{username} ({user.role}) logged in successfully")
            return redirect(url_for('notes'))
        else:
            return "Login failed"
            
    return '''
        <h2>Login (SAMS)</h2>
        <form method="post">
            Username: <input name="username" required><br>
            Password: <input name="password" type="password" required><br><br>
            <input type="submit" value="Login">
        </form>
    '''

@app.route('/notes', methods=['GET', 'POST'])
def notes():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    current_user = session['username']
    current_role = session['role']
    
    if request.method == 'POST':
        receiver = request.form['receiver']
        note_content = request.form['note']
        
        if not note_content.strip():
            return "Note cannot be empty"
            
        enc_text = encrypt_message(note_content)
        h_value = generate_hash(note_content)
        
        new_msg = Message(
            sender=current_user,
            receiver=receiver,
            ciphertext=enc_text,
            digital_fingerprint=h_value
        )
        db.session.add(new_msg)
        db.session.commit()
        
    messages = Message.query.filter((Message.sender == current_user) | (Message.receiver == current_user)).all()
    all_users = User.query.filter(User.username != current_user).all()
    
    users_options = "".join([f'<option value="{u.username}">{u.username} ({u.role})</option>' for u in all_users])
    
    notes_html = []
    for msg in messages:
        original_text = decrypt_message(msg.ciphertext)
        calculated_hash = generate_hash(original_text)
        
        if calculated_hash == msg.digital_fingerprint:
            display_text = original_text
        else:
            display_text = "[Warning: Integrity Compromised!]"
            
        notes_html.append(f"<li><b>From {msg.sender} to {msg.receiver}:</b> {display_text} <br><small>Cipher: {msg.ciphertext[:30]}... | Hash: {msg.digital_fingerprint[:15]}...</small></li>")
        
    notes_list_str = "".join(notes_html) if notes_html else "No messages exchange yet."
    
    return f'''
        <h2>Secure Messaging System (SAMS)</h2>
        <h3>Welcome, {current_user} ({current_role})</h3>
        
        <form method="post">
            Send Message To: 
            <select name="receiver">
                {users_options}
            </select><br><br>
            Message/Note: <br>
            <textarea name="note" rows="4" cols="40" required></textarea><br><br>
            <input type="submit" value="Send Secure Message">
        </form>
        
        <h3>Saved Messages & Notes:</h3>
        <ul>
            {notes_list_str}
        </ul>
        <br>
        <a href="/logout">Logout</a>
    '''

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '_main_':
    app.run(debug=True)