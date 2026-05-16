from flask import Flask, render_template, request, redirect
from models import db, Message
from cryptography_logic import encrypt_message, generate_hash

app = Flask(_name_)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sams.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

with app.app_context():
    db.create_all()

@app.route('/')
def home():
    messages = Message.query.all()
    return render_template('index.html', messages=messages)

@app.route('/send', methods=['POST'])
def send():
    content = request.form['content']
    enc_text = encrypt_message(content)
    h_value = generate_hash(content)
    
    new_msg = Message(
        sender=request.form['sender'],
        receiver=request.form['receiver'],
        ciphertext=enc_text,
        digital_fingerprint=h_value
    )
    
    db.session.add(new_msg)
    db.session.commit()
    return redirect('/')

if __name__ == '_main_':
    app.run(debug=True)