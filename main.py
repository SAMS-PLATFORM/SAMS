import os
from app import app, db

if not os.path.exists('instance'):
    os.makedirs('instance')

with app.app_context():
    db.create_all()

if __name__ == '_main_':
    app.run(debug=True)