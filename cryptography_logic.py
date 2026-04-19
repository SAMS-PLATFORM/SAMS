import hashlib
from cryptography.fernet import Fernet

key = Fernet.generate_key()
cipher_suite = Fernet(key)

def encrypt_message(text):
    return cipher_suite.encrypt(text.encode()).decode()

def generate_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()