import hashlib
from cryptography.fernet import Fernet

KEY = b'G0M7B1v2K9LpQ_X5J8zW4R3n1t6uY8eE-2A4BcdEFgh='
cipher_suite = Fernet(KEY)

def encrypt_message(text):
    return cipher_suite.encrypt(text.encode()).decode()

def decrypt_message(cipher_text):
    try:
        return cipher_suite.decrypt(cipher_text.encode()).decode()
    except Exception:
        return "[Error: Message Integrity Compromised]"

def generate_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()