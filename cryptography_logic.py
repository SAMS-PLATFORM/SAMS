from cryptography.fernet import Fernet
import hashlib

KEY = b'u76GfV_6v8eB6XmR0vLpXQ4D7uS3H9jk2mN1bV8cZ5A='
cipher_suite = Fernet(KEY)

def encrypt_message(message: str) -> str:
    if not message:
        return ""
    return cipher_suite.encrypt(message.encode()).decode()

def decrypt_message(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    try:
        return cipher_suite.decrypt(ciphertext.encode()).decode()
    except Exception:
        return "[Decryption Error]"

def generate_hash(message: str) -> str:
    return hashlib.sha256(message.encode()).hexdigest()