import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from base64 import urlsafe_b64encode, urlsafe_b64decode

import os

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path, password):
    with open(file_path, "rb") as f:
        data = f.read()

    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    with open(file_path + ".enc", "wb") as f:
        f.write(salt + iv + encrypted)

    print("File Encrypted Successfully")

def decrypt_file(file_path, password):
    with open(file_path, "rb") as f:
        file_data = f.read()

    salt = file_data[:16]
    iv = file_data[16:32]
    encrypted = file_data[32:]

    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

    output_file = file_path.replace(".enc", "_decrypted")

    with open(output_file, "wb") as f:
        f.write(decrypted)

    print("File Decrypted Successfully")

def main():
    print("1. Encrypt File")
    print("2. Decrypt File")

    choice = input("Enter choice: ")

    file_path = input("Enter file path: ")
    password = input("Enter password: ")

    if choice == "1":
        encrypt_file(file_path, password)
    elif choice == "2":
        decrypt_file(file_path, password)
    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()
