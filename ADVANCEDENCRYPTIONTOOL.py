import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def derive_key(password, salt):
    # Converts password → strong fixed-length key using PBKDF2
    # Same password + same salt → same key (important for decryption)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = AES-256 key
        salt=salt,
        iterations=100000,  # slows brute-force attacks
    )
    return kdf.derive(password.encode())


def encrypt_file(file_path, password):
    with open(file_path, "rb") as f:
        data = f.read()  # read full file as bytes

    salt = os.urandom(16)  # random salt (must be saved for decryption)
    key = derive_key(password, salt)
    iv = os.urandom(16)    # IV for AES (must also be saved)

    # AES works on fixed-size blocks → padding required
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # AES-CBC encryption setup
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    with open(file_path + ".enc", "wb") as f:
        # Store salt + iv + encrypted data in one file
        # Order matters → must match during decryption
        f.write(salt + iv + encrypted)

    print("File Encrypted Successfully")


def decrypt_file(file_path, password):
    with open(file_path, "rb") as f:
        file_data = f.read()

    # Extract values in same order they were stored
    salt = file_data[:16]
    iv = file_data[16:32]
    encrypted = file_data[32:]

    key = derive_key(password, salt)

    # Same cipher setup as encryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()

    # Remove padding added during encryption
    unpadder = padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

    # Replace .enc with readable output file name
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
