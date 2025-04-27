import os
import io
import zipfile
from flask import Flask, render_template, request, send_file, jsonify
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
ENCRYPTED_FOLDER = 'encrypted'
DECRYPTED_FOLDER = 'decrypted'
ZIP_FOLDER = 'zips'

for folder in [UPLOAD_FOLDER, ENCRYPTED_FOLDER, DECRYPTED_FOLDER, ZIP_FOLDER]:
    os.makedirs(folder, exist_ok=True)

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(input_path, output_path, password):
    salt = secrets.token_bytes(8)
    iv = secrets.token_bytes(16)
    key = derive_key(password, salt)

    with open(input_path, 'rb') as f:
        data = f.read()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_path, 'wb') as f:
        f.write(salt + iv + ciphertext)

def decrypt_file(input_path, output_path, password):
    try:
        with open(input_path, 'rb') as f:
            content = f.read()

        salt = content[:8]
        iv = content[8:24]
        ciphertext = content[24:]

        key = derive_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        with open(output_path, 'wb') as f:
            f.write(data)

        return None
    except Exception:
        return "Invalid password or corrupted file."

def create_zip(folder_path, zip_path):
    with zipfile.ZipFile(zip_path, 'w') as zipf:
        for filename in os.listdir(folder_path):
            filepath = os.path.join(folder_path, filename)
            zipf.write(filepath, arcname=filename)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        password = request.form['password']
        action = request.form['action']
        files = request.files.getlist('files')

        for folder in [UPLOAD_FOLDER, ENCRYPTED_FOLDER, DECRYPTED_FOLDER, ZIP_FOLDER]:
            for f in os.listdir(folder):
                os.remove(os.path.join(folder, f))

        for file in files:
            filename = file.filename
            if action == 'encrypt' and filename.endswith('.enc'):
                return jsonify(error="This file is already encrypted. Please select Decrypt.")
            if action == 'decrypt' and not filename.endswith('.enc'):
                return jsonify(error="This is not an encrypted file. Please select Encrypt.")

        for file in files:
            filename = file.filename
            input_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(input_path)

            if action == 'encrypt':
                output_path = os.path.join(ENCRYPTED_FOLDER, filename + '.enc')
                encrypt_file(input_path, output_path, password)
            elif action == 'decrypt':
                output_filename = filename[:-4]  # remove .enc
                output_path = os.path.join(DECRYPTED_FOLDER, output_filename)
                error_message = decrypt_file(input_path, output_path, password)
                if error_message:
                    return jsonify(error=error_message)

        if action == 'encrypt':
            folder_to_zip = ENCRYPTED_FOLDER
        else:
            folder_to_zip = DECRYPTED_FOLDER

        all_files = os.listdir(folder_to_zip)

        if len(all_files) == 1:
            filepath = os.path.join(folder_to_zip, all_files[0])
            return send_file(filepath, as_attachment=True)
        else:
            zip_path = os.path.join(ZIP_FOLDER, 'files.zip')
            create_zip(folder_to_zip, zip_path)
            return send_file(zip_path, as_attachment=True)

    return render_template('index.html')

if __name__ == "__main__":
    app.run(debug=True,port=20000)
