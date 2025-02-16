from flask import Flask, render_template, request, send_file, jsonify
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# AES Encryption for Files
def encrypt_file(file_path, key):
    cipher = AES.new(key, AES.MODE_CBC)
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size))
    encrypted_file_path = file_path + '.enc'
    with open(encrypted_file_path, 'wb') as f:
        f.write(cipher.iv + ct_bytes)
    return encrypted_file_path, key.hex()  # Return encrypted file path and key (in hex)

# AES Decryption for Files
def decrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        iv = f.read(16)  # Read the IV (first 16 bytes of the file)
        ciphertext = f.read()  # Read the rest of the file (encrypted data)

    # Initialize the AES cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the data and remove padding
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    # Save the decrypted data to a new file
    decrypted_file_path = file_path.replace('.enc', '_decrypted')
    with open(decrypted_file_path, 'wb') as f:
        f.write(plaintext)

    return decrypted_file_path

# Flask Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    if 'file' not in request.files:
        return "No file uploaded", 400#-
        return jsonify({'error': 'No file uploaded'}), 400#+
    file = request.files['file']
    if file.filename == '':
        return "No file selected", 400#-
        return jsonify({'error': 'No file selected'}), 400#+
#+
    # Validate file type and size#+
    if file.content_type not in ['application/octet-stream', 'application/pdf', 'text/plain']:#+
        return jsonify({'error': 'Invalid file type. Only PDF, Word, and text files are allowed.'}), 400#+
    if file.content_length > 10 * 1024 * 1024:  # 10 MB#+
        return jsonify({'error': 'File size exceeds the maximum limit of 10 MB.'}), 400#+
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(file_path)

    # Generate a 128-bit (16-byte) key
    key = get_random_bytes(16)

    # Encrypt the file
    encrypted_file_path, key_hex = encrypt_file(file_path, key)#-
    try:#+
        encrypted_file_path, key_hex = encrypt_file(file_path, key)#+
    except Exception as e:#+
        return jsonify({'error': f'Error encrypting file: {str(e)}'}), 500#+

    # Return the encrypted file and the key to the user
    return jsonify({
        'encrypted_file': encrypted_file_path,
        'key': key_hex  # Send the key to the user
    })

@app.route('/decrypt', methods=['POST'])
def decrypt():
    if 'file' not in request.files:
        return "No file uploaded", 400#-
        return jsonify({'error': 'No file uploaded'}), 400#+
    file = request.files['file']
    if file.filename == '':
        return "No file selected", 400#-
        return jsonify({'error': 'No file selected'}), 400#+
    key_hex = request.form['key']  # Get the key from the form
    key = bytes.fromhex(key_hex)  # Convert hex key back to bytes
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(file_path)
    decrypted_file_path = decrypt_file(file_path, key)#-
#+
    try:#+
        decrypted_file_path = decrypt_file(file_path, key)#+
    except Exception as e:#+
        return jsonify({'error': f'Error decrypting file: {str(e)}'}), 500#+
    return send_file(decrypted_file_path, as_attachment=True)

# Add the download route here
@app.route('/download')#-
@app.route('/download/<filename>')#+
def download_file(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename), as_attachment=True)#-
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)#+
    if not os.path.exists(file_path):#+
        return jsonify({'error': 'File not found'}), 404#+
    return send_file(file_path, as_attachment=True)#+

@app.route('/delete/<filename>')#+
def delete_file(filename):#+
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)#+
    if not os.path.exists(file_path):#+
        return jsonify({'error': 'File not found'}), 404#+
    os.remove(file_path)#+
    return jsonify({'message': 'File deleted successfully'})#+
if __name__ == '__main__':
    app.run(debug=True)
