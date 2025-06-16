from flask import Flask, request, jsonify
from cipher.rsa import RSACipher 
from cipher.ecc import ECCCipher
app = Flask(__name__)

# RSA CIPHER ALGORITHM
rsa_cipher = RSACipher()

@app.route('/api/rsa/generate_keys', methods=['GET'])
def rsa_generate_keys():
    rsa_cipher.generate_keys()
    return jsonify({'message': 'Keys generated successfully'})

@app.route("/api/rsa/encrypt", methods=["POST"])
def rsa_encrypt():
    data = request.json
    message = data['message']
    key_type = data['key_type']
    private_key, public_key = rsa_cipher.load_keys()

    key = None
    if key_type == 'public':
        key = public_key
    elif key_type == 'private':
        key = private_key
    else:
        return jsonify({'error': 'Invalid key type'})

    encrypted_message = rsa_cipher.encrypt(message, key)
    encrypted_hex = encrypted_message.hex() # Chuyển đổi bytes sang dạng hex string
    return jsonify({'encrypted_message': encrypted_hex})

@app.route("/api/rsa/decrypt", methods=["POST"])
def rsa_decrypt():
    data = request.json
    ciphertext_hex = data['ciphertext']
    key_type = data['key_type']
    private_key, public_key = rsa_cipher.load_keys()

    key = None
    if key_type == 'public':
        key = public_key
    elif key_type == 'private':
        key = private_key
    else:
        return jsonify({'error': 'Invalid key type'})

    ciphertext = bytes.fromhex(ciphertext_hex) # Chuyển đổi hex string sang bytes
    decrypted_message = rsa_cipher.decrypt(ciphertext, key)
    return jsonify({'decrypted_message': decrypted_message})

@app.route('/api/rsa/sign', methods=['POST'])
def rsa_sign_message():
    data = request.json
    message = data['message']
    private_key, _ = rsa_cipher.load_keys() # Chỉ cần private key để ký

    signature = rsa_cipher.sign(message, private_key)
    signature_hex = signature.hex() # Chuyển đổi bytes sang dạng hex string
    return jsonify({'signature': signature_hex})

@app.route('/api/rsa/verify', methods=['POST'])
def rsa_verify_signature():
    data = request.json
    message = data['message']
    signature_hex = data['signature']
    public_key, _ = rsa_cipher.load_keys() # Chỉ cần public key để xác minh

    signature = bytes.fromhex(signature_hex) # Chuyển đổi hex string sang bytes
    is_verified = rsa_cipher.verify(message, signature, public_key)
    return jsonify({'is_verified': is_verified})


ecc_cipher = ECCCipher() # Khởi tạo đối tượng ECCipher

@app.route('/api/ecc/generate_keys', methods=['GET']) # Định nghĩa endpoint để tạo khóa ECC
def ecc_generate_keys():
    ecc_cipher.generate_keys() # Gọi phương thức tạo khóa của ECCipher
    return jsonify({'message': 'Keys generated successfully'}) # Trả về thông báo thành công

@app.route('/api/ecc/sign', methods=['POST']) # Định nghĩa endpoint để ký dữ liệu bằng ECC
def ecc_sign_message():
    data = request.json # Lấy dữ liệu JSON từ request
    message = data['message'] # Lấy thông điệp cần ký
    private_key, _ = ecc_cipher.load_keys() # Tải khóa riêng tư (chỉ cần private key để ký)

    signature = ecc_cipher.sign(message, private_key) # Ký thông điệp
    signature_hex = signature.hex() # Chuyển đổi bytes sang dạng hex string
    return jsonify({'signature': signature_hex}) # Trả về chữ ký dưới dạng hex

@app.route('/api/ecc/verify', methods=['POST']) # Định nghĩa endpoint để xác minh chữ ký ECC
def ecc_verify_signature():
    data = request.json # Lấy dữ liệu JSON từ request
    message = data['message'] # Lấy thông điệp gốc
    signature_hex = data['signature'] # Lấy chữ ký dưới dạng hex string
    public_key, _ = ecc_cipher.load_keys() # Tải khóa công khai (chỉ cần public key để xác minh)

    signature = bytes.fromhex(signature_hex) # Chuyển đổi hex string sang bytes
    is_verified = ecc_cipher.verify(message, signature, public_key) # Xác minh chữ ký
    return jsonify({'is_verified': is_verified}) # Trả về kết quả xác minh (True/False)
# main function
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)