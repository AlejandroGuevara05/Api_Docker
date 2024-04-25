from flask import Flask, request, jsonify
import datetime
from cryptography.fernet import Fernet

app = Flask(__name__)
encryption_key = None
cipher_suite = None

@app.route("/generate_token", methods=['GET']) 
def generate_token():
    global encryption_key, cipher_suite
    encryption_key = Fernet.generate_key()
    cipher_suite = Fernet(encryption_key)
    return jsonify({'encryption_key': encryption_key.decode()})

@app.route("/hello_date", methods=['GET'])
def hello_date():
    now = datetime.datetime.now()
    return jsonify({'message': 'Hola mundo', 'date': now.strftime('%Y-%m-%d %H:%M:%S')})

@app.route("/encrypt", methods=['POST'])
def encrypt():
    if cipher_suite is None: 
        return jsonify({'error': 'No se ha generado un token'}), 400
    data = request.get_json()
    text = data['text']
    token = cipher_suite.encrypt(text.encode())
    return jsonify({'encryption_message': token.decode()})

@app.route("/decrypt", methods=['POST'])
def decrypt():
    if cipher_suite is None:
        return jsonify({'error': 'No se ha generado un token'}), 400
    data = request.get_json()
    encrypted_text = data['encrypted_text']
    decrypted_text = cipher_suite.decrypt(encrypted_text.encode())
    return jsonify({'decrypted_message': decrypted_text.decode()})

@app.route("/validar_token", methods=['POST'])
def validar_token():
    if encryption_key is None:
        return jsonify({'error': 'No se ha generado un token'}), 400
    data = request.get_json()
    token_a_validar = data.get('token')
    if token_a_validar is None:
        return jsonify({'error': 'No se proporcionó token para validar'}), 400
    if token_a_validar == encryption_key.decode():
        return jsonify({'valid': True})
    else:
        return jsonify({'valid': False, 'error': 'El token no coincide con el generado'}), 400
    
@app.route("/invalidar_token", methods=['POST'])
def invalidar_token():
    global encryption_key, cipher_suite
    if encryption_key is None:
        return jsonify({'error': 'No se puede invalidar porque no se ha generado un token'})
    data = request.get_json()
    token_a_invalidar = data.get('token')
    if token_a_invalidar == encryption_key.decode():
        encryption_key = None
        cipher_suite = None
        return jsonify({'result': 'Token desactivado'})
    else:
        return jsonify({'error': 'El token no es valido, proporciona un token valido para invalidarlo'}), 400

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=3000)