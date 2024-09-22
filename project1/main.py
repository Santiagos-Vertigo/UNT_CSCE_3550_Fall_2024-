from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt
from datetime import datetime, timedelta
import base64

app = Flask(__name__)

# Dictionary to store keys
keys = {}
EXPIRE_TIME = 3600  # Example expiration time for keys

# Function to convert an integer to Base64URL-encoded string
def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

# Function to generate an RSA key pair and return the keys in JWKS format
def generate_rsa_key(kid):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # Serialize public key in JWKS format
    public_numbers = public_key.public_numbers()
    public_jwk = {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": int_to_base64(public_numbers.n),
        "e": int_to_base64(public_numbers.e),
    }

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    return private_key_pem, public_jwk

# Route to generate a new key pair
def generate_key_pair(kid, expiry):
    private_key_pem, public_jwk = generate_rsa_key(kid)
    keys[kid] = {
        "private_key": private_key_pem,
        "public_key": public_jwk,
        "expiry": expiry
    }

# JWKS endpoint: Return only unexpired public keys in JWKS format
@app.route('/.well-known/jwks.json', methods=['GET'])
def get_jwks():
    # Filter out expired keys
    jwks_keys = [
        key_data["public_key"]
        for kid, key_data in keys.items()
        if key_data["expiry"] > datetime.utcnow()
    ]
    return jsonify({"keys": jwks_keys}), 200

# Authentication route to return a JWT
@app.route('/auth', methods=['POST'])
def auth():
    params = request.args
    kid = "goodKID"
    expiry_time = datetime.utcnow() + timedelta(hours=1)
    
    # Handle expired token case
    if 'expired' in params:
        kid = "expiredKID"
        expiry_time = datetime.utcnow() - timedelta(hours=1)

    token_payload = {
        "user": "username",
        "exp": expiry_time
    }
    
    private_key_pem = keys[kid]["private_key"]
    encoded_jwt = jwt.encode(token_payload, private_key_pem, algorithm="RS256", headers={"kid": kid})
    return encoded_jwt, 200

# Home route
@app.route('/')
def home():
    return "Welcome to the JWKS and JWT server!", 200

# Generate initial key pairs
generate_key_pair("goodKID", datetime.utcnow() + timedelta(hours=1))
generate_key_pair("expiredKID", datetime.utcnow() - timedelta(hours=1))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
