from flask import Blueprint, request, jsonify
from core import aes_module, rsa_module, hmac_module, stego_module

main = Blueprint("main", __name__)


@main.route("/")
def index():
    return jsonify({"message": "Crypto Steganography API"})


# Add your crypto endpoints here
@main.route("/encrypt", methods=["POST"])
def encrypt_data():
    # Handle encryption logic
    pass


@main.route("/decrypt", methods=["POST"])
def decrypt_data():
    # Handle decryption logic
    pass
