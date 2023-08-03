from flask import Blueprint, request

from mypass.crypto import init_pw, encrypt_secret, decrypt_secret

CryptoApi = Blueprint('crypto', __name__)


@CryptoApi.route('/api/crypto/encrypt', methods=['POST'])
def crypto_encrypt():
    son = request.json
    msg, pw = son['secret'], son['pw']
    secret, salt = encrypt_secret(msg, pw)
    return {'secret': secret, 'salt': salt}, 200


@CryptoApi.route('/api/crypto/decrypt', methods=['POST'])
def crypto_decrypt():
    son = request.json
    secret, pw, salt = son['secret'], son['pw'], son['salt']
    msg = decrypt_secret(secret, pw, salt)
    return {'message': msg}, 200


@CryptoApi.route('/api/crypto/init', methods=['POST'])
def crypto_init():
    token = init_pw()
    return {'token': token}, 200
