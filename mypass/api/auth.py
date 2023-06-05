from flask import Blueprint, request
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt

AuthApi = Blueprint('auth', __name__)

_blacklist = set()


@AuthApi.route('/api/auth/signin', methods=['POST'])
def signin():
    _blacklist.clear()
    son = request.json
    pw = son['pw']
    access_token = create_access_token(identity=pw, fresh=True)
    refresh_token = create_refresh_token(identity=pw)
    return {
        'access_token': access_token,
        'refresh_token': refresh_token
    }, 201


@AuthApi.route('/api/auth/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    pw = get_jwt_identity()
    access_token = create_access_token(identity=pw, fresh=False)
    return {
        'access_token': access_token
    }, 201


@AuthApi.route('/api/auth/logout', methods=['DELETE'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    _blacklist.add(jti)
    return '', 204
