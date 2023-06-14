import logging
import os

import flask
from flask import Blueprint, request
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt

from mypass.persistence.blacklist.memory import blacklist
from ._utils import register_user, check_user_login

AuthApi = Blueprint('auth', __name__)


@AuthApi.route('/api/auth/registration', methods=['POST'])
def registration():
    user = request.json['user']
    pw = request.json['pw']
    resp = register_user(user, pw)
    if resp.status_code == 201:
        return flask.redirect('/api/auth/login', 307)
    return resp.json(), resp.status_code


@AuthApi.route('/api/auth/login', methods=['POST'])
@jwt_required(refresh=True, optional=True)
def login():
    request_obj = request.json
    identity = get_jwt_identity()
    # if we cant find authorization information in request header,
    # then passing along user in request is mandatory
    if identity is None:
        identity = {'user': request_obj['user'], 'pw': request_obj['pw']}
    user = identity['user']
    pw = identity['pw']
    if check_user_login(user, pw):
        access_token = create_access_token(identity=identity, fresh=True)
        refresh_token = create_refresh_token(identity=identity)
        return {'access_token': access_token, 'refresh_token': refresh_token}, 201
    return {'msg': f'AUTHORIZATION FAILURE :: Could not log in user {user}.'}, 401


@AuthApi.route('/api/auth/refresh', methods=['POST'])
@jwt_required(refresh=True, optional=bool(int(os.environ.get('MYPASS_OPTIONAL_JWT_CHECKS', 0))))
def refresh():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity, fresh=False)
    return {
        'access_token': access_token
    }, 201


@AuthApi.route('/api/auth/logout', methods=['DELETE'])
@jwt_required(optional=True)
def logout():
    logging.getLogger().debug('Logging out user.')
    try:
        jti = get_jwt()['jti']
        logging.getLogger().debug(f'Blacklisting token: {jti}.')
        blacklist.add(jti)
        return '', 204
    except KeyError:
        return '', 409
