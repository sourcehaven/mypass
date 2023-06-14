import os

import flask
import requests
from flask import Blueprint, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from mypass_logman.persistence import session
from mypass_logman.utils import BearerAuth

from mypass import crypto
from mypass.middlewares import RaiseErr
from ._utils import get_master_info, update_user, get_updated_token

DbApi = Blueprint('db', __name__)


@DbApi.route('/api/db/master/read', methods=['POST'])
@RaiseErr.raise_if_unauthorized
@jwt_required(fresh=True, optional=bool(int(os.environ.get('MYPASS_OPTIONAL_JWT_CHECKS', 0))))
def query_master_pw():
    # TODO: return identity?
    return {
        'msg': 'NOT IMPLEMENTED :: Your master password is stored in a hashed format, it cannot be recovered. Ever.'
    }, 501


@DbApi.route('/api/db/master/update', methods=['POST'])
@RaiseErr.raise_if_unauthorized
@jwt_required(fresh=True, optional=bool(int(os.environ.get('MYPASS_OPTIONAL_JWT_CHECKS', 0))))
def update_master_pw():
    request_obj = request.json
    identity = get_jwt_identity()
    user = identity['user']
    pw = identity['pw']
    new_pw = request_obj['pw']

    res = get_master_info(user)
    if res is not None:
        secret_token, secret_pw, salt = res
        token, salt = get_updated_token(secret_token, pw, salt, new_pw)
        hashed_pw = crypto.hash_pw(new_pw, salt)
        resp = update_user(user, token=token, pw=hashed_pw, salt=salt)

        if resp.status_code == 200:
            return flask.redirect('/api/auth/login', 307)
        return resp.json(), resp.status_code
    return {'msg': f'AUTHORIZATION FAILURE :: Could not update master password for user {user}.'}, 401


@DbApi.route('/api/db/vault/create', methods=['POST'])
@RaiseErr.raise_if_unauthorized
@jwt_required(optional=bool(int(os.environ.get('MYPASS_OPTIONAL_JWT_CHECKS', 0))))
def create_vault_pw():
    request_obj = request.json
    host = flask.current_app.config['DB_API_HOST']
    port = flask.current_app.config['DB_API_PORT']
    key = get_jwt_identity()

    resp = requests.post(
        f'{host}/api/db/tiny/master/create',
        proxies={'http': f'{host}:{port}', 'https': f'{host}:{port}'},
        auth=BearerAuth(session['access_token']), json=request_obj)
    if resp.status_code == 200:
        response_obj = resp.json()
        pw, salt = response_obj['pw'], response_obj['salt']
        # decrypt old master token with password (stored as key) in jwt manager
        secret = crypto.decrypt_secret(pw, key, salt)
        # extract master token before connector string
        master_token = secret.split(crypto.CONNECTOR)[0]
        # encrypt the same master token with the new password
        secret, salt = crypto.encrypt_secret(f'{master_token}{crypto.CONNECTOR}{new_pw}', new_pw)
        # request password update
        resp = requests.post(
            f'{host}:{port}/api/db/tiny/master/update',
            proxies={'http': f'{host}:{port}', 'https': f'{host}:{port}'},
            json={'pw': secret, 'salt': salt}, auth=BearerAuth(session['access_token']))

    return resp.json(), resp.status_code
