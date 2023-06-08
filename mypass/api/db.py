import flask
import requests
from flask import Blueprint, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.exceptions import UnsupportedMediaType

from mypass.middlewares import RaiseErr
from mypass.persistence.session.memory import session
from mypass.utils import BearerAuth
from mypass import crypto

DbApi = Blueprint('db', __name__)


@DbApi.route('/api/db/master/create', methods=['POST'])
@RaiseErr.raise_if_unauthorized
@jwt_required(fresh=True)
def create_master_pw():
    son = request.json
    host = flask.current_app.config['DB_API_HOST']
    port = flask.current_app.config['DB_API_PORT']

    master_token, salt = crypto.gen_master_token(**son)

    resp = requests.post(
        url=f'{host}:{port}/api/db/tiny/master/create',
        proxies={'http': f'{host}:{port}', 'https': f'{host}:{port}'},
        json={'pw': master_token, 'salt': salt}, auth=BearerAuth(session['access_token']))

    return resp.json(), resp.status_code


@DbApi.route('/api/db/master/read', methods=['POST'])
@RaiseErr.raise_if_unauthorized
@jwt_required(fresh=True)
def query_master_pw():
    try:
        son = request.json
    except UnsupportedMediaType:
        son = {}
    host = flask.current_app.config['DB_API_HOST']
    port = flask.current_app.config['DB_API_PORT']
    resp = requests.post(
        f'{host}:{port}/api/db/tiny/master/read',
        proxies={'http': f'{host}:{port}', 'https': f'{host}:{port}'},
        json=son, auth=BearerAuth(session['access_token']))

    key = get_jwt_identity()
    if resp.status_code == 200:
        son = resp.json()
        pw, salt = son['pw'], son['salt']
        secret = crypto.decrypt_secret(pw, key, salt)
        # extract master password after connector string
        mpass = secret.split(crypto.CONNECTOR)[1]
        return {'pw': mpass}, 200

    return resp.json(), resp.status_code


@DbApi.route('/api/db/master/update', methods=['POST'])
@RaiseErr.raise_if_unauthorized
@jwt_required(fresh=True)
def update_master_pw():
    son = request.json
    host = flask.current_app.config['DB_API_HOST']
    port = flask.current_app.config['DB_API_PORT']
    new_pw = son['pw']

    resp = requests.post(
        f'{host}:{port}/api/db/tiny/master/read',
        proxies={'http': f'{host}:{port}', 'https': f'{host}:{port}'},
        auth=BearerAuth(session['access_token']))

    key = get_jwt_identity()
    if resp.status_code == 200:
        son = resp.json()
        pw, salt = son['pw'], son['salt']
        secret = crypto.decrypt_secret(pw, key, salt)
        # extract master token before connector string
        master_token = secret.split(crypto.CONNECTOR)[0]

        secret, salt = crypto.encrypt_secret(f'{master_token}{crypto.CONNECTOR}{new_pw}', new_pw)

        resp = requests.post(
            f'{host}:{port}/api/db/tiny/master/update',
            proxies={'http': f'{host}:{port}', 'https': f'{host}:{port}'},
            json={'pw': secret, 'salt': salt})

    return resp.json(), resp.status_code
