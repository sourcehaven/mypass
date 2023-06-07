import flask
import requests
from flask import Blueprint, request
from flask_jwt_extended import jwt_required
from werkzeug.exceptions import UnsupportedMediaType

from mypass.middlewares import RaiseErr
from mypass.persistence.session.memory import session
from mypass.utils import BearerAuth
from mypass import crypto

DbApi = Blueprint('db', __name__)


@DbApi.route('/api/db/tiny/master/create', methods=['POST'])
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


@DbApi.route('/api/db/tiny/master/read', methods=['POST'])
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

    return resp.json(), resp.status_code


@DbApi.route('/api/db/tiny/master/update', methods=['POST'])
@RaiseErr.raise_if_unauthorized
@jwt_required(fresh=True)
def update_master_pw():
    son = request.json
    host = flask.current_app.config['DB_API_HOST']
    port = flask.current_app.config['DB_API_PORT']
    resp = requests.post(
        f'{host}:{port}/api/db/tiny/master/update',
        proxies={'http': f'{host}:{port}', 'https': f'{host}:{port}'},
        json=son)
    return resp.json(), resp.status_code
