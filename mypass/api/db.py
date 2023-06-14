import os

import flask
from flask import Blueprint, request
from flask_jwt_extended import jwt_required, get_jwt_identity

from mypass import crypto
from mypass.middlewares import RaiseErr
from . import _utils as utils

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
    """
    Returns:
        201 status code on success
    """

    request_obj = request.json
    identity = get_jwt_identity()
    user = identity['user']
    pw = identity['pw']
    new_pw = request_obj['pw']

    res = utils.get_master_info(user)
    if res is not None:
        secret_token, secret_pw, salt = res
        token, salt = utils.refresh_master_token(secret_token, pw, salt, new_pw)
        hashed_pw = crypto.hash_pw(new_pw, salt)
        resp = utils.update_user(user, token=token, pw=hashed_pw, salt=salt)

        if resp.status_code == 200:
            return flask.redirect('/api/auth/login', 307)
        return resp.json(), resp.status_code
    return {'msg': f'AUTHORIZATION FAILURE :: Could not update master password for user {user}.'}, 401


@DbApi.route('/api/db/vault/create', methods=['POST'])
@RaiseErr.raise_if_unauthorized
@jwt_required(optional=bool(int(os.environ.get('MYPASS_OPTIONAL_JWT_CHECKS', 0))))
def create_vault_pw():
    """
    Returns:
        201 status code on success
    """

    request_obj = dict(request.json)
    protected_fields = request_obj.pop('protected_fields', None)
    identity = get_jwt_identity()
    user = identity['user']
    pw = identity['pw']

    resp = utils.create_vault_pw(user, pw, fields=request_obj, protected_fields=protected_fields)
    return resp.json(), resp.status_code
