import os

import flask
from flask import Blueprint, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.exceptions import UnsupportedMediaType

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
    assert user is not None and pw is not None, 'None user identity should not happen.'

    res = utils.get_master_info(user)
    if res is not None:
        secret_token, secret_pw, salt = res
        token, salt = utils.refresh_master_token(secret_token, pw, salt, new_pw)
        hashed_pw = crypto.hash_pw(new_pw, salt)
        result_json, status_code = utils.update_user(user, token=token, pw=hashed_pw, salt=salt)

        if status_code == 200:
            return flask.redirect(flask.url_for('auth.login', _method='POST', uid=result_json['_id']), 307)
        return result_json, status_code
    return {'msg': f'AUTHORIZATION FAILURE :: Could not update master password for user {user}.'}, 401


@DbApi.route('/api/db/vault/create', methods=['POST'])
@RaiseErr.raise_if_unauthorized
@jwt_required(optional=bool(int(os.environ.get('MYPASS_OPTIONAL_JWT_CHECKS', 0))))
def create_vault_entry():
    """
    Returns:
        201 status code on success
    """

    request_obj = dict(request.json)
    identity = get_jwt_identity()
    uid = identity['uid']
    user = identity['user']
    pw = identity['pw']
    assert uid is not None and user is not None and pw is not None, 'None user identity should not happen.'

    protected_fields = request_obj.pop('protected_fields', None)
    fields = request_obj.pop('fields', None)
    if fields is None:
        return {'msg': 'BAD REQUEST :: Empty request will not be handled.'}, 400

    result_json, status_code = utils.create_vault_entry(
        uid, pw, fields=fields, protected_fields=protected_fields)
    return result_json, status_code


@DbApi.route('/api/db/vault/read', methods=['POST'])
@RaiseErr.raise_if_unauthorized
@jwt_required(optional=bool(int(os.environ.get('MYPASS_OPTIONAL_JWT_CHECKS', 0))))
def query_vault_entry():
    """
    Returns:
        200 status code on success
    """

    try:
        request_obj = request.json
    except UnsupportedMediaType:
        request_obj = {}
    identity = get_jwt_identity()
    uid = identity['uid']
    user = identity['user']
    pw = identity['pw']
    assert uid is not None and user is not None and pw is not None, 'None user identity should not happen.'

    doc_id = request_obj.get('_id', None)
    doc_ids = request_obj.get('_ids', None)
    cond = request_obj.get('cond', None)
    result_json, status_code = utils.query_vault_entry(uid, pw, doc_id=doc_id, cond=cond, doc_ids=doc_ids)
    return result_json, status_code


@DbApi.route('/api/db/vault/update', methods=['POST'])
@RaiseErr.raise_if_unauthorized
@jwt_required(optional=bool(int(os.environ.get('MYPASS_OPTIONAL_JWT_CHECKS', 0))))
def update_vault_entry():
    """
    Returns:
        200 status code on success
    """

    request_obj = request.json
    identity = get_jwt_identity()
    uid = identity['uid']
    user = identity['user']
    pw = identity['pw']
    assert uid is not None and user is not None and pw is not None, 'None user identity should not happen.'

    doc_id = request_obj.get('_id', None)
    doc_ids = request_obj.get('_ids', None)
    fields = request_obj.get('fields', None)
    protected_fields = request_obj.get('protected_fields', None)
    remove_keys = request_obj.get('remove_keys', None)
    cond = request_obj.get('cond', None)

    # TODO: Bad request if everything is None?

    # TODO: implementation things to watch for:
    #  - updating protected fields will require master token for decryption end re-encryption
    #  - generate and save new salt, under _salt -> similarly to how its done in vault pw creation
    #  - returning somewhat meaningful error message if no success
    #  - implement helper methods similar to the above mentioned endpoints
    raise NotImplementedError()


@DbApi.route('/api/db/vault/delete', methods=['POST'])
@RaiseErr.raise_if_unauthorized
@jwt_required(optional=bool(int(os.environ.get('MYPASS_OPTIONAL_JWT_CHECKS', 0))))
def delete_vault_entry():
    """
    Returns:
        200 status code on success
    """

    request_obj = request.json
    identity = get_jwt_identity()
    uid = identity['uid']
    user = identity['user']
    pw = identity['pw']
    assert uid is not None and user is not None and pw is not None, 'None user identity should not happen.'

    doc_id = request_obj.get('_id', None)
    doc_ids = request_obj.get('_ids', None)
    cond = request_obj.get('cond', None)

    # TODO: Bad request if everything is None?

    # TODO: implementation things to watch for:
    #  - this should be basically implemented by the same logic as update
    #  - except you do not need to watch out for decrypting and encrypting
    raise NotImplementedError()
