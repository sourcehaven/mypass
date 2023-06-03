from flask import Blueprint

TeapotApi = Blueprint('teapot', __name__)


@TeapotApi.route('/api/teapot', methods=['GET'])
def teapot():
    return 'I am a teapot!', 418
