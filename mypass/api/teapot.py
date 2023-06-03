from flask import Blueprint, Response

TeapotApi = Blueprint('teapot', __name__)


@TeapotApi.route('/api/teapot', methods=['GET'])
def teapot():
    return Response('I am a teapot!', status=418, mimetype='text')
