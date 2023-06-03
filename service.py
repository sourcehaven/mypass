from argparse import ArgumentParser, Namespace
from datetime import timedelta

import waitress
from flask import Flask
from flask_jwt_extended import JWTManager

from mypass.api import TeapotApi


class MyPassArgs(Namespace):
    debug: bool
    host: str
    port: int


def run(debug=False, host='0.0.0.0', port=5757):
    app = Flask(__name__)
    app.register_blueprint(TeapotApi)

    jwt_key = 'sourcehaven'
    app.config['JWT_SECRET_KEY'] = jwt_key
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=10)
    JWTManager(app)

    if debug:
        app.run(host=host, port=port, debug=True)
    else:
        waitress.serve(app, host=host, port=port, channel_timeout=10, threads=1)


if __name__ == '__main__':
    arg_parser = ArgumentParser('MyPass')
    arg_parser.add_argument(
        '-d', '--debug', action='store_true', default=False,
        help='flag for debugging mode')
    arg_parser.add_argument(
        '-H', '--host', type=str, default='0.0.0.0',
        help='specifies the host for the microservice, defaults to "0.0.0.0"')
    arg_parser.add_argument(
        '-p', '--port', type=int, default=5757,
        help='specifies the port for the microservice, defaults to 5757')

    args = arg_parser.parse_args(namespace=MyPassArgs)
    run(debug=args.debug, host=args.host, port=args.port)
