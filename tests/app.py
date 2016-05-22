"""
Flask app for testing the OpenID Connect extension.
"""

import json

from flask import Flask, g
from flask.ext.oidc import OpenIDConnect


def index():
    return "too many secrets", 200, {
        'Content-Type': 'text/plain; charset=utf-8'
    }


def api():
    return json.dumps({'token': g.oidc_token_info})


def create_app(config, oidc_overrides=None):
    app = Flask(__name__)
    app.config.update(config)
    if oidc_overrides is None:
        oidc_overrides = {}
    oidc = OpenIDConnect(app, **oidc_overrides)
    app.route('/')(oidc.check(index))
    app.route('/api', methods=['GET', 'POST'])(
        oidc.accept_token(True, ['openid'])(api))
    return app
