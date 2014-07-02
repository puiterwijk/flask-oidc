"""
Flask app for testing the OpenID Connect extension.
"""

from flask import Flask
from flask.ext.oidc import OpenIDConnect


def index():
    return "too many secrets", 200, {
        'Content-Type': 'text/plain; charset=utf-8'
    }


def create_app(config, oidc_overrides=None):
    app = Flask(__name__)
    app.config.update(config)
    if oidc_overrides is None:
        oidc_overrides = {}
    oidc = OpenIDConnect(app, **oidc_overrides)
    app.route('/')(oidc.check(index))
    return app
