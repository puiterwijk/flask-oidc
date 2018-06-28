"""
Flask app for testing the OpenID Connect extension.
"""

import json

from flask import Flask, g
from flask_oidc import OpenIDConnect

oidc = None


def index():
    return "too many secrets", 200, {
        'Content-Type': 'text/plain; charset=utf-8'
    }

def get_at():
    return oidc.get_access_token(), 200, {
        'Content-Type': 'text/plain; charset=utf-8'
    }

def get_rt():
    return oidc.get_refresh_token(), 200, {
        'Content-Type': 'text/plain; charset=utf-8'
    }

def raw_api():
    return {'token': g.oidc_token_info}

def api():
    return json.dumps(raw_api())

def create_app(config, oidc_overrides=None):
    global oidc

    app = Flask(__name__)
    app.config.update(config)
    if oidc_overrides is None:
        oidc_overrides = {}
    oidc = OpenIDConnect(app, **oidc_overrides)
    app.route('/')(oidc.check(index))
    app.route('/at')(oidc.check(get_at))
    app.route('/rt')(oidc.check(get_rt))
    # Check standalone usage
    rendered = oidc.accept_token(True, ['openid'])(api)
    app.route('/api', methods=['GET', 'POST'])(rendered)

    # Check combination with an external API renderer like Flask-RESTful
    unrendered = oidc.accept_token(True, ['openid'], render_errors=False)(raw_api)
    def externally_rendered_api(*args, **kwds):
        inner_response = unrendered(*args, **kwds)
        if isinstance(inner_response, tuple):
            raw_response, response_code, headers = inner_response
            rendered_response = json.dumps(raw_response), response_code, headers
        else:
            rendered_response = json.dumps(inner_response)
        return rendered_response
    app.route('/external_api', methods=['GET', 'POST'])(externally_rendered_api)
    return app
