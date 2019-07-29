"""
Flask app for testing the OpenID Connect extension.
"""

import json
from unittest.mock import MagicMock, Mock

from flask import Flask, g
import flask_oidc
from tests.json_snippets import *

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


def get_test1():
    return "successful call to test1", 200, {
        'Content-Type': 'text/plain; charset=utf-8'
    }


def get_test2():
    return "successful call to test2", 200, {
        'Content-Type': 'text/plain; charset=utf-8'
    }


def get_test3():
    return "successful call to test3", 200, {
        'Content-Type': 'text/plain; charset=utf-8'
    }


def get_unprotected():
    return "successful call to unprotected", 200, {
        'Content-Type': 'text/plain; charset=utf-8'
    }


def raw_api():
    return {'token': g.oidc_token_info}


def api():
    return json.dumps(raw_api())


def get_test4():
    return "successful call to test4", 200, {
        'Content-Type': 'text/plain; charset=utf-8'
    }


callback_method = Mock()


def create_app(config, oidc_overrides=None):
    global oidc

    app = Flask(__name__)
    app.config.update(config)
    if oidc_overrides is None:
        oidc_overrides = {}
    app.oidc = flask_oidc.OpenIDConnect(app, **oidc_overrides)
    oidc = app.oidc

    app.route('/')(app.oidc.check(index))
    app.route('/at')(app.oidc.check(get_at))
    app.route('/rt')(app.oidc.check(get_rt))
    # Check standalone usage
    rendered = app.oidc.accept_token(True, ['openid'])(api)
    app.route('/api', methods=['GET', 'POST'])(rendered)

    configure_keycloak_test_uris(app)

    # Check combination with an external API renderer like Flask-RESTful
    unrendered = app.oidc.accept_token(True, ['openid'], render_errors=False)(raw_api)

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


def configure_keycloak_test_uris(app):
    test1 = app.oidc.check_authorization(True)(get_test1)
    app.route('/test1', methods=['GET', 'POST'])(test1)
    test2 = app.oidc.check_authorization(True)(get_test2)
    app.route('/test2', methods=['GET', 'POST'])(test2)
    test3 = app.oidc.check_authorization(True)(get_test3)
    app.route('/test3', methods=['GET', 'POST'])(test3)

    callback_method.return_value = True

    test4 = app.oidc.check_authorization(True, validation_func=callback_method)(get_test4)
    app.route('/test4', methods=['GET', 'POST'])(test4)

    unprotected = app.oidc.check_authorization(False)(get_unprotected)
    app.route('/unprotected', methods=['GET'])(unprotected)


def _configure_mock_object(test_app):
    test_app.oidc.validate_token = Mock()
    test_app.oidc.validate_token.return_value = True
    test_app.oidc.keycloakApi = MagicMock(autospec=flask_oidc.KeycloakAPI)
    test_app.oidc.keycloakApi.authorize = Mock()
    test_app.oidc.keycloakApi.authorize.return_value = valid_rpt
    test_app.oidc.keycloakApi.get_access_token = Mock()
    test_app.oidc.keycloakApi.get_access_token.return_value = access_token


def configure_mock_object_version1(test_app):
    _configure_mock_object(test_app)

    test_app.oidc.keycloakApi.jwt_decode = Mock()
    test_app.oidc.keycloakApi.jwt_decode.return_value = decoded_jwt_with_permission_test1_and_test2
    test_app.oidc.keycloakApi.get_resource_info = Mock()
    test_app.oidc.keycloakApi.get_resource_info.side_effect = [resource_test1, resource_test2]


def configure_mock_version2(test_app):
    _configure_mock_object(test_app)
    test_app.oidc.keycloakApi.jwt_decode.return_value = decoded_jwt_with_permission_test3
    test_app.oidc.keycloakApi.get_resource_info = Mock()
    test_app.oidc.keycloakApi.get_resource_info.side_effect = [resource_test3]

def configure_mock_version3(test_app):
    _configure_mock_object(test_app)
    test_app.oidc.keycloakApi.jwt_decode.return_value = None
    test_app.oidc.keycloakApi.get_resource_info = Mock()
    test_app.oidc.keycloakApi.get_resource_info.side_effect = [resource_test3]
