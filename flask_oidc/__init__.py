from functools import wraps
import os
import json
from urllib import urlencode
from base64 import b64encode
import time as time_module

from flask import request, session, redirect, url_for
from oauth2client.client import flow_from_clientsecrets, OAuth2WebServerFlow, AccessTokenRefreshError
import httplib2


class MemoryCredentials(dict):
    pass


class OpenIDConnect(object):
    """
    @see: https://developers.google.com/api-client-library/python/start/get_started
    @see: https://developers.google.com/api-client-library/python/samples/authorized_api_web_server_calendar.py
    """
    def __init__(self, app=None, credentials_store=None, http=None, time=None, urandom=None):
        self.app = app
        if app is not None:
            self.init_app(app)

        # set from app config in .init_app()
        self.flow = None

        # optional, also set from app config
        self.google_apps_domain = None
        self.session_variable_prefix = 'oidc'

        # stuff that we might want to override for tests
        self.http = http if http is not None else httplib2.Http()
        self.credentials_store = credentials_store if credentials_store is not None else MemoryCredentials()
        self.time = time if time is not None else time_module.time
        self.urandom = urandom if urandom is not None else os.urandom

    def init_app(self, app):
        """
        Do setup that requires a Flask app.
        """
        # register callback route
        callback_path = app.config.get('OIDC_CALLBACK_PATH', '/oauth2callback')
        app.route(callback_path)(self.oauth2callback)

        with app.app_context():
            redirect_uri = url_for('oauth2callback')

        # load client_secrets.json
        self.flow = flow_from_clientsecrets(
            app.config['OIDC_CLIENT_SECRETS'],
            scope=['openid', 'email'],
            redirect_uri=redirect_uri)
        assert isinstance(self.flow, OAuth2WebServerFlow)

        self.google_apps_domain = app.config.get('OIDC_GOOGLE_APPS_DOMAIN')
        self.session_variable_prefix = app.config.get('OIDC_SESSION_VARIABLE_PREFIX', 'oidc')

        try:
            pass  # TODO: alternate credentials stores from OIDC_CREDENTIALS_STORE
        except KeyError:
            pass

    def s_pfx(self, name):
        return '{pfx}_{name}'.format(pfx=self.session_variable_prefix, name=name)

    def check(self, view_func):
        @wraps(view_func)
        def decorated(*args, **kwargs):
            id_token = session.get(self.s_pfx('id_token'))
            if id_token is None:
                return self.redirect_to_auth_server(request.url)

            if self.time() >= id_token['exp']:
                try:
                    credentials = self.credentials_store[id_token['sub']]
                except KeyError:
                    return self.redirect_to_auth_server(request.url)

                try:
                    credentials.refresh(self.http)
                    id_token = credentials.id_token
                    self.credentials_store[id_token['sub']] = credentials
                    session[self.s_pfx('id_token')] = id_token
                except AccessTokenRefreshError:
                    del self.credentials_store[id_token['sub']]
                    return self.redirect_to_auth_server(request.url)

            return view_func(*args, **kwargs)
        return decorated

    def redirect_to_auth_server(self, destination):
        csrf_token = b64encode(os.urandom(24))
        session[self.s_pfx('csrf_token')] = csrf_token
        state = {
            'csrf_token': csrf_token,
            'destination': destination,
        }
        extra_params = {
            'state': json.dumps(state),
        }
        if self.google_apps_domain is not None:
            extra_params['hd'] = self.google_apps_domain
        auth_url = '{url}&{extra_params}'.format(
            url=self.flow.step1_get_authorize_url(),
            extra_params=urlencode(extra_params))
        return redirect(auth_url)

    not_authorized = (
        'Not Authorized', 401, {
            'Content-Type': 'text/plain',
        })

    def is_id_token_valid(self, id_token):
        """
        Check if `id_token` is a current ID token for this application,
        was issued by the Apps domain we expected,
        and that the email address has been verified.

        @see: http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
        """
        if not id_token:
            return False

        # TODO: step 2: check issuer

        if isinstance(id_token['aud'], list):
            # step 3 for audience list
            if self.flow.client_id not in id_token['aud']:
                return False
            # step 4
            if 'azp' not in id_token:
                return False
        else:
            # step 3 for single audience
            if id_token['aud'] != self.flow.client_id:
                return False

        # step 5
        if id_token.get('azp') != self.flow.client_id:
            return False

        # steps 9, 10
        if not (id_token['iat'] <= self.time() < id_token['exp']):
            return False

        # TODO: step 11: check nonce

        # additional steps specific to our usage

        if id_token.get('hd') != self.google_apps_domain:
            return False

        if not id_token['email_verified']:
            return False

        return True

    def oauth2callback(self):
        """
        Exchange the auth code for actual credentials,
        then redirect to the originally requested page.
        """
        try:
            session_csrf_token = session.pop(self.s_pfx('csrf_token'))

            state = json.loads(request.args['state'])
            csrf_token = state['csrf_token']
            destination = state['destination']

            code = request.args['code']
        except (KeyError, ValueError):
            return self.not_authorized

        if csrf_token != session_csrf_token:
            return self.not_authorized

        credentials = self.flow.step2_exchange(code, http=self.http)
        id_token = credentials.id_token
        if not self.is_id_token_valid(id_token):
            return self.not_authorized

        self.credentials_store[id_token['sub']] = credentials
        # TODO: set the id_token as a persistent cookie, not a session cookie
        session[self.s_pfx('id_token')] = id_token

        # TODO: validate redirect destination
        return redirect(destination)
