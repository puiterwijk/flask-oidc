from functools import wraps
import os
import json
from base64 import b64encode
import time as time_module
from copy import copy
import logging

from six.moves.urllib.parse import urlencode
from flask import request, session, redirect, url_for, g
from oauth2client.client import flow_from_clientsecrets, OAuth2WebServerFlow,\
    AccessTokenRefreshError
import httplib2
from itsdangerous import TimedJSONWebSignatureSerializer, SignatureExpired

__all__ = ['OpenIDConnect', 'MemoryCredentials']

logger = logging.getLogger(__name__)


class MemoryCredentials(dict):
    """
    Non-persistent local credentials store.
    Use this if you only have one app server, and don't mind making everyone
    log in again after a restart.
    """
    pass


class OpenIDConnect(object):
    """
    @see: https://developers.google.com/api-client-library/python/start/get_started
    @see: https://developers.google.com/api-client-library/python/samples/authorized_api_web_server_calendar.py
    """
    def __init__(self, app=None, credentials_store=None, http=None, time=None,
                 urandom=None):
        # set from app config in .init_app()
        self.callback_path = None
        self.flow = None
        self.cookie_serializer = None

        # optional, also set from app config
        self.google_apps_domain = None
        self.id_token_cookie_name = 'oidc_id_token'
        self.id_token_cookie_ttl = 7 * 86400  # one week
        # should ONLY be turned off for local debugging
        self.id_token_cookie_secure = True

        # stuff that we might want to override for tests
        self.http = http if http is not None else httplib2.Http()
        self.credentials_store = credentials_store\
            if credentials_store is not None\
            else MemoryCredentials()
        self.time = time if time is not None else time_module.time
        self.urandom = urandom if urandom is not None else os.urandom

        # get stuff from the app's config, which may override stuff set above
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """
        Do setup that requires a Flask app.
        """
        # register callback route and cookie-setting decorator
        app.route('/oidc_callback')(self.oidc_callback)
        app.after_request(self.after_request)

        # load client_secrets.json
        self.flow = flow_from_clientsecrets(
            app.config['OIDC_CLIENT_SECRETS'],
            scope=['openid', 'email'])
        assert isinstance(self.flow, OAuth2WebServerFlow)

        # create a cookie signer using the Flask secret key
        self.cookie_serializer = TimedJSONWebSignatureSerializer(
            app.config['SECRET_KEY'])

        try:
            self.google_apps_domain = app.config['OIDC_GOOGLE_APPS_DOMAIN']
        except KeyError:
            pass

        try:
            self.id_token_cookie_name = app.config['OIDC_ID_TOKEN_COOKIE_NAME']
        except KeyError:
            pass

        try:
            self.id_token_cookie_ttl = app.config['OIDC_ID_TOKEN_COOKIE_TTL']
        except KeyError:
            pass

        try:
            self.id_token_cookie_secure =\
                app.config['OIDC_ID_TOKEN_COOKIE_SECURE']
        except KeyError:
            pass

        try:
            self.credentials_store = app.config['OIDC_CREDENTIALS_STORE']
        except KeyError:
            pass

    def get_cookie_id_token(self):
        try:
            id_token_cookie = request.cookies[self.id_token_cookie_name]
            return self.cookie_serializer.loads(id_token_cookie)
        except (KeyError, SignatureExpired):
            logger.debug("Missing or invalid ID token cookie", exc_info=True)
            return None

    def set_cookie_id_token(self, id_token):
        """
        Cooperates with @after_request to set a new ID token cookie.
        """
        g.oidc_id_token = id_token
        g.oidc_id_token_dirty = True

    def after_request(self, response):
        """
        Set a new ID token cookie if the ID token has changed.
        """
        if getattr(g, 'oidc_id_token_dirty', False):
            signed_id_token = self.cookie_serializer.dumps(g.oidc_id_token)
            response.set_cookie(
                self.id_token_cookie_name, signed_id_token,
                secure=self.id_token_cookie_secure,
                httponly=True,
                max_age=self.id_token_cookie_ttl)
        return response

    def authenticate_or_redirect(self):
        """
        Helper function suitable for @app.before_request and @check (below).
        Sets g.oidc_id_token to the ID token if the user has successfully
        authenticated, else returns a redirect object so they can go try
        to authenticate.
        :return: A redirect, or None if the user is authenticated.
        """
        # the auth callback and error pages don't need user to be authenticated
        if request.endpoint in frozenset(['oidc_callback', 'oidc_error']):
            return None

        # retrieve signed ID token cookie
        id_token = self.get_cookie_id_token()
        if id_token is None:
            return self.redirect_to_auth_server(request.url)

        # ID token expired
        # when Google is the IdP, this happens after one hour
        if self.time() >= id_token['exp']:
            # get credentials from store
            try:
                credentials = self.credentials_store[id_token['sub']]
            except KeyError:
                logger.debug("Expired ID token, credentials missing",
                             exc_info=True)
                return self.redirect_to_auth_server(request.url)

            # refresh and store credentials
            try:
                credentials.refresh(self.http)
                id_token = credentials.id_token
                self.credentials_store[id_token['sub']] = credentials
                self.set_cookie_id_token(id_token)
            except AccessTokenRefreshError:
                # Can't refresh. Wipe credentials and redirect user to IdP
                # for re-authentication.
                logger.debug("Expired ID token, can't refresh credentials",
                             exc_info=True)
                del self.credentials_store[id_token['sub']]
                return self.redirect_to_auth_server(request.url)

        # make ID token available to views
        g.oidc_id_token = id_token

        return None

    def check(self, view_func):
        """
        Use this to decorate view functions if only some of your app's views
        require authentication.
        """
        @wraps(view_func)
        def decorated(*args, **kwargs):
            response = self.authenticate_or_redirect()
            if response is not None:
                return response
            return view_func(*args, **kwargs)
        return decorated

    def flow_for_request(self):
        """
        Build a flow with the correct absolute callback URL for this request.
        :return:
        """
        flow = copy(self.flow)
        flow.redirect_uri = url_for('oidc_callback', _external=True)
        return flow

    def redirect_to_auth_server(self, destination):
        """
        Set a CSRF token in the session, and redirect to the IdP.
        :param destination: the page that the user was going to,
                            before we noticed they weren't logged in
        :return: a redirect response
        """
        csrf_token = b64encode(self.urandom(24)).decode('utf-8')
        session['oidc_csrf_token'] = csrf_token
        state = {
            'csrf_token': csrf_token,
            'destination': destination,
        }
        extra_params = {
            'state': json.dumps(state),
        }
        flow = self.flow_for_request()
        auth_url = '{url}&{extra_params}'.format(
            url=flow.step1_get_authorize_url(),
            extra_params=urlencode(extra_params))
        # if the user has an ID token, it's invalid, or we wouldn't be here
        self.set_cookie_id_token(None)
        return redirect(auth_url)

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
        if 'azp' in id_token and id_token['azp'] != self.flow.client_id:
            return False

        # steps 9, 10
        if not (id_token['iat'] <= self.time() < id_token['exp']):
            return False

        # (not required if using HTTPS?) step 11: check nonce

        # additional steps specific to our usage

        if id_token.get('hd') != self.google_apps_domain:
            return False

        if not id_token['email_verified']:
            return False

        return True

    WRONG_GOOGLE_APPS_DOMAIN = 'WRONG_GOOGLE_APPS_DOMAIN'

    def oidc_callback(self):
        """
        Exchange the auth code for actual credentials,
        then redirect to the originally requested page.
        """
        # retrieve session and callback variables
        try:
            session_csrf_token = session.pop('oidc_csrf_token')

            state = json.loads(request.args['state'])
            csrf_token = state['csrf_token']
            destination = state['destination']

            code = request.args['code']
        except (KeyError, ValueError):
            logger.debug("Can't retrieve CSRF token, state, or code",
                         exc_info=True)
            return self.oidc_error()

        # check callback CSRF token passed to IdP
        # against session CSRF token held by user
        if csrf_token != session_csrf_token:
            logger.debug("CSRF token mismatch")
            return self.oidc_error()

        # make a request to IdP to exchange the auth code for OAuth credentials
        flow = self.flow_for_request()
        credentials = flow.step2_exchange(code, http=self.http)
        id_token = credentials.id_token
        if not self.is_id_token_valid(id_token):
            logger.debug("Invalid ID token")
            if id_token.get('hd') != self.google_apps_domain:
                return self.oidc_error(
                    "You must log in with an account from the {0} domain."
                    .format(self.google_apps_domain),
                    self.WRONG_GOOGLE_APPS_DOMAIN)
            return self.oidc_error()

        # store credentials by subject
        # when Google is the IdP, the subject is their G+ account number
        self.credentials_store[id_token['sub']] = credentials

        # set a persistent signed cookie containing the ID token
        # and redirect to the final destination
        # TODO: validate redirect destination
        response = redirect(destination)
        self.set_cookie_id_token(id_token)
        return response

    def oidc_error(self, message='Not Authorized', code=None):
        return (message, 401, {
            'Content-Type': 'text/plain',
        })
