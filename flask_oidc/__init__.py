# Copyright (c) 2014-2015, Jeremy Ehrhardt <jeremy@bat-country.us>
# Copyright (c) 2016, Patrick Uiterwijk <patrick@puiterwijk.org>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from functools import wraps
import os
import json
from base64 import b64encode, urlsafe_b64encode, urlsafe_b64decode
import time
from copy import copy
import logging
from warnings import warn
import calendar

from six.moves.urllib.parse import urlencode
from flask import request, session, redirect, url_for, g, current_app
from oauth2client.client import flow_from_clientsecrets, OAuth2WebServerFlow,\
    AccessTokenRefreshError, OAuth2Credentials
import httplib2
from itsdangerous import JSONWebSignatureSerializer, BadSignature, \
    TimedJSONWebSignatureSerializer, SignatureExpired

__all__ = ['OpenIDConnect', 'MemoryCredentials']

logger = logging.getLogger(__name__)


def _json_loads(content):
    if not isinstance(content, str):
        content = content.decode('utf-8')
    return json.loads(content)

class MemoryCredentials(dict):
    """
    Non-persistent local credentials store.
    Use this if you only have one app server, and don't mind making everyone
    log in again after a restart.
    """
    pass


class DummySecretsCache(object):
    """
    oauth2client secrets cache
    """
    def __init__(self, client_secrets):
        self.client_secrets = client_secrets

    def get(self, filename, namespace):
        return self.client_secrets


class ErrStr(str):
    """
    This is a class to work around the time I made a terrible API decision.

    Basically, the validate_token() function returns a boolean True if all went
    right, but a string with an error message if something went wrong.

    The problem here is that this means that "if validate_token(...)" will
    always be True, even with an invalid token, and users had to do
    "if validate_token(...) is True:".

    This is counter-intuitive, so let's "fix" this by returning instances of
    this ErrStr class, which are basic strings except for their bool() results:
    they return False.
    """
    def __nonzero__(self):
        """The py2 method for bool()."""
        return False

    def __bool__(self):
        """The py3 method for bool()."""
        return False


GOOGLE_ISSUERS = ['accounts.google.com', 'https://accounts.google.com']


class OpenIDConnect(object):
    """
    The core OpenID Connect client object.
    """
    def __init__(self, app=None, credentials_store=None, http=None, time=None,
                 urandom=None):
        self.credentials_store = credentials_store\
            if credentials_store is not None\
            else MemoryCredentials()

        if http is not None:
            warn('HTTP argument is deprecated and unused', DeprecationWarning)
        if time is not None:
            warn('time argument is deprecated and unused', DeprecationWarning)
        if urandom is not None:
            warn('urandom argument is deprecated and unused',
                 DeprecationWarning)

        # By default, we do not have a custom callback
        self._custom_callback = None

        # get stuff from the app's config, which may override stuff set above
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """
        Do setup that requires a Flask app.

        :param app: The application to initialize.
        :type app: Flask
        """
        secrets = self.load_secrets(app)
        self.client_secrets = list(secrets.values())[0]
        secrets_cache = DummySecretsCache(secrets)

        # Set some default configuration options
        app.config.setdefault('OIDC_SCOPES', ['openid', 'email'])
        app.config.setdefault('OIDC_GOOGLE_APPS_DOMAIN', None)
        app.config.setdefault('OIDC_ID_TOKEN_COOKIE_NAME', 'oidc_id_token')
        app.config.setdefault('OIDC_ID_TOKEN_COOKIE_PATH', '/')
        app.config.setdefault('OIDC_ID_TOKEN_COOKIE_TTL', 7 * 86400)  # 7 days
        # should ONLY be turned off for local debugging
        app.config.setdefault('OIDC_COOKIE_SECURE', True)
        app.config.setdefault('OIDC_VALID_ISSUERS',
                              (self.client_secrets.get('issuer') or
                               GOOGLE_ISSUERS))
        app.config.setdefault('OIDC_CLOCK_SKEW', 60)  # 1 minute
        app.config.setdefault('OIDC_REQUIRE_VERIFIED_EMAIL', False)
        app.config.setdefault('OIDC_OPENID_REALM', None)
        app.config.setdefault('OIDC_USER_INFO_ENABLED', True)
        app.config.setdefault('OIDC_CALLBACK_ROUTE', '/oidc_callback')
        app.config.setdefault('OVERWRITE_REDIRECT_URI', False)
        # Configuration for resource servers
        app.config.setdefault('OIDC_RESOURCE_SERVER_ONLY', False)
        app.config.setdefault('OIDC_RESOURCE_CHECK_AUD', False)

        # We use client_secret_post, because that's what the Google
        # oauth2client library defaults to
        app.config.setdefault('OIDC_INTROSPECTION_AUTH_METHOD', 'client_secret_post')
        app.config.setdefault('OIDC_TOKEN_TYPE_HINT', 'access_token')

        if not 'openid' in app.config['OIDC_SCOPES']:
            raise ValueError('The value "openid" must be in the OIDC_SCOPES')

        # register callback route and cookie-setting decorator
        if not app.config['OIDC_RESOURCE_SERVER_ONLY']:
            app.route(app.config['OIDC_CALLBACK_ROUTE'])(self._oidc_callback)
            app.before_request(self._before_request)
            app.after_request(self._after_request)

        # Initialize oauth2client
        self.flow = flow_from_clientsecrets(
            app.config['OIDC_CLIENT_SECRETS'],
            scope=app.config['OIDC_SCOPES'],
            cache=secrets_cache)
        assert isinstance(self.flow, OAuth2WebServerFlow)

        # create signers using the Flask secret key
        self.extra_data_serializer = JSONWebSignatureSerializer(
            app.config['SECRET_KEY'])
        self.cookie_serializer = TimedJSONWebSignatureSerializer(
            app.config['SECRET_KEY'])

        try:
            self.credentials_store = app.config['OIDC_CREDENTIALS_STORE']
        except KeyError:
            pass

    def load_secrets(self, app):
        # Load client_secrets.json to pre-initialize some configuration
        return _json_loads(open(app.config['OIDC_CLIENT_SECRETS'],
                                   'r').read())
        
    @property
    def user_loggedin(self):
        """
        Represents whether the user is currently logged in.

        Returns:
            bool: Whether the user is logged in with Flask-OIDC.

        .. versionadded:: 1.0
        """
        return g.oidc_id_token is not None

    def user_getfield(self, field, access_token=None):
        """
        Request a single field of information about the user.

        :param field: The name of the field requested.
        :type field: str
        :returns: The value of the field. Depending on the type, this may be
            a string, list, dict, or something else.
        :rtype: object

        .. versionadded:: 1.0
        """
        info = self.user_getinfo([field], access_token)
        return info.get(field)

    def user_getinfo(self, fields, access_token=None):
        """
        Request multiple fields of information about the user.

        :param fields: The names of the fields requested.
        :type fields: list
        :returns: The values of the current user for the fields requested.
            The keys are the field names, values are the values of the
            fields as indicated by the OpenID Provider. Note that fields
            that were not provided by the Provider are absent.
        :rtype: dict
        :raises Exception: If the user was not authenticated. Check this with
            user_loggedin.

        .. versionadded:: 1.0
        """
        if g.oidc_id_token is None and access_token is None:
            raise Exception('User was not authenticated')
        info = {}
        all_info = None
        for field in fields:
            if access_token is None and field in g.oidc_id_token:
                info[field] = g.oidc_id_token[field]
            elif current_app.config['OIDC_USER_INFO_ENABLED']:
                # This was not in the id_token. Let's get user information
                if all_info is None:
                    all_info = self._retrieve_userinfo(access_token)
                    if all_info is None:
                        # To make sure we don't retry for every field
                        all_info = {}
                if field in all_info:
                    info[field] = all_info[field]
                else:
                    # We didn't get this information
                    pass
        return info

    def get_access_token(self):
        """Method to return the current requests' access_token.

        :returns: Access token or None
        :rtype: str

        .. versionadded:: 1.2
        """
        try:
            credentials = OAuth2Credentials.from_json(
                self.credentials_store[g.oidc_id_token['sub']])
            return credentials.access_token
        except KeyError:
            logger.debug("Expired ID token, credentials missing",
                         exc_info=True)
            return None

    def get_refresh_token(self):
        """Method to return the current requests' refresh_token.

        :returns: Access token or None
        :rtype: str

        .. versionadded:: 1.2
        """
        try:
            credentials = OAuth2Credentials.from_json(
                self.credentials_store[g.oidc_id_token['sub']])
            return credentials.refresh_token
        except KeyError:
            logger.debug("Expired ID token, credentials missing",
                         exc_info=True)
            return None

    def _retrieve_userinfo(self, access_token=None):
        """
        Requests extra user information from the Provider's UserInfo and
        returns the result.

        :returns: The contents of the UserInfo endpoint.
        :rtype: dict
        """
        if 'userinfo_uri' not in self.client_secrets:
            logger.debug('Userinfo uri not specified')
            raise AssertionError('UserInfo URI not specified')

        # Cache the info from this request
        if '_oidc_userinfo' in g:
            return g._oidc_userinfo

        http = httplib2.Http()
        if access_token is None:
            try:
                credentials = OAuth2Credentials.from_json(
                    self.credentials_store[g.oidc_id_token['sub']])
            except KeyError:
                logger.debug("Expired ID token, credentials missing",
                             exc_info=True)
                return None
            credentials.authorize(http)
            resp, content = http.request(self.client_secrets['userinfo_uri'])
        else:
            # We have been manually overriden with an access token
            resp, content = http.request(
                self.client_secrets['userinfo_uri'],
                "POST",
                body=urlencode({"access_token": access_token}),
                headers={'Content-Type': 'application/x-www-form-urlencoded'})

        logger.debug('Retrieved user info: %s' % content)
        info = _json_loads(content)

        g._oidc_userinfo = info

        return info


    def get_cookie_id_token(self):
        """
        .. deprecated:: 1.0
           Use :func:`user_getinfo` instead.
        """
        warn('You are using a deprecated function (get_cookie_id_token). '
             'Please reconsider using this', DeprecationWarning)
        return self._get_cookie_id_token()

    def _get_cookie_id_token(self):
        try:
            id_token_cookie = request.cookies.get(current_app.config[
                'OIDC_ID_TOKEN_COOKIE_NAME'])
            if not id_token_cookie:
                # Do not error if we were unable to get the cookie.
                # The user can debug this themselves.
                return None
            return self.cookie_serializer.loads(id_token_cookie)
        except SignatureExpired:
            logger.debug("Invalid ID token cookie", exc_info=True)
            return None

    def set_cookie_id_token(self, id_token):
        """
        .. deprecated:: 1.0
        """
        warn('You are using a deprecated function (set_cookie_id_token). '
             'Please reconsider using this', DeprecationWarning)
        return self._set_cookie_id_token(id_token)

    def _set_cookie_id_token(self, id_token):
        """
        Cooperates with @after_request to set a new ID token cookie.
        """
        g.oidc_id_token = id_token
        g.oidc_id_token_dirty = True

    def _after_request(self, response):
        """
        Set a new ID token cookie if the ID token has changed.
        """
        # This means that if either the new or the old are False, we set
        # insecure cookies.
        # We don't define OIDC_ID_TOKEN_COOKIE_SECURE in init_app, because we
        # don't want people to find it easily.
        cookie_secure = (current_app.config['OIDC_COOKIE_SECURE'] and
                         current_app.config.get('OIDC_ID_TOKEN_COOKIE_SECURE',
                                                True))

        if getattr(g, 'oidc_id_token_dirty', False):
            if g.oidc_id_token:
                signed_id_token = self.cookie_serializer.dumps(g.oidc_id_token)
                response.set_cookie(
                    current_app.config['OIDC_ID_TOKEN_COOKIE_NAME'],
                    signed_id_token,
                    secure=cookie_secure,
                    httponly=True,
                    max_age=current_app.config['OIDC_ID_TOKEN_COOKIE_TTL'])
            else:
                # This was a log out
                response.set_cookie(
                    current_app.config['OIDC_ID_TOKEN_COOKIE_NAME'],
                    '',
                    path=current_app.config['OIDC_ID_TOKEN_COOKIE_PATH'],
                    secure=cookie_secure,
                    httponly=True,
                    expires=0)
        return response

    def _before_request(self):
        g.oidc_id_token = None
        self.authenticate_or_redirect()

    def authenticate_or_redirect(self):
        """
        Helper function suitable for @app.before_request and @check.
        Sets g.oidc_id_token to the ID token if the user has successfully
        authenticated, else returns a redirect object so they can go try
        to authenticate.

        :returns: A redirect object, or None if the user is logged in.
        :rtype: Redirect

        .. deprecated:: 1.0
           Use :func:`require_login` instead.
        """
        # the auth callback and error pages don't need user to be authenticated
        if request.endpoint in frozenset(['_oidc_callback', '_oidc_error']):
            return None

        # retrieve signed ID token cookie
        id_token = self._get_cookie_id_token()
        if id_token is None:
            return self.redirect_to_auth_server(request.url)

        # ID token expired
        # when Google is the IdP, this happens after one hour
        if time.time() >= id_token['exp']:
            # get credentials from store
            try:
                credentials = OAuth2Credentials.from_json(
                    self.credentials_store[id_token['sub']])
            except KeyError:
                logger.debug("Expired ID token, credentials missing",
                             exc_info=True)
                return self.redirect_to_auth_server(request.url)

            # refresh and store credentials
            try:
                credentials.refresh(httplib2.Http())
                if credentials.id_token:
                    id_token = credentials.id_token
                else:
                    # It is not guaranteed that we will get a new ID Token on
                    # refresh, so if we do not, let's just update the id token
                    # expiry field and reuse the existing ID Token.
                    if credentials.token_expiry is None:
                        logger.debug('Expired ID token, no new expiry. Falling'
                                     ' back to assuming 1 hour')
                        id_token['exp'] = time.time() + 3600
                    else:
                        id_token['exp'] = calendar.timegm(
                            credentials.token_expiry.timetuple())
                self.credentials_store[id_token['sub']] = credentials.to_json()
                self._set_cookie_id_token(id_token)
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

    def require_login(self, view_func):
        """
        Use this to decorate view functions that require a user to be logged
        in. If the user is not already logged in, they will be sent to the
        Provider to log in, after which they will be returned.

        .. versionadded:: 1.0
           This was :func:`check` before.
        """
        @wraps(view_func)
        def decorated(*args, **kwargs):
            if g.oidc_id_token is None:
                return self.redirect_to_auth_server(request.url)
            return view_func(*args, **kwargs)
        return decorated
    # Backwards compatibility
    check = require_login
    """
    .. deprecated:: 1.0
       Use :func:`require_login` instead.
    """

    def flow_for_request(self):
        """
        .. deprecated:: 1.0
           Use :func:`require_login` instead.
        """
        warn('You are using a deprecated function (flow_for_request). '
             'Please reconsider using this', DeprecationWarning)
        return self._flow_for_request()

    def _flow_for_request(self):
        """
        Build a flow with the correct absolute callback URL for this request.
        :return:
        """
        flow = copy(self.flow)
        redirect_uri = current_app.config['OVERWRITE_REDIRECT_URI']
        if not redirect_uri:
            flow.redirect_uri = url_for('_oidc_callback', _external=True)
        else:
            flow.redirect_uri = redirect_uri
        return flow

    def redirect_to_auth_server(self, destination=None, customstate=None):
        """
        Set a CSRF token in the session, and redirect to the IdP.

        :param destination: The page that the user was going to,
            before we noticed they weren't logged in.
        :type destination: Url to return the client to if a custom handler is
            not used. Not available with custom callback.
        :param customstate: The custom data passed via the ODIC state.
            Note that this only works with a custom_callback, and this will
            ignore destination.
        :type customstate: Anything that can be serialized
        :returns: A redirect response to start the login process.
        :rtype: Flask Response

        .. deprecated:: 1.0
           Use :func:`require_login` instead.
        """
        if not self._custom_callback and customstate:
            raise ValueError('Custom State is only avilable with a custom '
                             'handler')
        if 'oidc_csrf_token' not in session:
            csrf_token = urlsafe_b64encode(os.urandom(24)).decode('utf-8')
            session['oidc_csrf_token'] = csrf_token
        state = {
            'csrf_token': session['oidc_csrf_token'],
        }
        statefield = 'destination'
        statevalue = destination
        if customstate is not None:
            statefield = 'custom'
            statevalue = customstate
        state[statefield] = self.extra_data_serializer.dumps(
            statevalue).decode('utf-8')

        extra_params = {
            'state': urlsafe_b64encode(json.dumps(state).encode('utf-8')),
        }
        if current_app.config['OIDC_GOOGLE_APPS_DOMAIN']:
            extra_params['hd'] = current_app.config['OIDC_GOOGLE_APPS_DOMAIN']
        if current_app.config['OIDC_OPENID_REALM']:
            extra_params['openid.realm'] = current_app.config[
                'OIDC_OPENID_REALM']

        flow = self._flow_for_request()
        auth_url = '{url}&{extra_params}'.format(
            url=flow.step1_get_authorize_url(),
            extra_params=urlencode(extra_params))
        # if the user has an ID token, it's invalid, or we wouldn't be here
        self._set_cookie_id_token(None)
        return redirect(auth_url)

    def _is_id_token_valid(self, id_token):
        """
        Check if `id_token` is a current ID token for this application,
        was issued by the Apps domain we expected,
        and that the email address has been verified.

        @see: http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
        """
        if not id_token:
            return False

        # step 2: check issuer
        if id_token['iss'] not in current_app.config['OIDC_VALID_ISSUERS']:
            logger.error('id_token issued by non-trusted issuer: %s'
                         % id_token['iss'])
            return False

        if isinstance(id_token['aud'], list):
            # step 3 for audience list
            if self.flow.client_id not in id_token['aud']:
                logger.error('We are not a valid audience')
                return False
            # step 4
            if 'azp' not in id_token:
                logger.error('Multiple audiences and not authorized party')
                return False
        else:
            # step 3 for single audience
            if id_token['aud'] != self.flow.client_id:
                logger.error('We are not the audience')
                return False

        # step 5
        if 'azp' in id_token and id_token['azp'] != self.flow.client_id:
            logger.error('Authorized Party is not us')
            return False

        # step 6-8: TLS checked

        # step 9: check exp
        if int(time.time()) >= int(id_token['exp']):
            logger.error('Token has expired')
            return False

        # step 10: check iat
        if id_token['iat'] < (time.time() -
                              current_app.config['OIDC_CLOCK_SKEW']):
            logger.error('Token issued in the past')
            return False

        # (not required if using HTTPS?) step 11: check nonce

        # step 12-13: not requested acr or auth_time, so not needed to test

        # additional steps specific to our usage
        if current_app.config['OIDC_GOOGLE_APPS_DOMAIN'] and \
                id_token.get('hd') != current_app.config[
                    'OIDC_GOOGLE_APPS_DOMAIN']:
            logger.error('Invalid google apps domain')
            return False

        if not id_token.get('email_verified', False) and \
                current_app.config['OIDC_REQUIRE_VERIFIED_EMAIL']:
            logger.error('Email not verified')
            return False

        return True

    WRONG_GOOGLE_APPS_DOMAIN = 'WRONG_GOOGLE_APPS_DOMAIN'

    def custom_callback(self, view_func):
        """
        Wrapper function to use a custom callback.
        The custom OIDC callback will get the custom state field passed in with
        redirect_to_auth_server.
        """
        @wraps(view_func)
        def decorated(*args, **kwargs):
            plainreturn, data = self._process_callback('custom')
            if plainreturn:
                return data
            else:
                return view_func(data, *args, **kwargs)
        self._custom_callback = decorated
        return decorated

    def _oidc_callback(self):
        plainreturn, data = self._process_callback('destination')
        if plainreturn:
            return data
        else:
            return redirect(data)

    def _process_callback(self, statefield):
        """
        Exchange the auth code for actual credentials,
        then redirect to the originally requested page.
        """
        # retrieve session and callback variables
        try:
            session_csrf_token = session.get('oidc_csrf_token')

            state = _json_loads(urlsafe_b64decode(request.args['state'].encode('utf-8')))
            csrf_token = state['csrf_token']

            code = request.args['code']
        except (KeyError, ValueError):
            logger.debug("Can't retrieve CSRF token, state, or code",
                         exc_info=True)
            return True, self._oidc_error()

        # check callback CSRF token passed to IdP
        # against session CSRF token held by user
        if csrf_token != session_csrf_token:
            logger.debug("CSRF token mismatch")
            return True, self._oidc_error()

        # make a request to IdP to exchange the auth code for OAuth credentials
        flow = self._flow_for_request()
        credentials = flow.step2_exchange(code)
        id_token = credentials.id_token
        if not self._is_id_token_valid(id_token):
            logger.debug("Invalid ID token")
            if id_token.get('hd') != current_app.config[
                    'OIDC_GOOGLE_APPS_DOMAIN']:
                return True, self._oidc_error(
                    "You must log in with an account from the {0} domain."
                    .format(current_app.config['OIDC_GOOGLE_APPS_DOMAIN']),
                    self.WRONG_GOOGLE_APPS_DOMAIN)
            return True, self._oidc_error()

        # store credentials by subject
        # when Google is the IdP, the subject is their G+ account number
        self.credentials_store[id_token['sub']] = credentials.to_json()

        # Retrieve the extra statefield data
        try:
            response = self.extra_data_serializer.loads(state[statefield])
        except BadSignature:
            logger.error('State field was invalid')
            return True, self._oidc_error()

        # set a persistent signed cookie containing the ID token
        # and redirect to the final destination
        self._set_cookie_id_token(id_token)
        return False, response

    def _oidc_error(self, message='Not Authorized', code=None):
        return (message, 401, {
            'Content-Type': 'text/plain',
        })

    def logout(self):
        """
        Request the browser to please forget the cookie we set, to clear the
        current session.

        Note that as described in [1], this will not log out in the case of a
        browser that doesn't clear cookies when requested to, and the user
        could be automatically logged in when they hit any authenticated
        endpoint.

        [1]: https://github.com/puiterwijk/flask-oidc/issues/5#issuecomment-86187023

        .. versionadded:: 1.0
        """
        # TODO: Add single logout
        self._set_cookie_id_token(None)

    # Below here is for resource servers to validate tokens
    def validate_token(self, token, scopes_required=None):
        """
        This function can be used to validate tokens.

        Note that this only works if a token introspection url is configured,
        as that URL will be queried for the validity and scopes of a token.

        :param scopes_required: List of scopes that are required to be
            granted by the token before returning True.
        :type scopes_required: list

        :returns: True if the token was valid and contained the required
            scopes. An ErrStr (subclass of string for which bool() is False) if
            an error occured.
        :rtype: Boolean or String

        .. versionadded:: 1.1
        """
        valid = self._validate_token(token, scopes_required)
        if valid is True:
            return True
        else:
            return ErrStr(valid)

    def _validate_token(self, token, scopes_required=None):
        """The actual implementation of validate_token."""
        if scopes_required is None:
            scopes_required = []
        scopes_required = set(scopes_required)

        token_info = None
        valid_token = False
        has_required_scopes = False
        if token:
            try:
                token_info = self._get_token_info(token)
            except Exception as ex:
                token_info = {'active': False}
                logger.error('ERROR: Unable to get token info')
                logger.error(str(ex))

            valid_token = token_info.get('active', False)

            if 'aud' in token_info and \
                    current_app.config['OIDC_RESOURCE_CHECK_AUD']:
                valid_audience = False
                aud = token_info['aud']
                clid = self.client_secrets['client_id']
                if isinstance(aud, list):
                    valid_audience = clid in aud
                else:
                    valid_audience = clid == aud

                if not valid_audience:
                    logger.error('Refused token because of invalid '
                                 'audience')
                    valid_token = False

            if valid_token:
                token_scopes = token_info.get('scope', '').split(' ')
            else:
                token_scopes = []
            has_required_scopes = scopes_required.issubset(
                set(token_scopes))

            if not has_required_scopes:
                logger.debug('Token missed required scopes')

        if (valid_token and has_required_scopes):
            g.oidc_token_info = token_info
            return True

        if not valid_token:
            return 'Token required but invalid'
        elif not has_required_scopes:
            return 'Token does not have required scopes'
        else:
            return 'Something went wrong checking your token'

    def accept_token(self, require_token=False, scopes_required=None,
                           render_errors=True):
        """
        Use this to decorate view functions that should accept OAuth2 tokens,
        this will most likely apply to API functions.

        Tokens are accepted as part of the query URL (access_token value) or
        a POST form value (access_token).

        Note that this only works if a token introspection url is configured,
        as that URL will be queried for the validity and scopes of a token.

        :param require_token: Whether a token is required for the current
            function. If this is True, we will abort the request if there
            was no token provided.
        :type require_token: bool
        :param scopes_required: List of scopes that are required to be
            granted by the token before being allowed to call the protected
            function.
        :type scopes_required: list
        :param render_errors: Whether or not to eagerly render error objects
            as JSON API responses. Set to False to pass the error object back
            unmodified for later rendering.
        :type render_errors: callback(obj) or None

        .. versionadded:: 1.0
        """

        def wrapper(view_func):
            @wraps(view_func)
            def decorated(*args, **kwargs):
                token = None
                if 'Authorization' in request.headers and request.headers['Authorization'].startswith('Bearer '):
                    token = request.headers['Authorization'].split(None,1)[1].strip()
                if 'access_token' in request.form:
                    token = request.form['access_token']
                elif 'access_token' in request.args:
                    token = request.args['access_token']

                validity = self.validate_token(token, scopes_required)
                if (validity is True) or (not require_token):
                    return view_func(*args, **kwargs)
                else:
                    response_body = {'error': 'invalid_token',
                                     'error_description': validity}
                    if render_errors:
                        response_body = json.dumps(response_body)
                    return response_body, 401, {'WWW-Authenticate': 'Bearer'}

            return decorated
        return wrapper

    def _get_token_info(self, token):
        # We hardcode to use client_secret_post, because that's what the Google
        # oauth2client library defaults to
        request = {'token': token}
        headers = {'Content-type': 'application/x-www-form-urlencoded'}

        hint = current_app.config['OIDC_TOKEN_TYPE_HINT']
        if hint != 'none':
            request['token_type_hint'] = hint

        auth_method = current_app.config['OIDC_INTROSPECTION_AUTH_METHOD'] 
        if (auth_method == 'client_secret_basic'):
            basic_auth_string = '%s:%s' % (self.client_secrets['client_id'], self.client_secrets['client_secret'])
            basic_auth_bytes = bytearray(basic_auth_string, 'utf-8')
            headers['Authorization'] = 'Basic %s' % b64encode(basic_auth_bytes)
        elif (auth_method == 'bearer'):
            headers['Authorization'] = 'Bearer %s' % token
        elif (auth_method == 'client_secret_post'):
            request['client_id'] = self.client_secrets['client_id']
            request['client_secret'] = self.client_secrets['client_secret']

        resp, content = httplib2.Http().request(
            self.client_secrets['token_introspection_uri'], 'POST',
            urlencode(request), headers=headers)
        # TODO: Cache this reply
        return _json_loads(content)
