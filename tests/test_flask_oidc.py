from pkg_resources import resource_filename, resource_stream
from urlparse import urlsplit, parse_qs
from urllib import urlencode
import json
from base64 import urlsafe_b64encode

from nose.tools import nottest

from .app import create_app


with resource_stream(__name__, 'client_secrets.json') as f:
    client_secrets = json.load(f)


class Clock(object):
    """
    Mock time source.
    """
    def __init__(self, now):
        self.now = now

    def time(self):
        return self.now


class MockHttpResponse(object):
    status = 200


class MockHttp(object):
    """
    Mock httplib2 client.
    Assumes all requests are auth code exchanges that return OAuth access/ID tokens.
    """
    def __init__(self, iat, exp):
        self.iat = iat
        self.exp = exp
        self.last_request = {}

    def request(self, path, **kwargs):
        self.last_request = kwargs
        self.last_request['path'] = path
        return MockHttpResponse(), json.dumps({
            'access_token': 'mock_access_token',
            'refresh_token': 'mock_refresh_token',
            'id_token': '.{}.'.format(urlsafe_b64encode(json.dumps({
                'aud': client_secrets['web']['client_id'],
                'sub': 'mock_user_id',
                'email_verified': True,
                'iat': self.iat,
                'exp': self.exp,
            }))),
        })


@nottest
def make_test_client():
    """
    :return: A Flask test client for the test app, and the mocks it uses.
    """
    clock = Clock(now=2)

    http = MockHttp(iat=clock.now - 1, exp=clock.now + 1)

    app = create_app({
        'SECRET_KEY': 'SEEEKRIT',
        'TESTING': True,
        'OIDC_CLIENT_SECRETS': resource_filename(__name__, 'client_secrets.json'),
    }, {
        'http': http,
        'time': clock.time,
    })
    test_client = app.test_client()

    return test_client, http, clock


def callback_url_for(response):
    """
    Take a redirect to the IdP and turn it into a redirect from the IdP.
    :return: The URL that the IdP would have redirected the user to.
    """
    location = urlsplit(response.headers['Location'])
    query = parse_qs(location.query)
    state = query['state'][0]
    callback_url = '/oidc_callback?' + urlencode({'state': state, 'code': 'mock_auth_code'})
    return callback_url


def test_signin():
    """
    Happy path authentication test.
    """
    test_client, _, _ = make_test_client()

    # make an unauthenticated request, which should result in a redirect to the IdP
    r1 = test_client.get('/')
    assert r1.status_code == 302,\
        "Expected redirect to IdP (response status was {response.status})".format(response=r1)

    # the app should now contact the IdP to exchange that auth code for credentials
    r2 = test_client.get(callback_url_for(r1))
    assert r2.status_code == 302,\
        "Expected redirect to destination (response status was {response.status})".format(response=r2)
    r2location = urlsplit(r2.headers['Location'])
    assert r2location.path == '/',\
        "Expected redirect to destination (unexpected path {location.path})".format(location=r2location)


def test_refresh():
    """
    Test token expiration and refresh.
    """
    test_client, http, clock = make_test_client()

    # authenticate and get an ID token cookie
    auth_redirect = test_client.get('/')
    callback_redirect = test_client.get(callback_url_for(auth_redirect))
    actual_page = test_client.get(callback_redirect.headers['Location'])
    assert ''.join(actual_page.response) == 'too many secrets', "Authentication failed"

    # expire the ID token cookie
    clock.now = 5

    # app should now try to use the refresh token
    test_client.get('/')
    body = parse_qs(http.last_request['body'])
    assert body.get('refresh_token') == ['mock_refresh_token'], "App should have tried to refresh credentials"
