from pkg_resources import resource_filename, resource_stream
from urlparse import urlsplit, parse_qs
from urllib import urlencode
import json
from base64 import urlsafe_b64encode

from .app import create_app


with resource_stream(__name__, 'client_secrets.json') as f:
    client_secrets = json.load(f)


def mock_time():
    return 2


class MockHttpResponse(object):
    status = 200


class MockHttp(object):
    @staticmethod
    def request(*_, **__):
        return MockHttpResponse(), json.dumps({
            'access_token': 'mock_access_token',
            'id_token': '.{}.'.format(urlsafe_b64encode(json.dumps({
                'aud': client_secrets['web']['client_id'],
                'sub': 'mock_user_id',
                'email_verified': True,
                'iat': mock_time() - 1,
                'exp': mock_time() + 1,
            }))),
        })


app = create_app({
    'SECRET_KEY': 'SEEEKRIT',
    'TESTING': True,
    'OIDC_CLIENT_SECRETS': resource_filename(__name__, 'client_secrets.json'),
}, {
    'http': MockHttp(),
    'time': mock_time,
})

test_client = app.test_client()


def test_signin():
    # make an unauthenticated request, which should result in a redirect to the IdP
    r1 = test_client.get('/')
    assert r1.status_code == 302,\
        "Expected redirect to IdP (response status was {response.status})".format(response=r1)

    # fake a callback from the IdP with an auth code
    r1location = urlsplit(r1.headers['Location'])
    query = parse_qs(r1location.query)
    state = query['state'][0]

    # the app should now contact the IdP to exchange that auth code for credentials
    r2 = test_client.get('/oidc_callback?' + urlencode({'state': state, 'code': 'mock_auth_code'}))
    assert r2.status_code == 302,\
        "Expected redirect to destination (response status was {response.status})".format(response=r2)
    r2location = urlsplit(r2.headers['Location'])
    assert r2location.path == '/',\
        "Expected redirect to destination (unexpected path {location.path})".format(location=r2location)
