from pkg_resources import resource_filename, resource_stream
import json
import time
import codecs
from base64 import urlsafe_b64encode
try:
    from unittest.mock import Mock, patch
except ImportError:
    from mock import Mock, patch

from six.moves.urllib.parse import urlsplit, parse_qs, urlencode
from nose.tools import nottest

from .app import create_app, create_jwt_auth_app


last_request = None
with resource_stream(__name__, 'client_secrets.json') as f:
    client_secrets = json.load(codecs.getreader('utf-8')(f))


class MockHttpResponse(object):
    status = 200


class MockHttp(object):
    def request(self, path, method='GET', post_string='', **kwargs):
        global last_request
        last_request = kwargs
        last_request['path'] = path
        iat = time.time() - 1
        exp = time.time() + 1
        post_args = {}
        if method == 'POST':
            post_args = parse_qs(post_string)

        if path == 'https://test/token':
            return MockHttpResponse(), json.dumps({
                'access_token': 'mock_access_token',
                'refresh_token': 'mock_refresh_token',
                'id_token': '.{0}.'.format(urlsafe_b64encode(json.dumps({
                    'aud': client_secrets['web']['client_id'],
                    'sub': 'mock_user_id',
                    'email_verified': True,
                    'iat': iat,
                    'exp': exp,
                    'iss': 'accounts.google.com',
                }).encode('utf-8')).decode('utf-8')),
            }).encode('utf-8')
        elif path == 'https://test/tokeninfo':
            assert post_args['client_id'] == ['MyClient'], \
                'Client ID is specified'
            req_token = post_args['token'][0]
            token_info = {'active': False}
            if req_token in ['query_token', 'post_token']:
                token_info['active'] = True
                token_info['scope'] = 'openid'
                token_info['sub'] = 'valid_sub'
                token_info['aud'] = 'MyClient'
            elif req_token == 'insufficient_token':
                token_info['active'] = True
                token_info['scope'] = 'email'
                token_info['sub'] = 'valid_sub'
                token_info['aud'] = 'MyClient'
            elif req_token == 'multi_aud_token':
                token_info['active'] = True
                token_info['scope'] = 'openid'
                token_info['sub'] = 'valid_sub'
                token_info['aud'] = ['MyClient', 'TheirClient']
            elif req_token == 'some_elses_token':
                token_info['active'] = True
                token_info['scope'] = 'openid'
                token_info['sub'] = 'valid_sub'
                token_info['aud'] = 'TheirClient'
            return MockHttpResponse(), json.dumps(token_info)
        elif path == 'https://test/jwks':
            # cert data converted from https://jwt.io/#debugger

            cert_value = """MIIC/zCCAeegAwIBAgIBATANBgkqhkiG9w0BAQUFADAaMQswCQYDVQQGEwJVUzELMAkGA1UE
CgwCWjQwHhcNMTMwODI4MTgyODM0WhcNMjMwODI4MTgyODM0WjAaMQswCQYDVQQGEwJVUzEL
MAkGA1UECgwCWjQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDfdOqotHd55SYO
0dLz2oXengw/tZ+q3ZmOPeVmMuOMIYO/Cv1wk2U0OK4pug4OBSJPhl09Zs6IwB8NwPOU7EDT
gMOcQUYB/6QNCI1J7Zm2oLtuchzz4pIb+o4ZAhVprLhRyvqi8OTKQ7kfGfs5Tuwmn1M/0fQk
fzMxADpjOKNgf0uy6lN6utjdTrPKKFUQNdc6/Ty8EeTnQEwUlsT2LAXCfEKxTn5RlRljDztS
7Sfgs8VL0FPy1Qi8B+dFcgRYKFrcpsVaZ1lBmXKsXDRu5QR/Rg3f9DRq4GR1sNH8RLY9uApM
l2SNz+sR4zRPG85R/se5Q06Gu0BUQ3UPm67ETVZLAgMBAAGjUDBOMB0GA1UdDgQWBBQHZPTE
yQVu/0I/3QWhlTyW7WoTzTAfBgNVHSMEGDAWgBQHZPTEyQVu/0I/3QWhlTyW7WoTzTAMBgNV
HRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQDHxqJ9y8alTH7agVMWZfic/RbrdvHwyq+I
OrgDToqyo0w+IZ6BCn9vjv5iuhqu4ForOWDAFpQKZW0DLBJEQy/7/0+9pk2DPhK1XzdOovlS
rkRt+GcEpGnUXnzACXDBbO0+Wrk+hcjEkQRRK1bW2rknARIEJG9GS+pShP9Bq/0BmNsMepdN
cBa0z3a5B0fzFyCQoUlX6RTqxRw1h1Qt5F00pfsp7SjXVIvYcewHaNASbto1n5hrSz1VY9hL
ba11ivL1N4WoWbmzAL6BWabsC2D/MenST2/X6hTKyGXpg3Eg2h3iLvUtwcNny0hRKstc73Jl
9xR3qXfXKJH0ThTlq0gq"""

            return MockHttpResponse(), json.dumps({'keys': [{'kid': '1234', 'kty': 'RSA', 'use':'sig', 'x5c': [cert_value]}]})
        else:
            raise Exception('Non-recognized path %s requested' % path)

class MockTime(Mock):
    def __init__(self, *args, **kwargs):
        Mock.__init__(self, *args, **kwargs)
        from datetime import datetime
        self.return_value = time.mktime(datetime(year=2017, month=5, day=4, hour=11, minute=4, second=0).timetuple())


@nottest
def make_test_client():
    """
    :return: A Flask test client for the test app, and the mocks it uses.
    """
    app = create_app({
        'SECRET_KEY': 'SEEEKRIT',
        'TESTING': True,
        'OIDC_CLIENT_SECRETS': resource_filename(
            __name__, 'client_secrets.json'),
    }, {
    })
    test_client = app.test_client()

    return test_client


def callback_url_for(response):
    """
    Take a redirect to the IdP and turn it into a redirect from the IdP.
    :return: The URL that the IdP would have redirected the user to.
    """
    location = urlsplit(response.headers['Location'])
    query = parse_qs(location.query)
    state = query['state'][0]
    callback_url = '/oidc_callback?'\
                   + urlencode({'state': state, 'code': 'mock_auth_code'})
    return callback_url


@patch('time.time', Mock(return_value=time.time()))
@patch('httplib2.Http', MockHttp)
def test_signin():
    """
    Happy path authentication test.
    """
    test_client = make_test_client()

    # make an unauthenticated request,
    # which should result in a redirect to the IdP
    r1 = test_client.get('/')
    assert r1.status_code == 302,\
        "Expected redirect to IdP "\
        "(response status was {response.status})".format(response=r1)

    # the app should now contact the IdP
    # to exchange that auth code for credentials
    r2 = test_client.get(callback_url_for(r1))
    assert r2.status_code == 302,\
        "Expected redirect to destination "\
        "(response status was {response.status})".format(response=r2)
    r2location = urlsplit(r2.headers['Location'])
    assert r2location.path == '/',\
        "Expected redirect to destination "\
        "(unexpected path {location.path})".format(location=r2location)


@patch('httplib2.Http', MockHttp)
def test_refresh():
    """
    Test token expiration and refresh.
    """
    test_client = make_test_client()

    with patch('time.time', Mock(return_value=time.time())) as time_1:
        # authenticate and get an ID token cookie
        auth_redirect = test_client.get('/')
        callback_redirect = test_client.get(callback_url_for(auth_redirect))
        actual_page = test_client.get(callback_redirect.headers['Location'])
        page_text = ''.join(codecs.iterdecode(actual_page.response, 'utf-8'))
        assert page_text == 'too many secrets', "Authentication failed"

    # app should now try to use the refresh token
    with patch('time.time', Mock(return_value=time.time() + 10)) as time_2:
        test_client.get('/')
        body = parse_qs(last_request['body'])
        assert body.get('refresh_token') == ['mock_refresh_token'],\
            "App should have tried to refresh credentials"


def _check_api_token_handling(api_path):
    """
    Test API token acceptance.
    """
    test_client = make_test_client()

    # Test without a token
    resp = test_client.get(api_path)
    assert resp.status_code == 401, "Token should be required"
    resp = json.loads(resp.get_data().decode('utf-8'))
    assert resp['error'] == 'invalid_token', "Token should be requested"

    # Test with invalid token
    resp = test_client.get(api_path + '?access_token=invalid_token')
    assert resp.status_code == 401, 'Token should be rejected'

    # Test with query token
    resp = test_client.get(api_path + '?access_token=query_token')
    assert resp.status_code == 200, 'Token should be accepted'
    resp = json.loads(resp.get_data().decode('utf-8'))
    assert resp['token']['sub'] == 'valid_sub'

    # Test with post token
    resp = test_client.post(api_path, data={'access_token': 'post_token'})
    assert resp.status_code == 200, 'Token should be accepted'

    # Test with insufficient token
    resp = test_client.post(api_path + '?access_token=insufficient_token')
    assert resp.status_code == 401, 'Token should be refused'
    resp = json.loads(resp.get_data().decode('utf-8'))
    assert resp['error'] == 'invalid_token'

    # Test with multiple audiences
    resp = test_client.get(api_path + '?access_token=multi_aud_token')
    assert resp.status_code == 200, 'Token should be accepted'

    # Test with token for another audience
    resp = test_client.get(api_path + '?access_token=some_elses_token')
    assert resp.status_code == 200, 'Token should be accepted'
    test_client.application.config['OIDC_RESOURCE_CHECK_AUD'] = True
    resp = test_client.get(api_path + '?access_token=some_elses_token')
    assert resp.status_code == 401, 'Token should be refused'

@patch('httplib2.Http', MockHttp)
def test_api_token():
    _check_api_token_handling('/api')

@patch('httplib2.Http', MockHttp)
def test_api_token_with_external_rendering():
    _check_api_token_handling('/external_api')

@patch('httplib2.Http', MockHttp)
@patch('time.time', MockTime())
def test_jwt_signature_check():
    config = {
        'SECRET_KEY': 'SEEEKRIT',
        'TESTING': True,
        'OIDC_TOKEN_VERIFY_METHOD': 'jwt',
        'OIDC_VALID_ISSUERS': 'https://jwt-idp.example.com',
        'OIDC_CLIENT_SECRETS': resource_filename(
            __name__, 'client_secrets.json'),
    }
    app = create_jwt_auth_app(config)
    client = app.test_client()
    # token from http://kjur.github.io/jsjws/tool_jwt.html
    # see also: https://mkjwk.org/
    # token payload:
    # {
    #  "iss": "https://jwt-idp.example.com",
    #  "aud": "MyClient",
    #  "sub": "mailto:mike@example.com",
    #  "nbf": 1493887946,
    #  "exp": 1493891546,
    #  "iat": 1493887946,
    #  "jti": "id123456",
    #  "typ": "https://example.com/register"
    #}
    token = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20iLCJhdWQiOiJNeUNsaWVudCIsInN1YiI6Im1haWx0bzptaWtlQGV4YW1wbGUuY29tIiwibmJmIjoxNDkzODg3OTQ2LCJleHAiOjE0OTM4OTE1NDYsImlhdCI6MTQ5Mzg4Nzk0NiwianRpIjoiaWQxMjM0NTYiLCJ0eXAiOiJodHRwczovL2V4YW1wbGUuY29tL3JlZ2lzdGVyIn0.Vdv14DkUqf5ZW1_LO7wUVloqUBrAXwwNbSUAnCfIeRw7U9QY061fMpcc4XYo9YRC9KCxiqSsLDA5uSZL4r_E8ozCUsVStxugNiZWEA8t5pZ2njaFPqnYDazInjlDvA8IhbgwAG-HMEoVyK0o48FGQ4d--tzzG6W-nXkSd0Tp6lv35_njxblTIyE_z8Hsol-oGNv4PgjjXSksTk5F3G343y_GPAO23e5JTvxlkjgCOAQ-W_mL1Z21zFuPiiwblcK_P7q75ZH7FOlxd4HD-P9WWiWEt6XkeNwGvuV8PPx8PcNhQrsqAKceTE1T1k_Ibzr-4Tyb1taUJZPV1kMd-_-O5g'
    resp = client.get('/jwt_auth', headers={'Authorization': 'Bearer {0}'.format(token)})
    assert resp.status_code == 200, "response code was not 200"
