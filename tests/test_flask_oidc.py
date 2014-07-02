from pkg_resources import resource_filename

from .app import create_app

app = create_app({
    'SECRET_KEY': 'SEEEKRIT',
    'TESTING': True,
    'SERVER_NAME': 'localhost:5000',
    'OIDC_CLIENT_SECRETS': resource_filename(__name__, 'client_secrets.json'),
})

test_client = app.test_client()


def test_not_signed_in():
    response = test_client.get('/')
    assert response.status_code == 302,\
        "Expected redirect to IdP (response status was {response.status})".format(response=response)
