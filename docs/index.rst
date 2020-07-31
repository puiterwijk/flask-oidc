Flask-OIDC
==========

Flask-OIDC is an extension to `Flask`_ that allows you to add `OpenID Connect`_
based authentication to your website in a matter of minutes. It depends
on Flask and `oauth2client`_. You can install the requirements from
PyPI with `easy_install` or `pip` or download them by hand.


Features
--------

- Support for OpenID Connect 1.0
- Support for OpenID Connect Discovery 1.0
- Support for OpenID Connect Dynamic Registration 1.0
- Friendly API
- Perfect integration into Flask
- Helper functions to allow resource servers to accept OAuth2 tokens


Installation
------------

Install the extension with `pip`::

    $ pip install Flask-OIDC



How to use
----------

To integrate Flask-OpenID into your application you need to create an
instance of the :class:`OpenID` object first::

    from flas_oidc_ext import OpenIDConnect
    oidc = OpenIDConnect(app)


Alternatively the object can be instantiated without the application in
which case it can later be registered for an application with the
:meth:`~flas_oidc_ext.OpenIDConnect.init_app` method.

Note that you should probably provide the library with a place to store the
credentials it has retrieved for the user. These need to be stored in a place
where the user themselves or an attacker can not get to them.
To provide this, give an object that has ``__setitem__`` and ``__getitem__``
dict APIs implemented as second argument to the :meth:`~flas_oidc_ext.OpenIDConnect.__init__`
call.
Without this, the library will only work on a single thread, and only retain
sessions until the server is restarted.

Using this library is very simple: you can use
:data:`~flas_oidc_ext.OpenIDConnect.user_loggedin` to determine whether a user is currently
logged in using OpenID Connect.

If the user is logged in, you an use :meth:`~flas_oidc_ext.OpenIDConnect.user_getfield` and
:meth:`~flas_oidc_ext.OpenIDConnect.user_getinfo` to get information about the currently
logged in user.

If the user is not logged in, you can send them to any function that is
decorated with :meth:`~flas_oidc_ext.OpenIDConnect.require_login` to get them automatically
redirected to login.


Example
-------

A very basic example client::

    @app.route('/')
    def index():
        if oidc.user_loggedin:
            return 'Welcome %s' % oidc.user_getfield('email')
        else:
            return 'Not logged in'

    @app.route('/login')
    @oidc.require_login
    def login():
        return 'Welcome %s' % oidc.user_getfield('email')


Custom callback
---------------

It is possible to override the default OIDC callback to keep track of a custom
state dict through the OIDC authentication steps, which makes it possible to
write stateless apps.
To do this, add the decorator `oidc.custom_callback` to your callback function.
This will get the (json-serializable) custom state that you passed in as
`customstate` to `oidc.redirect_to_auth_server`.
Note that to use this, you will need to set `OVERWRITE_REDIRECT_URI`.

Example::

    @app.route('/')
    def index():
        return oidc.redirect_to_auth_server(None, flask.request.values)

    @app.route('/custom_callback')
    @oidc.custom_callback
    def callback(data):
        return 'Hello. You submitted %s' % data


Resource server
---------------

Also, if you have implemented an API that can should be able to accept tokens
issued by the OpenID Connect provider, just decorate those API functions with
:meth:`~flas_oidc_ext.OpenIDConnect.accept_token`::

    @app.route('/api')
    @oidc.accept_token()
    def my_api():
        return json.dumps('Welcome %s' % g.oidc_token_info['sub'])

If you are only using this part of flask-oidc, it is suggested to set the
configuration option `OIDC_RESOURCE_SERVER_ONLY` (new in 1.0.5).


Registration
------------

To be able to use an OpenID Provider, you will need to register your client
with them.
If the Provider you want to use supports Dynamic Registration, you can execute
``oidc-register https://myprovider.example.com/ https://myapplication.example.com/``
and the full client_secrets.json will be generated for you, and you are ready
to start.

If it does not, please see the documentation of the Provider you want to use
for information on how to obtain client secrets.

For example, for Google, you will need to visit `Google API credentials management
<https://console.developers.google.com/apis/credentials?project=_>`_.

For `MojeID <https://www.mojeid.cz/en/provider/getting-started/>`_, you type ``oidc-register https://mojeid.cz/oidc/ https://your-application``.

Manual client registration
--------------------------

If your identity provider does not offer Dynamic Registration (and you can't
push them to do so, as it would make it a lot simpler!), you might need to know
the following details:

  Grant type
    authorization_code (Authorization Code flow)

  Response type
    Code

  Token endpoint auth metod
    client_secret_post

  Redirect URI
    <APPLICATION_URL>/oidc_callback


You will also need to manually craft your client_secrets.json.
This is just a json document, with everything under a top-level "web" key.
Underneath that top-level key, you have the following keys:

  client_id
    Client ID issued by your IdP

  client_secret
    Client secret belonging to the registered ID

  auth_uri
    The Identity Provider's authorization endpoint url

  token_uri
    The Identity Provider's token endpoint url
    (Optional, used for resource server)

  userinfo_uri
    The Identity Provider's userinfo url

  issuer
    The "issuer" value for the Identity Provider

  redirect_uris
    A list of the registered redirect uris


Settings reference
-------------------

This is a list of all settings supported in the current release.

  OIDC_SCOPES
    A python list with the scopes that should be requested. This impacts the
    information available in the UserInfo field and what the token can be used
    for. Please check your identity provider's documentation for valid values.
    Defaults to ['openid', 'email'].

  OIDC_GOOGLE_APPS_DOMAIN
    The Google Apps domain that must be used to login to this application.
    Defaults to None, which means this check is skipped and the user can login
    with any Google account.

  OIDC_ID_TOKEN_COOKIE_NAME
    Name of the cookie used to store the users' login state. Defaults to
    "oidc_id_token".

  OIDC_ID_TOKEN_COOKIE_PATH
    Path under which the login state cookie is stored. Defaults to "/".

  OIDC_ID_TOKEN_COOKIE_TTL
    Integer telling how long the login state of the user remains valid.
    Defaults to 7 days.

  OIDC_COOKIE_SECURE
    Boolean indicating whether the cookie should be sent with the secure flag
    enabled. This means that a client (browser) will only send the cookie over
    an https connection. *Do NOT disable this in production please.*
    Defaults to True, indicating the cookie is marked as secure.

  OIDC_VALID_ISSUERS
    The token issuer that is accepted. Please check your Identity Providers
    documentation for the correct value.
    Defaults to the value of "issuer" in client_secrets, or the Google issuer
    if not found.

  OIDC_CLOCK_SKEW
    Number of seconds of clock skew allowed when checking the "don't use
    before" and "don't use after" values for tokens.
    Defaults to sixty seconds (one minute).

  OIDC_REQUIRE_VERIFIED_EMAIL
    Boolean indicating whether the Identity Provider needs to mark the email
    as "verified".
    Defaults to False.

  OIDC_OPENID_REALM
    String passed to the OpenID Connect provider to ask for the old OpenID
    identity for users. This helps when migrating from OpenID 2.0 to OpenID
    Connect because the Identity Provider will also add the OpenID 2.0 identity
    so you can tie them together.
    Defaults to None.

  OIDC_USER_INFO_ENABLED
    Boolean whether to get user information from the UserInfo endpoint provided
    by the Identity Provider in addition to the token information.
    Defaults to True.

  OIDC_CALLBACK_ROUTE
    URL relative to the web root to indicate where the oidc_callback url is
    mounted on.
    Defaults to /oidc_callback.

  OVERWRITE_REDIRECT_URI
    URL to use as return url when passing to the Identity Provider. To be used
    when Flask could not detect the correct hostname, scheme or path to your
    application. Alternatively used when custom handler is to be used.
    Defaults to False (disabled).

  OIDC_RESOURCE_SERVER_ONLY
    Boolean whether to disable the OpenID Client parts. You can enable this
    in applications where you only use the resource server parts (accept_token)
    and will skip checking for any cookies.

  OIDC_RESOURCE_CHECK_AUD
    Boolean to indicate whether the current application needs to be the
    "audience" of tokens passed.
    Defaults to False.

  OIDC_INTROSPECTION_AUTH_METHOD
    String that sets the authentication method used when communicating with
    the token_introspection_uri.  Valid values are 'client_secret_post',
    'client_secret_basic', or 'bearer'.  Defaults to 'client_secret_post'.


API References
--------------

The full API reference:

.. automodule:: flas_oidc_ext
   :members:

Discovery
---------
.. automodule:: flas_oidc_ext.discovery
   :members:

Registration
------------
.. automodule:: flas_oidc_ext.registration
   :members:


.. _Flask: http://flask.pocoo.org/
.. _OpenID Connect: https://openid.net/connect/
.. _oauth2client: https://github.com/google/oauth2client
