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

    from flask.ext.oidc import OpenIDConnect
    oidc = OpenIDConnect(app)


Alternatively the object can be instantiated without the application in
which case it can later be registered for an application with the
:meth:`~flask_oidc.OpenIDConnect.init_app` method.

Note that you should probably provide the library with a place to store the
credentials it has retrieved for the user. These need to be stored in a place
where the user themselves or an attacker can not get to them.
To provide this, give an object that has ``__setitem__`` and ``__getitem__``
dict APIs implemented as second argument to the :meth:`~flask_oidc.OpenIDConnect.__init__`
call.
Without this, the library will only work on a single thread, and only retain
sessions until the server is restarted.

Using this library is very simple: you can use
:data:`~flask_oidc.OpenIDConnect.user_loggedin` to determine whether a user is currently
logged in using OpenID Connect.

If the user is logged in, you an use :meth:`~flask_oidc.OpenIDConnect.user_getfield` and
:meth:`~flask_oidc.OpenIDConnect.user_getinfo` to get information about the currently
logged in user.

If the user is not logged in, you can send them to any function that is
decorated with :meth:`~flask_oidc.OpenIDConnect.require_login` to get them automatically
redirected to login.


Example
-------

A very basic example client::

    @app.route('/')
    def index():
        if oidc.user_loggedin:
            return 'Welcome %s' % oidc.user_getfield('email')
        else
            return 'Not logged in'

    @app.route('/login')
    @oidc.require_login
    def login():
        return 'Welcome %s' % oidc.user_getfield('email')


Resource server
---------------

Also, if you have implemented an API that can should be able to accept tokens
issued by the OpenID Connect provider, just decorate those API functions with
:meth:`~flask_oidc.OpenIDConnect.accept_token`::

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
    application.
    Defaults to False (disabled).

  OIDC_RESOURCE_SERVER_ONLY
    Boolean whether to disable the OpenID Client parts. You can enable this
    in applications where you only use the resource server parts (accept_token)
    and will skip checking for any cookies.

  OIDC_RESOURCE_CHECK_AUD
    Boolean to indicate whether the current application needs to be the
    "audience" of tokens passed.
    Defaults to False.


API References
--------------

The full API reference:

.. automodule:: flask_oidc
   :members:

Discovery
---------
.. automodule:: flask_oidc.discovery
   :members:

Registration
------------
.. automodule:: flask_oidc.registration
   :members:


.. _Flask: http://flask.pocoo.org/
.. _OpenID Connect: https://openid.net/connect/
.. _oauth2client: https://github.com/google/oauth2client
