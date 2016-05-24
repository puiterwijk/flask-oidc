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
    oidc = OpenID(app)


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
