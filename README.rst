flask-oidc
==========

`OpenID Connect <https://openid.net/connect/>`_ support for `Flask <http://flask.pocoo.org/>`_.

.. image:: https://img.shields.io/pypi/v/flask-oidc.svg?style=flat
  :target: https://pypi.python.org/pypi/flask-oidc

.. image:: https://img.shields.io/pypi/dm/flask-oidc.svg?style=flat
  :target: https://pypi.python.org/pypi/flask-oidc

.. image:: https://img.shields.io/travis/SteelPangolin/flask-oidc.svg?style=flat
  :target: https://travis-ci.org/SteelPangolin/flask-oidc

Currently designed around Google's `oauth2client <https://github.com/google/oauth2client>`_ library
and `OpenID Connect implementation <https://developers.google.com/accounts/docs/OAuth2Login>`_.
May or may not interoperate with other OpenID Connect identity providers,
for example, Microsoft's `Azure Active Directory <http://msdn.microsoft.com/en-us/library/azure/dn499820.aspx>`_.

Project status
==============

I hope this library has been helpful to anyone who had to scramble to port their Flask apps from `flask-openid <https://pythonhosted.org/Flask-OpenID/>`_ when `Google turned off their OpenID 2.0 support <https://developers.google.com/identity/protocols/OpenID2Migration?hl=en>`_. However, I'm not maintaining it any more, because I'm not currently using it for anything. If you are, either try `danring's fork of this library <https://github.com/danring/flask-oidc>`_, or `Google's oauth2client.flask_util <https://github.com/google/oauth2client/blob/master/oauth2client/flask_util.py>`_.
