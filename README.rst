flask-oidc-ext
==============

`OpenID Connect`_ support for `Flask`_. |image| |image1| |Documentation Status| |image2|

.. _OpenID Connect: https://openid.net/connect/
.. _Flask: http://flask.pocoo.org/
.. _Google+ Login: https://developers.google.com/accounts/docs/OAuth2Login
.. _Ipsilon: https://ipsilon-project.org/

.. |image| image:: https://img.shields.io/pypi/v/flask-oidc-ext.svg?style=flat
   :target: https://pypi.python.org/pypi/flask-oidc-ext
.. |image1| image:: https://img.shields.io/pypi/dm/flask-oidc.svg?style=flat
   :target: https://pypi.python.org/pypi/flask-oidc
.. |Documentation Status| image:: https://readthedocs.org/projects/flask-oidc/badge/?version=latest
   :target: http://flask-oidc.readthedocs.io/en/latest/?badge=latest
.. |image2| image:: https://img.shields.io/travis/puiterwijk/flask-oidc.svg?style=flat
   :target: https://travis-ci.org/puiterwijk/flask-oidc

This library should work with any standards compliant OpenID Connect
provider.

It has been tested with:

* `Google+ Login <https://developers.google.com/accounts/docs/OAuth2Login>`_
* `Ipsilon <https://ipsilon-project.org/>`_
* `MojeID <https://mojeid.cz>`_

--------------

Project status
**************

This project is actively maintained.

--------------

Extension list
**************

-  Added extra header option to requests ``OIDC_EXTRA_REQUEST_HEADERS``.
   This adds the ability to add a ``Host: <issuer>`` header in
   environments where the issuer is no the same DNS as where the request
   is sent to. E.g ``localhost`` vs ``127.0.0.1``.

