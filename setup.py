import os.path
import io

from setuptools import setup

here = os.path.abspath(os.path.dirname(__file__))
with io.open(os.path.join(here, 'README.rst')) as f:
    readme = f.read()

setup(
    name='flask-oidc',
    description='OpenID Connect extension for Flask',
    long_description=readme,
    url='https://github.com/SteelPangolin/flask-oidc',
    author='Jeremy Ehrhardt',
    author_email='jeremy@bat-country.us',
    version='0.1.2',
    packages=[
        'flask_oidc',
    ],
    install_requires=[
        'Flask',
        'itsdangerous',
        'oauth2client',
        'six',
    ],
    zip_safe=False,
    classifiers=[
        'Environment :: Web Environment',
        'Framework :: Flask',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
)
