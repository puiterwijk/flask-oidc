from setuptools import setup
from pip.req import parse_requirements

setup(
    name='flask-oidc',
    description='OpenID Connect extension for Flask',
    url='https://github.com/SteelPangolin/flask-oidc',
    author='Jeremy Ehrhardt',
    author_email='jeremy@bat-country.us',
    version='0.1.0',
    packages=[
        'flask_oidc',
    ],
    install_requires=[str(req.req) for req in parse_requirements('requirements.txt')],
    zip_safe=False,
)
