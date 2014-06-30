from setuptools import setup
from pip.req import parse_requirements

setup(
    name='flask-oidc',
    description='OpenID Connect extension for Flask',
    version='0.0.0',
    packages=[
        'flask_oidc',
    ],
    install_requires=[str(req.req) for req in parse_requirements('requirements.txt')],
    zip_safe=False,
)
