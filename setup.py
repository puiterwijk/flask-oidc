import os.path
import io
import sys

from setuptools import setup

here = os.path.abspath(os.path.dirname(__file__))
with io.open(os.path.join(here, 'README.rst')) as f:
    readme = f.read()

setup(
    name='flask-oidc2',
    use_scm_version = {
        "root": ".",
        "relative_to": __file__,
        "local_scheme": "node-and-timestamp"
    },
    description='OpenID Connect extension for Flask',
    long_description=readme,
    url='https://github.com/vishnu667/flask-oidc2',
    
    author='Vishnu Prasad, Patrick Uiterwijk',
    author_email='vishnu667@gmail.com',
    project_urls={
        "Bug Tracker": "https://github.com/vishnu667/flask-oidc2/issues",
        "Documentation": "https://flask-oidc2.readthedocs.io/",
        "Source Code": "https://github.com/vishnu667/flask-oidc2/",
    },
    setup_requires=['setuptools_scm'],
    packages=[
        'flask_oidc',
    ],
    
    install_requires=[
        'flask',
        'itsdangerous',
        'oauth2client',
        'six',
    ],
    tests_require=['nose', 'mock'],
    entry_points={
        'console_scripts': ['oidc-register=flask_oidc.registration_util:main'],
    },
    zip_safe=False,
    classifiers=[
        'Environment :: Web Environment',
        'Framework :: Flask',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
)
