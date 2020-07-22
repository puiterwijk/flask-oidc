
project = 'Flask Oidc 2'

copyright = '2020, Vishnu Prasad'

author = 'Vishnu Prasad'


from pkg_resources import get_distribution

release = get_distribution('flask_oidc2').version
version = '.'.join(release.split('.')[:2])


extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.doctest',
    'sphinx.ext.todo'
]

master_doc = 'index'

templates_path = ['_templates']

exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

html_theme = 'sphinx_drove_theme'

import sphinx_drove_theme

html_theme_path = [sphinx_drove_theme.get_html_theme_path()]
