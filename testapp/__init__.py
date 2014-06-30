from flask import Flask
from flask.ext.oidc import OpenIDConnect

app = Flask(__name__)

app.config['SECRET_KEY'] = 'SEEEKRIT'  # used to encrypt cookies
app.config['OIDC_CLIENT_SECRETS'] = 'client_secrets.json'
app.config['SERVER_NAME'] = 'localhost:5000'

oidc = OpenIDConnect(app)

@app.route('/')
@oidc.check
def index():
    return "too many secrets", 200, {
        'Content-Type': 'text/plain; charset=utf-8'
    }
