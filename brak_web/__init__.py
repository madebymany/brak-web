import os
import re
from functools import wraps
import base64

from flask import Flask, render_template, request, redirect, url_for, flash, \
    session
from flask.ext.sqlalchemy import SQLAlchemy
from flask_appconfig.env import from_envvars
from flask_oauthlib.client import OAuth
from flask_sslify import SSLify
from sqlalchemy.dialects import postgresql

from . import tansit


app = Flask(__name__)
SSLify(app, skips=['_health_check'])

app.config['PORT'] = 5000
app.config['SQLALCHEMY_DATABASE_URI'] = \
    "postgresql+pg8000://brak-web@/brak_dev"
app.config['TANSIT_ENDPOINT'] = "ipc:///tmp/tansit.zmq"
app.config['PREFERRED_URL_SCHEME'] = 'http'
app.secret_key = os.urandom(128)  # maybe do this better sometime
from_envvars(app.config, prefix="BRAK_")

if app.config.get('SECRET_KEY_BASE64'):
    app.secret_key = base64.b64decode(app.config['SECRET_KEY_BASE64'])

db = SQLAlchemy(app)
db_metadata = db.MetaData()

newest_packages = db.Table(
    'newest_packages', db_metadata,
    db.Column('name', db.String),
    db.Column('latest_version', db.String),
    db.Column('codename', db.String),
    db.Column('component', db.String),
    db.Column('bucket', db.String),
    db.Column('archs', postgresql.ARRAY(db.String)),
)

oauth = OAuth(app)
google_auth = oauth.remote_app(
    'google',
    consumer_key=app.config.get('GOOGLE_ID'),
    consumer_secret=app.config.get('GOOGLE_SECRET'),
    request_token_params={
        'scope': 'https://www.googleapis.com/auth/userinfo.email'
    },
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
)


class PromotionRequest:
    @classmethod
    def from_request_or_redirect(cls, request):
        try:
            return cls(package_name=request.args.get('name'),
                       version=request.args.get('version'),
                       codename=request.args.get('codename'),
                       component=request.args.get('component'),
                       bucket=request.args.get('bucket'),
                       arch=request.args.get('arch'),
                       )
        except ValueError:
            return redirect(url_for('.index'))

    @classmethod
    def from_db_or_none(cls, row):
        try:
            return cls(package_name=row.name,
                       version=row.latest_version,
                       codename=row.codename,
                       component=row.component,
                       bucket=row.bucket,
                       arch=row.archs[0])
        except ValueError:
            return None

    def __init__(self, package_name, version, codename, component, bucket,
                 arch):
        self.package_name = package_name
        self.version = version
        self.codename = codename
        self.from_component = component
        if self.from_component not in PROMOTION_PATHS:
            raise ValueError("Cannot promote from {}".
                             format(self.from_component))
        self.bucket = bucket
        self.arch = arch

    @property
    def to_component(self):
        return PROMOTION_PATHS[self.from_component]

    @property
    def url_args(self):
        return dict(name=self.package_name, version=self.version,
                    codename=self.codename, component=self.from_component,
                    bucket=self.bucket, arch=self.arch)


PROMOTION_PATHS = {
    'unstable': 'stable',
    'qa': 'staging',
    'staging': 'production',
}


class Package(object):
    def __init__(self, row):
        self.row = row
        self.promotion_req = PromotionRequest.from_db_or_none(self.row)
        return super().__init__()

    @property
    def can_promote(self):
        return self.promotion_req is not None

    @property
    def promotion_url(self):
        return url_for('.promote', **self.promotion_req.url_args)

    def __getattr__(self, attr):
        return getattr(self.row, attr)


def authorized(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'google_token' in session:
            return f(*args, **kwargs)
        else:
            return redirect(url_for('.login'))
    return wrapper


@google_auth.tokengetter
def get_google_oauth_token():
    return session.get('google_token')


@app.route('/_health_check')
def health_check():
    return ("OK", 200, {"Content-Type": "text/plain"})


@app.route('/login')
def login():
    return render_template("login.html")


@app.route('/auth/google')
def redirect_google_auth():
    return google_auth.authorize(
        callback=url_for('.oauth2callback', _external=True,
                         _scheme=app.config['PREFERRED_URL_SCHEME']))


@app.route('/logout')
def logout():
    session.pop('google_token', None)
    return redirect(url_for('index'))


@app.route('/oauth2callback')
def oauth2callback():
    resp = google_auth.authorized_response()
    if resp is None:
        flash('Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        ), "danger")
    else:
        session['google_token'] = (resp['access_token'], '')
        email = google_auth.get('userinfo').data['email']
        if not re.match(r'\A[-\.\+a-z]+@madebymany\.(co\.uk|com)\Z', email):
            flash("You're not an MxMer", "danger")
            session.pop('google_token', None)
    return redirect(url_for('.index'))


@app.route('/')
@authorized
def index():
    return render_template(
        'index.html',
        entries=(Package(r) for r in
                 db.session.execute(db.select([newest_packages]))))


@app.route('/promote', methods=['GET', 'POST'])
@authorized
def promote():
    promotion_req = PromotionRequest.from_request_or_redirect(request)
    if not isinstance(promotion_req, PromotionRequest):
        flash("Invalid promotion request", "danger")
        return promotion_req

    if request.method == 'POST':
        success, msg = tansit.promote(app.config['TANSIT_ENDPOINT'],
                                      promotion_req)
        return render_template('promote_done.html', success=success,
                               command_output=msg)
    else:
        return render_template('promote_confirm.html',
                               promotion_req=promotion_req)


def run():
    import tornado.options
    from tornado.wsgi import WSGIContainer
    from tornado.httpserver import HTTPServer
    from tornado.ioloop import IOLoop

    tornado.options.parse_command_line()

    http_server = HTTPServer(WSGIContainer(app))
    http_server.listen(int(app.config['PORT']))
    IOLoop.instance().start()
