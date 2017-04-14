# coding: utf-8
from datetime import datetime, timedelta
from flask import g, render_template, request, jsonify, make_response,redirect
from flask_oauthlib.provider import OAuth2Provider
from flask_oauthlib.contrib.oauth2 import bind_sqlalchemy
from flask_oauthlib.contrib.oauth2 import bind_cache_grant
from model import db,SSO_USER,SSO_CLIENT,SSO_GRANT,SSO_TOKEN,SSO_ADMIN



def current_user():
    return g.user


def cache_provider(app):
    oauth = OAuth2Provider(app)

    bind_sqlalchemy(oauth, db.session, user=User,
                    token=Token, client=Client)

    app.config.update({'OAUTH2_CACHE_TYPE': 'simple'})
    bind_cache_grant(app, oauth, current_user)
    return oauth


def sqlalchemy_provider(app):
    oauth = OAuth2Provider(app)

    bind_sqlalchemy(oauth, db.session, user=User, token=Token,
                    client=Client, grant=Grant, current_user=current_user)

    return oauth


def default_provider(app):
    oauth = OAuth2Provider(app)

    @oauth.clientgetter
    def get_client(client_id):
        return SSO_CLIENT.query.filter_by(client_id=client_id).first()

    @oauth.grantgetter
    def get_grant(client_id, code):
        return SSO_GRANT.query.filter_by(client_id=client_id, code=code).first()

    @oauth.tokengetter
    def get_token(access_token=None, refresh_token=None):
        if access_token:
            return SSO_TOKEN.query.filter_by(access_token=access_token).first()
        if refresh_token:
            return SSO_TOKEN.query.filter_by(refresh_token=refresh_token).first()
        return None

    @oauth.grantsetter
    def set_grant(client_id, code, request, *args, **kwargs):
        expires = datetime.utcnow() + timedelta(seconds=100)
        grant = SSO_GRANT(
            client_id=client_id,
            code=code['code'],
            redirect_uri=request.redirect_uri,
            scope=' '.join(request.scopes),
            user_id=g.user.id,
            expires=expires,
        )
        db.session.add(grant)
        db.session.commit()

    @oauth.tokensetter
    def set_token(token, request, *args, **kwargs):
        # In real project, a token is unique bound to user and client.
        # Which means, you don't need to create a token every time.
        tok = SSO_TOKEN(**token)
        tok.user_id = request.user.id
        tok.client_id = request.client.client_id
        db.session.add(tok)
        db.session.commit()

    @oauth.usergetter
    def get_user(username, password, *args, **kwargs):
        # This is optional, if you don't need password credential
        # there is no need to implement this method
        return User.query.filter_by(name=username).first()

    return oauth


def prepare_app(app):
    db.init_app(app)
    db.app = app
    db.create_all()

    admin = SSO_ADMIN(
        name='knowsec',passwd='Knowsec321.123!'
    )

    # client1 = SSO_CLIENT(
    #     name='wiki', client_id='wiki', client_secret='wiki',
    #     _redirect_uris=(
    #         'http://127.0.0.1:8000/authorized '
    #         'http://127.0.0.1/authorized'
    #     ),
    # )

    # user = SSO_USER(name='admin')

    # temp_grant = SSO_GRANT(
    #     user_id=1, client_id='confidential',
    #     code='12345', scope='email',
    #     expires=datetime.utcnow() + timedelta(seconds=100)
    # )

    # access_token = SSO_TOKEN(
    #     user_id=1, client_id='dev', access_token='expired', expires_in=0
    # )

    # access_token2 = SSO_TOKEN(
    #     user_id=1, client_id='dev', access_token='never_expire'
    # )

    try:
        # db.session.add(client1)
        db.session.add(admin)
        # db.session.add(user)
        # db.session.add(temp_grant)
        # db.session.add(access_token)
        # db.session.add(access_token2)
        db.session.commit()
    except:
        db.session.rollback()
    return app


def create_server(app, oauth=None):
    if not oauth:
        oauth = default_provider(app)

    app = prepare_app(app)

    # @app.before_request
    # def load_current_user():
    #     user = SSO_USER.query.get(1)
    #     g.user = user


    @app.route('/client_reg', methods=['GET', 'POST'])
    def client_reg():
        if request.method == 'GET':
            if(SSO_ADMIN.query.filter_by(name=request.args.get('name'), passwd=request.args.get('passwd')).first()!=None):
                return render_template("client_reg.html")
            else:
                return "滚！"
        
        if request.method == 'POST':
            client1 = SSO_CLIENT(
                name=request.form['name'], client_id=request.form['id'], client_secret=request.form['secret'],
                _redirect_uris=(
                    request.form['uri']
                ),
            )
            try:
                db.session.add(client1)
                db.session.commit()
                return "注册成功"
            except:
                db.session.rollback()
                return "注册失败"

    @app.route('/user_reg', methods=['GET', 'POST'])
    def user_reg():
        if request.method == 'GET':
            return render_template("user_reg.html")
        
        if request.method == 'POST':
            user = SSO_USER(
                name=request.form['name'], passwd=request.form['passwd'], email=request.form['email']
            )
            try:
                db.session.add(user)
                db.session.commit()
                return "注册成功"
            except:
                db.session.rollback()
                return "注册失败"

    @app.route('/home')
    def home():
        return render_template('home.html')

    @app.route('/oauth/authorize', methods=['GET', 'POST'])
    @oauth.authorize_handler
    def authorize(*args, **kwargs):
        # NOTICE: for real project, you need to require login
        if request.method == 'GET':
            # render a page for user to confirm the authorization
            return render_template('confirm.html')

        if request.method == 'HEAD':
            # if HEAD is supported properly, request parameters like
            # client_id should be validated the same way as for 'GET'
            response = make_response('', 200)
            response.headers['X-Client-ID'] = kwargs.get('client_id')
            return response
        user=SSO_USER.query.filter_by(name=request.form['name'], passwd=request.form['passwd']).first()
        if(user!=None):
            g.user = user
            return True
        else:
            return False

    @app.route('/oauth/token', methods=['POST', 'GET'])
    @oauth.token_handler
    def access_token():
        return {}

    @app.route('/oauth/revoke', methods=['POST'])
    @oauth.revoke_handler
    def revoke_token():
        pass

    @app.route('/api/email')
    @oauth.require_oauth('email')
    def email_api():
        oauth = request.oauth
        return jsonify(email=oauth.user.email, username=oauth.user.name,id=oauth.user.id)

    @app.route('/api/client')
    @oauth.require_oauth()
    def client_api():
        oauth = request.oauth
        return jsonify(client=oauth.client.name)

    @app.route('/api/address/<city>')
    @oauth.require_oauth('address')
    def address_api(city):
        oauth = request.oauth
        return jsonify(address=city, name=oauth.user.name)

    @app.route('/api/method', methods=['GET', 'POST', 'PUT', 'DELETE'])
    @oauth.require_oauth()
    def method_api():
        return jsonify(method=request.method)

    @oauth.invalid_response
    def require_oauth_invalid(req):
        return jsonify(message=req.error_message), 401

    return app


if __name__ == '__main__':
    from flask import Flask
    app = Flask(__name__)
    app.debug = True
    app.secret_key = 'development'
    app.config.update({
        'SQLALCHEMY_DATABASE_URI': 'mysql://root:Knowsec321.@120.76.112.182:3306/knowsec'
    })
    app = create_server(app)
    app.run()
