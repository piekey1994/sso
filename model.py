from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta

db = SQLAlchemy()

class SSO_ADMIN(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40), unique=True)
    passwd = db.Column(db.String(256))
    

class SSO_USER(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40), unique=True, index=True,
                         nullable=False)
    passwd = db.Column(db.String(256))
    reg_time = db.Column(db.DateTime,default=datetime.utcnow())
    pic_src = db.Column(db.String(256),default="")
    email = db.Column(db.String(256),default="")
    sex = db.Column(db.Integer)
    address = db.Column(db.String(256))
    def check_password(self, password):
        return True


class SSO_CLIENT(db.Model):
    #id = db.Column(db.Integer, primary_key=True)
    # human readable name
    name = db.Column(db.String(40))
    client_id = db.Column(db.String(40), primary_key=True)
    client_secret = db.Column(db.String(55), unique=True, index=True,
                              nullable=False)
    client_type = db.Column(db.String(20), default='public')
    _redirect_uris = db.Column(db.Text)
    default_scope = db.Column(db.Text, default='email address')

    @property
    def user(self):
        return SSO_USER.query.get(1)

    @property
    def redirect_uris(self):
        if self._redirect_uris:
            return self._redirect_uris.split()
        return []

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]

    @property
    def default_scopes(self):
        if self.default_scope:
            return self.default_scope.split()
        return []

    @property
    def allowed_grant_types(self):
        return ['authorization_code', 'password', 'client_credentials',
                'refresh_token']


class SSO_GRANT(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('SSO_USER.id', ondelete='CASCADE')
    )
    user = relationship('SSO_USER')

    client_id = db.Column(
        db.String(40), db.ForeignKey('SSO_CLIENT.client_id', ondelete='CASCADE'),
        nullable=False,
    )
    client = relationship('SSO_CLIENT')
    code = db.Column(db.String(255), index=True, nullable=False)

    redirect_uri = db.Column(db.String(255))
    scope = db.Column(db.Text)
    expires = db.Column(db.DateTime)

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        return self

    @property
    def scopes(self):
        if self.scope:
            return self.scope.split()
        return None


class SSO_TOKEN(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(
        db.String(40), db.ForeignKey('SSO_CLIENT.client_id', ondelete='CASCADE'),
        nullable=False,
    )
    user_id = db.Column(
        db.Integer, db.ForeignKey('SSO_USER.id', ondelete='CASCADE')
    )
    user = relationship('SSO_USER')
    client = relationship('SSO_CLIENT')
    token_type = db.Column(db.String(40))
    access_token = db.Column(db.String(255))
    refresh_token = db.Column(db.String(255))
    expires = db.Column(db.DateTime)
    scope = db.Column(db.Text)

    def __init__(self, **kwargs):
        expires_in = kwargs.pop('expires_in', None)
        if expires_in is not None:
            self.expires = datetime.utcnow() + timedelta(seconds=expires_in)

        for k, v in kwargs.items():
            setattr(self, k, v)

    @property
    def scopes(self):
        if self.scope:
            return self.scope.split()
        return []

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        return self
