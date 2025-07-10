from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from extensions import db

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(12), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    crew_id = db.Column(db.Integer, db.ForeignKey('crew.id'), nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    email_verified = db.Column(db.Boolean, default=False)
    email_verification_token = db.Column(db.String(128), nullable=True)
    reset_token = db.Column(db.String(128), nullable=True)
    reset_token_expiry = db.Column(db.DateTime, nullable=True)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_earned = db.Column(db.DateTime, default=None, nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    premium = db.Column(db.Boolean, default=False)
    premium_until = db.Column(db.DateTime, nullable=True)
    last_known_ip = db.Column(db.String(45))
    organized_crime_id = db.Column(db.Integer, db.ForeignKey('organized_crime.id'))
    last_crime_time = db.Column(db.DateTime, nullable=True)
    gun_id = db.Column(db.Integer, db.ForeignKey('shop_item.id'), nullable=True)
    gun = db.relationship('ShopItem', foreign_keys=[gun_id])
    character = db.relationship('Character', backref='master', uselist=False, foreign_keys='Character.master_id')
    characters = db.relationship(
        'Character',
        backref=db.backref('owner', overlaps="character,master"),
        lazy=True,
        foreign_keys='Character.master_id',
        overlaps="character,master"
    )
    kills = db.Column(db.Integer, default=0)
    linked_characters = db.relationship('Character', foreign_keys='Character.user_id')

    def set_password(self, password):
        self.password_hash = generate_password_hash(
            password,
            method='pbkdf2:sha256',
            salt_length=16
        )
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    def __repr__(self):
        return f'<User {self.username}>'

