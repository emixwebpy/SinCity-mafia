from extensions import db
from datetime import datetime

class BankAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    character_id = db.Column(db.Integer, db.ForeignKey('character.id'), unique=True)
    balance = db.Column(db.Integer, default=0)
    character = db.relationship('Character', backref='bank_account')

class BankTransaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.Integer, db.ForeignKey('bank_account.id'))
    type = db.Column(db.String(20))  # deposit, withdraw, transfer
    amount = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.String(255))
    account = db.relationship('BankAccount', backref='transactions')