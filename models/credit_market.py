from extensions import db
from datetime import datetime

class CreditOffer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    seller_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    credits = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Integer, nullable=False)  # in-game money per credit
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    seller = db.relationship('User', backref='credit_offers')