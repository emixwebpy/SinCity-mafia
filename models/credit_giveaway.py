from datetime import datetime
from app import db

class CreditGiveaway(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(32), unique=True, nullable=False)
    credits = db.Column(db.Integer, nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    claimed_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    claimed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    claimer = db.relationship('User', foreign_keys=[claimed_by_id])