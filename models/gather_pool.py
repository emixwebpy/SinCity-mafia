from extensions import db
from datetime import datetime

class JailGatherPool(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    total_credits = db.Column(db.Integer, default=0)
    last_reset = db.Column(db.DateTime, default=datetime.utcnow)

class JailGatherContribution(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    credits = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)