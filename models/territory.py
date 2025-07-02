from extensions import db
from datetime import datetime

class Territory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    city = db.Column(db.String(64), unique=True, nullable=False)
    owner_crew_id = db.Column(db.Integer, db.ForeignKey('crew.id'))
    contesting_crew_id = db.Column(db.Integer, db.ForeignKey('crew.id'), nullable=True)
    payout = db.Column(db.Integer, default=10000)
    contested_until = db.Column(db.DateTime, nullable=True)
    custom_name = db.Column(db.String(64), nullable=True)  # New field
    theme = db.Column(db.String(64), nullable=True)        # New field

    owner_crew = db.relationship('Crew', foreign_keys=[owner_crew_id], backref='territories_owned')
    contesting_crew = db.relationship('Crew', foreign_keys=[contesting_crew_id], backref='territories_contesting')