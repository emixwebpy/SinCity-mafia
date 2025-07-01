from extensions import db

class Territory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    city = db.Column(db.String(64), unique=True, nullable=False)
    owner_crew_id = db.Column(db.Integer, db.ForeignKey('crew.id'))
    payout = db.Column(db.Integer, default=10000)  # Example payout per period

    owner_crew = db.relationship('Crew', backref='territories')