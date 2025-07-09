from extensions import db

class TerritoryClaimer(db.Model):
    __tablename__ = 'territory_claimers'
    id = db.Column(db.Integer, primary_key=True)
    territory_id = db.Column(db.Integer, db.ForeignKey('territory.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    # Relationships (optional, for convenience)
    territory = db.relationship('Territory', backref='claimers')
    user = db.relationship('User', backref='territory_claims')