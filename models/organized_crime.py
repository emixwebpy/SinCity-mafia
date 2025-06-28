from extensions import db

class OrganizedCrime(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=True)
    invite_code = db.Column(db.String(8), unique=True, nullable=False)
    leader_id = db.Column(db.Integer, db.ForeignKey('character.id'), nullable=False)
    leader = db.relationship("Character", backref="led_crime_groups", foreign_keys=[leader_id])
    members = db.relationship(
        "Character",
        back_populates="crime_group",
        foreign_keys="Character.crime_group_id"
    )

    def is_full(self):
        return len(self.members) >= 4
