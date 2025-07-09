from extensions import db
from datetime import datetime

class Territory(db.Model):
    __tablename__ = 'territory'
    id = db.Column(db.Integer, primary_key=True)
    x = db.Column(db.Integer, nullable=False)
    y = db.Column(db.Integer, nullable=False)
    owner_crew_id = db.Column(db.Integer, db.ForeignKey('crew.id'), nullable=True)
    contesting_crew_id = db.Column(db.Integer, db.ForeignKey('crew.id'), nullable=True)
    payout = db.Column(db.Integer, default=10000)
    contested_until = db.Column(db.DateTime, nullable=True)
    custom_name = db.Column(db.String(64), nullable=True)
    theme = db.Column(db.String(64), nullable=True)
    last_payout = db.Column(db.DateTime, nullable=True, default=None)
    owner_crew = db.relationship('Crew', foreign_keys=[owner_crew_id], backref='territories_owned')
    contesting_crew = db.relationship('Crew', foreign_keys=[contesting_crew_id], backref='territories_contesting')

    __table_args__ = (db.UniqueConstraint('x', 'y', name='unique_grid_cell'),)
    def last_gathered_by(self, character_id):
        log = ResourceGatherLog.query.filter_by(
            character_id=character_id,
            territory_id=self.id
        ).first()
        return log.last_gathered if log else None
    def is_claimed(self):
        return self.owner_crew_id is not None

    def is_contested(self):
        return self.contesting_crew_id is not None and self.contested_until is not None
    
class TerritoryResource(db.Model):
    __tablename__ = 'territory_resources'
    id = db.Column(db.Integer, primary_key=True)
    crew_id = db.Column(db.Integer, db.ForeignKey('crew.id'), nullable=False)
    territory_id = db.Column(db.Integer, db.ForeignKey('territory.id'), nullable=False)
    resource_type = db.Column(db.String(32), nullable=False, default='supplies')
    amount = db.Column(db.Integer, nullable=False, default=0)
    required = db.Column(db.Integer, nullable=False, default=100)  # Example requirement
    
    __table_args__ = (db.UniqueConstraint('crew_id', 'territory_id', 'resource_type'),)

class ResourceGatherLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    character_id = db.Column(db.Integer, db.ForeignKey('character.id'), nullable=False)
    territory_id = db.Column(db.Integer, db.ForeignKey('territory.id'), nullable=False)
    last_gathered = db.Column(db.DateTime, nullable=False)
    __table_args__ = (db.UniqueConstraint('character_id', 'territory_id', name='_char_territory_uc'),)