from extensions import db

class Drug(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    type = db.Column(db.String(32), nullable=False, default="Other")

class DrugDealer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    city = db.Column(db.String(64), nullable=False)
    drug_id = db.Column(db.Integer, db.ForeignKey('drug.id'), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    stock = db.Column(db.Integer, nullable=False, default=10)
    drug = db.relationship('Drug')

class CharacterDrugInventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    character_id = db.Column(db.Integer, db.ForeignKey('character.id'), nullable=False)
    drug_id = db.Column(db.Integer, db.ForeignKey('drug.id'), nullable=False)
    quantity = db.Column(db.Integer, default=0)
    drug = db.relationship('Drug')
    character = db.relationship('Character')
