from models.character import Character
from extensions import db
for char in Character.query.filter(Character.kills == None).all():
    char.kills = 0
db.session.commit()