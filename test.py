from app import db, Character, app

with app.app_context():
    print([c.id for c in Character.query.all()])