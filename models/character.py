from datetime import datetime
from extensions import db
import json
class Character(db.Model):
    __tablename__ = 'character'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    user = db.relationship('User', backref=db.backref('linked_character', overlaps="linked_characters"), foreign_keys=[user_id], overlaps="linked_characters")
    name = db.Column(db.String(64), unique=True, nullable=False)
    bodyguards = db.Column(db.Integer, default=0)
    date_created = db.Column(db.DateTime, nullable=True, default=datetime.utcnow)
    health = db.Column(db.Integer, default=100)
    money = db.Column(db.Integer, default=250)
    level = db.Column(db.Integer, default=1)
    xp = db.Column(db.Integer, default=0)
    last_crime_time = db.Column(db.DateTime, nullable=True)
    last_travel_time = db.Column(db.DateTime, nullable=True)
    city = db.Column(db.String(64), default="New York")
    gun_id = db.Column(db.Integer, db.ForeignKey('shop_item.id'))
    gun = db.relationship('ShopItem', foreign_keys=[gun_id])
    in_jail = db.Column(db.Boolean, default=False)
    jail_until = db.Column(db.DateTime, nullable=True)
    bar_timer = db.Column(db.DateTime, nullable=True)
    bar_cooldown = db.Column(db.DateTime, nullable=True)  # New field for bar cooldown
    crime_group_id = db.Column(db.Integer, db.ForeignKey('organized_crime.id'))
    crime_group = db.relationship("OrganizedCrime", back_populates="members", foreign_keys=[crime_group_id])
    master_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    equipped_gun_id = db.Column(db.Integer, db.ForeignKey('gun.id'), nullable=True)
    equipped_gun = db.relationship('Gun', foreign_keys=[equipped_gun_id])
    earn_streak = db.Column(db.Integer, default=0)
    last_earned = db.Column(db.DateTime, nullable=True)
    is_alive = db.Column(db.Boolean, default=True)
    profile_image = db.Column(db.String(255), nullable=True)
    crew_id = db.Column(db.Integer, db.ForeignKey('crew.id'))
    linked_user = db.relationship('User', foreign_keys=[user_id], overlaps="linked_character,linked_characters,user")
    crew = db.relationship('Crew', backref='characters')
    bio = db.Column(db.Text, default="")
    bodyguard_names = db.Column(db.Text, default="[]")  # Store as JSON list of names

    @property
    def bodyguard_names_list(self):
        return json.loads(self.bodyguard_names or "[]")

    def add_bodyguards(self, names):
        current = self.bodyguard_names_list
        current.extend(names)
        self.bodyguard_names = json.dumps(current)



    
    @property
    def immortal(self):
        if self.master and getattr(self.master, "is_admin", False):
            return True
        return False

class Godfather(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    city = db.Column(db.String(64), unique=True, nullable=False)
    character_id = db.Column(db.Integer, db.ForeignKey('character.id'), unique=True, nullable=False)
    character = db.relationship('Character', backref='godfather_of')
