from flask_admin.contrib.sqla import ModelView
from wtforms import BooleanField, IntegerField
from extensions import db

class ShopItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    description = db.Column(db.String(256))
    price = db.Column(db.Integer, nullable=False)
    stock = db.Column(db.Integer, nullable=False, default=0)
    is_gun = db.Column(db.Boolean, default=False)
    damage = db.Column(db.Integer, default=0)
    gun_id = db.Column(db.Integer, db.ForeignKey('gun.id', ondelete='CASCADE'), nullable=True)
    gun = db.relationship('Gun')

class ShopItemModelView(ModelView):
    can_create = True
    can_edit = True
    can_delete = True
    can_view_details = True
    column_list = ('id', 'name', 'description', 'price', 'stock', 'is_gun', 'damage')
    form_columns = ('name', 'description', 'price', 'stock', 'is_gun', 'damage')
    column_searchable_list = ('name', 'description')
    is_gun = BooleanField('Is Gun', default=False)
    damage = IntegerField('Damage', default=0)

class UserInventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('shop_item.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1, nullable=False)
    user = db.relationship('User', backref='inventory')
    item = db.relationship('ShopItem')

class Gun(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    damage = db.Column(db.Integer, nullable=False)
    accuracy = db.Column(db.Float, default=0.7)
    rarity = db.Column(db.String(32), default='Common')
    price = db.Column(db.Integer, nullable=False)
    image = db.Column(db.String(255), nullable=True)
    description = db.Column(db.String(255), nullable=True)
