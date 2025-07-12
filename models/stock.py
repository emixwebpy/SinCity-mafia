from extensions import db
from datetime import datetime
import random
class Stock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32), unique=True, nullable=False)
    symbol = db.Column(db.String(16), unique=True, nullable=False)
    price = db.Column(db.Float, nullable=False)
    is_rugged = db.Column(db.Boolean, default=False)

class StockInvestment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    character_id = db.Column(db.Integer, db.ForeignKey('character.id'), nullable=False)
    stock_id = db.Column(db.Integer, db.ForeignKey('stock.id'), nullable=False)
    shares = db.Column(db.Integer, nullable=False)
    buy_price = db.Column(db.Float, nullable=False)

class StockPriceHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    stock_id = db.Column(db.Integer, db.ForeignKey('stock.id'), nullable=False)
    price = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    branch_id = db.Column(db.Integer, default=1)  # Default branch

    stock = db.relationship('Stock', backref=db.backref('price_history', lazy=True))

def update_all_stock_prices():
    stocks = Stock.query.all()
    for stock in stocks:
        # Example: random walk for price
        change = random.randint(-5, 5)
        new_price = max(1, stock.price + change)
        stock.price = new_price
        # Record in history
        history = StockPriceHistory(
            stock_id=stock.id,
            price=new_price,
            timestamp=datetime.utcnow(),
            branch_id=1  # Or your branch logic
        )
        db.session.add(history)
    db.session.commit()