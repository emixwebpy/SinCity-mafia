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
        # Allow price to go up or down: -50% to +50% random walk
        pct_change = random.uniform(-0.99, 0.99)
        new_price = max(1, round(stock.price * (1 + pct_change), 2))
        stock.price = new_price

        for stock in stocks:
    
            last_history = StockPriceHistory.query.filter_by(stock_id=stock.id).order_by(StockPriceHistory.timestamp.desc()).first()
            if last_history:
                branch_id = last_history.branch_id if last_history.branch_id else 1
                # Example: increment branch_id if the stock was just rugged
                if stock.is_rugged and not last_history.stock.is_rugged:
                    branch_id += 1
            else:
                branch_id = 1

        # Record the new price in history
        history = StockPriceHistory(
            stock_id=stock.id,
            price=new_price,
            timestamp=datetime.utcnow(),
            branch_id=branch_id
        )
        db.session.add(history)
    db.session.commit()