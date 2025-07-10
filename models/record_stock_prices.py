
from extensions import db
from models.stock import Stock, StockPriceHistory

def record_current_stock_prices():
    """Record the current prices of all stocks in the database."""
    stocks = Stock.query.all()
    for stock in stocks:
        history = StockPriceHistory(stock_id=stock.id, price=stock.price)
        db.session.add(history)
    db.session.commit()
    print("Recorded current prices for all stocks.")