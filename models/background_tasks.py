import threading
import time
from flask import current_app
from models.utils import release_expired_jail
from models.drug import DrugDealer
from datetime import datetime, timedelta
from flask_login import current_user
import random
from models.character import Character
from extensions import db


def jail_release_background_task(app):
    with app.app_context():
        while True:
            release_expired_jail()
            time.sleep(20)  # Check every 20 seconds

def start_jail_release_thread(app):
    t = threading.Thread(target=jail_release_background_task, args=(app,), daemon=True)
    t.start()

def randomize_all_drug_prices(min_price=50, max_price=10000, min_stock=5, max_stock=500):
    """Randomize prices and stock for all DrugDealers."""
    dealers = DrugDealer.query.all()
    for dealer in dealers:
        dealer.price = random.randint(min_price, max_price)
        dealer.stock = random.randint(min_stock, max_stock)
    db.session.commit()
def randomize_drug_prices(app, interval_minutes=10):
    with app.app_context():
        while True:
            randomize_all_drug_prices(min_price=50, max_price=10000, min_stock=5, max_stock=5000)
            time.sleep(interval_minutes * 60)
def get_online_users():
    cutoff = datetime.utcnow() - timedelta(seconds=1)
    # Real users online
    real_online = current_user.name.query.filter(current_user.last_seen >= cutoff).all()
    # NPCs: Characters with master_id=0 (or whatever you use)
    npcs = Character.query.filter_by(master_id=0, is_alive=True).all()
    # Optionally, create a fake User object for each NPC if your template expects User
    return real_online, npcs
def start_price_randomizer():
    t = threading.Thread(target=randomize_drug_prices, args=(10,), daemon=True)  # 10 minutes interval
    t.start()