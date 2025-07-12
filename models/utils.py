import random
import string, re
from datetime import datetime, timedelta
from urllib.parse import urlparse, urljoin
from flask import request
from flask_limiter.util import get_remote_address
from models.character import Character
from models.organized_crime import OrganizedCrime
from models.user import User
from models.drug import Drug, DrugDealer
from models.constants import *
from models.crew import CrewMember, Crew
from flask_login import current_user
from extensions import db
from flask import flash, redirect, url_for
from models.event import CityEvent
from markupsafe import escape, Markup
from models.notification import Notification
from models.territory import Territory

from models.stock import Stock




def initialize_stocks():
    for stock_def in STOCK_MARKETS:
        stock = Stock.query.filter_by(symbol=stock_def['symbol']).first()
        if not stock:
            stock = Stock(
                name=stock_def['name'],
                symbol=stock_def['symbol'],
                price=stock_def['price'],
                branch_id=stock_def['branch_id']
            )
            db.session.add(stock)
    db.session.commit()


def urlize(text, nofollow=True, target='_blank'):
    # Simple urlize implementation
    def repl(match):
        url = match.group(0)
        attrs = []
        if nofollow:
            attrs.append('rel="nofollow"')
        if target:
            attrs.append(f'target="{target}"')
        attr_str = ' '.join(attrs)
        return f'<a href="{url}" {attr_str}>{url}</a>'
    return re.sub(r'(https?://[^\s]+)', repl, text)


def maybe_trigger_city_event():
    # 5% chance to trigger an event on dashboard load
    if random.random() < 0.05:
        event_types = [
            ("Police Raid", "Police are cracking down! All crime payouts halved.", 30),
            ("Festival", "City festival! XP gains doubled.", 30),
            ("Double XP", "Double XP for all actions!", 30)
        ]
        event_type, desc, minutes = random.choice(event_types)
        city = random.choice(CITIES)
        event = CityEvent(
            event_type=event_type,
            city=city,
            start_time=datetime.utcnow(),
            end_time=datetime.utcnow() + timedelta(minutes=minutes),
            description=desc
        )
        db.session.add(event)
        db.session.commit()

#check if the territory claimer failed to claim the territory
def seed_territory_claimers():
    from models.territory import Territory
    from models.territory_claimers import TerritoryClaimer
    from extensions import db

    for territory in Territory.query.all():
        if territory.is_claimed() or territory.is_contested():
            continue
        
        # Check if there's a claimer for this territory
        claimer = TerritoryClaimer.query.filter_by(territory_id=territory.id).first()
        if not claimer:
            continue
        
        # Randomly decide if the claim fails (70% chance)
        if random.random() < 0.7:
            db.session.delete(claimer)
            db.session.commit()



def process_territory_payouts():
    """
    Pays out territory income to the owning crew's bank_balance every 24 hours.
    Only pays if 24 hours have passed since last_payout.
    Updates last_payout timestamp.
    """
    now = datetime.utcnow()
    territories = Territory.query.all()
    for territory in territories:
        # Only pay out if territory has an owner crew and a payout value
        if not territory.owner_crew_id or not hasattr(territory, 'payout'):
            continue

        # Check if 24 hours have passed since last payout (or never paid out)
        if territory.last_payout is None or (now - territory.last_payout) >= timedelta(hours=24):
            crew = Crew.query.get(territory.owner_crew_id)
            if crew:
                # Ensure bank_balance is not None
                if crew.bank_balance is None:
                    crew.bank_balance = 0
                # Ensure payout is a valid number
                payout_amount = getattr(territory, 'payout', 0) or 0
                crew.bank_balance += payout_amount
                territory.last_payout = now
    db.session.commit()


def randomize_all_drug_prices():
    
    from models.constants import DRUG_LIST
    for city in CITIES:
        for name, drug_type in DRUG_LIST:
            drug = Drug.query.filter_by(name=name).first()
            if not drug:
                continue
            dealer = DrugDealer.query.filter_by(city=city, drug_id=drug.id).first()
            price = random.randint(250, 10000)
            stock = random.randint(250, 500)
            if not dealer:
                dealer = DrugDealer(city=city, drug_id=drug.id, price=price, stock=stock)
                db.session.add(dealer)
            else:
                dealer.price = price
                dealer.stock = stock
    db.session.commit()



def update_crew_member_count(Crew):
    for cm in CrewMember.query.all():
        char = Character.query.filter_by(master_id=cm.user_id, is_alive=True).first()
        if not char or not char.crew_id or char.crew_id != cm.crew_id:
            db.session.delete(cm)
    db.session.commit()

def seed_territories():
    from models.territory import Territory
    from extensions import db
    grid_size = 20
    for x in range(grid_size):
        for y in range(grid_size):
            if not Territory.query.filter_by(x=x, y=y).first():
                t = Territory(x=x, y=y)
                db.session.add(t)
    db.session.commit()


def seed_drugs():
    DRUG_LIST = [
        ("Cocaine", "Cocaine"),
        ("Heroin", "Heroin"),
        ("Methamphetamine", "Methamphetamine"),
        ("Ecstasy", "Ecstasy"),
        ("LSD", "LSD"),
        ("Marijuana", "Marijuana"),
        ("Opium", "Opium"),
        ("Crack", "Crack"),
        ("Speed", "Speed"),
        ("Mushrooms", "Mushrooms"),
    ]
    for name, drug_type in DRUG_LIST:
        if not Drug.query.filter_by(name=name).first():
            db.session.add(Drug(name=name, drug_type=drug_type))
    db.session.commit()

def notify_admin_duplicate_ip(user, admin_logger):
    same_ip_users = User.query.filter(
        User.last_known_ip == user.last_known_ip,
        User.id != user.id
    ).all()
    if same_ip_users:
        admin_logger.warning(
            f"Duplicate IP detected: User '{user.username}' (ID {user.id}) shares IP {user.last_known_ip} with: " +
            ", ".join([f"{u.username} (ID {u.id})" for u in same_ip_users])
        )

def allowed_file(filename, allowed_extensions):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return (
        test_url.scheme in ('http', 'https') and
        ref_url.netloc == test_url.netloc
    )

def limiter_key_func():
    if request.remote_addr in ('127.0.0.1', '::1'):
        return 'localhost'
    return get_remote_address() or 'localhost'

def generate_unique_invite_code(length=6):
    while True:
        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
        if not OrganizedCrime.query.filter_by(invite_code=code).first():
            return code

def is_on_crime_cooldown(character, cooldown_minutes=360):
    if character.last_crime_time:
        return datetime.utcnow() < character.last_crime_time + timedelta(minutes=cooldown_minutes)
    return False

def release_expired_jail():
    now = datetime.utcnow()
    expired = Character.query.filter(
        Character.in_jail == True,
        Character.jail_until != None,
        Character.jail_until <= now
    ).all()
    for char in expired:
        char.in_jail = False
        char.jail_until = None
    if expired:
        db.session.commit()

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not getattr(current_user, 'is_admin', False):
            flash("Admin access required.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def render_bio(bio):
    if not bio:
        return "No bio set yet."
    lines = escape(bio).split('\n')
    lines = [Markup(urlize(line, nofollow=True, target='_blank')) for line in lines]
    return Markup('<br>').join(lines)

def send_notification(user_id, message):
    notif = Notification(user_id=user_id, message=message)
    db.session.add(notif)
    db.session.commit()