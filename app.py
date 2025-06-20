
from ast import And
from calendar import c
from doctest import master
from email import message
from sys import maxsize
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_admin.contrib.sqla import ModelView
from flask_admin import expose, Admin, AdminIndexView, BaseView
from flask_admin.form import SecureForm, BaseForm
from flask_migrate import Migrate
from wtforms import PasswordField, StringField, BooleanField, IntegerField
from wtforms.fields import DateTimeField
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from sqlalchemy import true
from operator import is_
from email.mime import base
import sqlite3, string, logging, random
import os


log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)





# Database -------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB max file size
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

db = SQLAlchemy(app)
with app.app_context():
    db.create_all()
migrate = Migrate(app, db)
DATABASE = 'users.db'
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@app.context_processor
def inject_user():
    return dict(user=current_user)

@app.before_request
def update_last_seen():
    if current_user.is_authenticated:
        now = datetime.utcnow()
        if not current_user.last_seen or (now - current_user.last_seen).seconds > 1:
            current_user.last_seen = now
            db.session.commit()

@app.before_request
def enable_sqlite_fk():
    if db.engine.url.drivername == 'sqlite':
        with db.engine.connect() as conn:
            conn.execute(db.text("PRAGMA foreign_keys=ON"))

@app.before_request
def check_character_alive():
    if current_user.is_authenticated:
        char = Character.query.filter_by(master_id=current_user.id).first()
        if not char or not char.is_alive:
            if request.endpoint not in ('create_character', 'logout', 'static'):
                return redirect(url_for('create_character'))

#Models -------------------------------

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(12), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    crew_id = db.Column(db.Integer, db.ForeignKey('crew.id'), nullable=True)
    
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_earned = db.Column(db.DateTime, default=None, nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    premium = db.Column(db.Boolean, default=False)
    premium_until = db.Column(db.DateTime, nullable=True)
    last_known_ip = db.Column(db.String(45))
    organized_crime_id = db.Column(db.Integer, db.ForeignKey('organized_crime.id'))
    last_crime_time = db.Column(db.DateTime, nullable=True)
    gun_id = db.Column(db.Integer, db.ForeignKey('shop_item.id'), nullable=True)
    gun = db.relationship('ShopItem', foreign_keys=[gun_id])
    character = db.relationship('Character', backref='master', uselist=False, foreign_keys='Character.master_id')
    kills = db.Column(db.Integer, default=0)
    # Characters owned by this user
    characters = db.relationship('Character', backref='owner', lazy=True,
                                 foreign_keys='Character.master_id')

    # Optional: characters linked for crew, etc.
    linked_characters = db.relationship('Character', foreign_keys='Character.user_id')

    def __repr__(self):
        return f'<User {self.username}>'

    def add_xp(self, amount):
        self.xp += amount
        # Maybe also increase level if xp passes a threshold
        while self.xp >= self.level * 250:
            self.xp -= self.level * 250
            self.level += 1

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
class Character(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    
    # The actual owner of the character
    master_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Optional user_id for linking in crews or alt usage
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    # Character attributes
    name = db.Column(db.String(12), nullable=False)
    health = db.Column(db.Integer, default=100)
    money = db.Column(db.Integer, default=0)
    level = db.Column(db.Integer, default=1)
    xp = db.Column(db.Integer, default=0)
    earn_streak = db.Column(db.Integer, default=0)
    last_earned = db.Column(db.DateTime, nullable=True)
    is_alive = db.Column(db.Boolean, default=True)
    user = db.relationship('User', backref='linked_character', foreign_keys=[user_id])
    gun_id = db.Column(db.Integer, db.ForeignKey('shop_item.id'))
    profile_image = db.Column(db.String(255), nullable=True)
    crew = db.Column(db.Integer, db.ForeignKey('crew.id'), nullable=True)
    crew_id = db.Column(db.Integer, db.ForeignKey('crew.id'))
    # Linked user (e.g., for crew systems)
    linked_user = db.relationship('User', foreign_keys=[user_id])

    gun = db.relationship('ShopItem', foreign_keys=[gun_id])

class CharacterEditForm(SecureForm):
    name = StringField('Name')
    health = IntegerField('Health')
    money = IntegerField('Money')
    level = IntegerField('Level')
    xp = IntegerField('XP')
    is_alive = BooleanField('Is Alive', default=True)
    profile_image = StringField('Profile Image URL')

class UserEditForm(SecureForm):
    username = StringField('Username')
    password = PasswordField('Password')
    crew_id = StringField('Crew ID')
    is_admin = BooleanField('Is Admin')
    premium = BooleanField('Premium User')
    premium_until = DateTimeField('Premium Until', format='%Y-%m-%d %H:%M:%S')

class CrewMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    crew_id = db.Column(db.Integer, db.ForeignKey('crew.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    role = db.Column(db.String(20), default='member')  # leader, right_hand, left_hand, member

    crew = db.relationship('Crew', backref='crew_members')
    
    
    user = db.relationship('User', backref='crew_roles')

class OrganizedCrime(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    invite_code = db.Column(db.String(8), unique=True, nullable=False)
    leader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    leader = db.relationship('User', foreign_keys=[leader_id], backref='led_crime_family')
    members = db.relationship('User', backref='crime_group', lazy=True, foreign_keys='User.organized_crime_id')


    def is_full(self):
        return len(self.members) >= 4
    
class ShopItemModelView(ModelView):
    can_create = True
    can_edit = True
    can_delete = True
    can_view_details = True
    column_list = ('id', 'name', 'description', 'price', 'stock', 'is_gun', 'damage')  # Add is_gun and damage
    form_columns = ('name', 'description', 'price', 'stock', 'is_gun', 'damage')
    column_searchable_list = ('name', 'description')
    is_gun = BooleanField('Is Gun', default=False)
    damage = IntegerField('Damage', default=0)

class ShopItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    description = db.Column(db.String(256))
    price = db.Column(db.Integer, nullable=False)
    stock = db.Column(db.Integer, nullable=False, default=0)
    is_gun = db.Column(db.Boolean, default=False)
    damage = db.Column(db.Integer, default=0)


class UserInventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('shop_item.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1, nullable=False)

    user = db.relationship('User', backref='inventory')
    item = db.relationship('ShopItem')



class Gun(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32))
    damage = db.Column(db.Integer)
    

class CharacterModelView(ModelView):
    column_list = ('id', 'name', 'master_id', 'health', 'money', 'level', 'is_alive')
    form_columns = ('name', 'master_id', 'health', 'money', 'level', 'is_alive')


class UserModelView(ModelView):
    column_searchable_list = ('username',)
    can_create = True
    can_edit = True
    can_delete = False
    can_view_details = True
    form = UserEditForm

    form_excluded_columns = ['password_hash', 'last_seen', 'last_earned']
    form_columns = ['username', 'crew_id', 'is_admin', 'premium', 'xp', 'level', 'money', 'health', 'gun_id']  # <-- Add 'level'
    column_list = ('id', 'username', 'crew_id', 'last_seen', 'is_admin','premium', 'premium_until', 'last_known_ip')

    def is_accessible(self):
        return current_user.is_authenticated and getattr(current_user, 'is_admin', False)

    def on_model_change(self, form, model, is_created):
        if form.password.data:
            model.set_password(form.password.data)
        if form.xp.data is not None:
            model.xp = form.xp.data
            # Reset level and recalculate based on XP
            model.level = 1
            while model.xp >= model.level * 250:
                model.xp -= model.level * 250
                model.level += 1
        if form.level.data is not None:
            model.level = form.level.data  # <-- Allow manual level set

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))

class Crew(db.Model):
    __tablename__ = 'crew'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    members = db.relationship('User', backref='crew', lazy=True)

class CrewMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    crew_id = db.Column(db.Integer, db.ForeignKey('crew.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.now())
    
    user = db.relationship('User', backref='messages')

class ChatMessage(db.Model):
    timestamp = db.Column(db.DateTime, default=db.func.now())
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    channel = db.Column(db.String(10), default='public')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='chat_messages')

class CrewInvitation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    inviter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    invitee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    crew_id = db.Column(db.Integer, db.ForeignKey('crew.id'), nullable=False)
    inviter = db.relationship('User', foreign_keys=[inviter_id])
    invitee = db.relationship('User', foreign_keys=[invitee_id])
    crew = db.relationship('Crew')

def generate_invite_code(length=6):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def is_on_crime_cooldown(user, cooldown_hours=6):
    if user.last_crime_time:
        return datetime.utcnow() < user.last_crime_time + timedelta(hours=cooldown_hours)
    return False

# Admin Interface -------------------------------
class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated and getattr(current_user, 'is_admin', False)
    
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))
# Routes -------------------------------
@app.route('/')
def home():
    return redirect(url_for('dashboard'))

@app.route('/fix_crew_members')
def fix_crew_members():
    users = {u.id for u in User.query.all()}
    broken = CrewMember.query.filter(~CrewMember.user_id.in_(users)).all()

    for b in broken:
        db.session.delete(b)

    db.session.commit()
    return f"Removed {len(broken)} broken crew member entries."

@app.route('/organized_crime/attempt', methods=['POST'])
@login_required
def attempt_organized_crime():
    crime = current_user.crime_group
    if not crime:
        flash("You are not in a crime group.", "danger")
        return redirect(url_for('dashboard'))

    if current_user.id != crime.leader_id:
        flash("Only the group leader can start the crime.", "danger")
        return redirect(url_for('dashboard'))

    members = crime.members
    if len(members) < 2:
        flash("You need at least 2 members to attempt the crime.", "warning")
        return redirect(url_for('dashboard'))

    # Crime logic (random success)
    import random
    success = random.choice([True, False])
    reward_money = random.randint(500, 1500) if success else 0
    reward_xp = random.randint(10, 30) if success else 0

    for member in members:
        if member.character:
            if success:
                member.character.money += reward_money
                member.character.xp += reward_xp
            member.last_crime_time = datetime.utcnow()
            member.organized_crime_id = None  # Disband

    db.session.delete(crime)
    db.session.commit()

    if success:
        flash(f"Crime successful! Each member earned ${reward_money} and {reward_xp} XP.", "success")
    else:
        flash("Crime failed! The crew has disbanded.", "danger")

    return redirect(url_for('dashboard'))

@app.route('/crew/<int:crew_id>')
@login_required
def crew_page(crew_id):
    crew = Crew.query.get_or_404(crew_id)
    members = CrewMember.query.filter_by(crew_id=crew.id).all()
    messages = CrewMessage.query.filter_by(crew_id=crew.id).order_by(CrewMessage.timestamp.desc()).limit(50).all()
    my_role = next((m.role for m in members if m.user_id == current_user.id), None)
    return render_template('crew_page.html', crew=crew, members=members, messages=messages, current_user_role=my_role)

@app.route('/crew_member/<int:crew_member_id>/update_role', methods=['POST'])
@login_required
def update_crew_role(crew_member_id):
    crew_member = CrewMember.query.get_or_404(crew_member_id)
    target_user_id = crew_member.user_id
    target_crew_id = crew_member.crew_id

    # Get current user's own crew role
    my_role = CrewMember.query.filter_by(user_id=current_user.id, crew_id=target_crew_id).first()
    if not my_role or my_role.role not in ['leader', 'right_hand', 'left_hand']:
        flash("You don't have permission to change roles.", "danger")
        return redirect(url_for('crew_page', crew_id=target_crew_id))

    new_role = request.form.get('new_role')

    # Prevent self-demotion or role change
    if target_user_id == current_user.id:
        flash("You can't change your own role.", "danger")
        return redirect(url_for('crew_page', crew_id=target_crew_id))

    # Prevent anyone but the Leader from changing the Leader's role
    if crew_member.role == 'leader' and my_role.role != 'leader':
        flash("Only the leader can change the leader's role.", "danger")
        return redirect(url_for('crew_page', crew_id=target_crew_id))

    # Prevent Right/Left Hands from assigning the leader role
    if my_role.role != 'leader' and new_role == 'leader':
        flash("Only the leader can assign the leader role.", "danger")
        return redirect(url_for('crew_page', crew_id=target_crew_id))

    crew_member.role = new_role
    db.session.commit()
    flash("Role updated.", "success")
    return redirect(url_for('crew_page', crew_id=target_crew_id))



@app.route('/kill/<username>', methods=['POST'])
@login_required
def kill(username):
    # Ensure the current user has a living character
    if not current_user.character or not current_user.character.is_alive:
        flash("You need a living character to attack!", "danger")
        return redirect(url_for('dashboard'))

    # Look up target user or NPC by username
    user = User.query.filter_by(username=username).first()
    if user:
        character = Character.query.filter_by(master_id=user.id, is_alive=True).first()
    else:
        # It's an NPC, get by name and NPC master ID
        npc_master = User.query.filter_by(username="NPC").first()
        character = Character.query.filter_by(name=username, master_id=npc_master.id, is_alive=True).first()

    if not character:
        flash("Target not found or already dead.", "danger")
        return redirect(url_for('dashboard'))

    # Prevent killing your own character
    if character.master_id == current_user.id:
        flash("You can't kill your own character!", "danger")
        return redirect(url_for('dashboard'))

    # Ensure player has a gun equipped
    if not current_user.gun:
        flash("You don't have a gun equipped!", "danger")
        return redirect(url_for('profile', username=username))

    # Apply damage
    character.health -= current_user.gun.damage
    killed = False

    if character.health <= 0:
        character.is_alive = False
        killed = True
        flash(f"You killed {character.name}!", "success")
    else:
        flash(f"You shot {character.name}!", "success")

    # Commit changes
    db.session.commit()

    # Update kill count if target was killed
    if killed:
        
        current_user.kills = (current_user.kills or 0) + 1
        db.session.commit()

    return redirect(url_for('profile', username=username))

# ...existing code...
@app.route('/shop', methods=['GET', 'POST'])
@login_required
def shop():
    items = ShopItem.query.all()
    message = None
    # Get the current user's character
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    if request.method == 'POST':
        item_id = request.form.get('item_id')
        item = ShopItem.query.get(item_id)
        if not character:
            message = "No character found."
        elif item and character.money >= item.price and item.stock > 0:
            character.money -= item.price
            item.stock -= 1

            # Add to inventory or increment quantity
            inventory_item = UserInventory.query.filter_by(user_id=current_user.id, item_id=item.id).first()
            if inventory_item:
                inventory_item.quantity += 1
            else:
                inventory_item = UserInventory(user_id=current_user.id, item_id=item.id, quantity=1)
                db.session.add(inventory_item)

            # If it's a gun, equip it
            if item.is_gun:
                current_user.gun_id = item.id
                message = f"You bought and equipped {item.name}!"
            else:
                message = f"You bought {item.name} for ${item.price}!"

            db.session.commit()
        elif item and item.stock <= 0:
            message = "Sorry, this item is out of stock."
        else:
            message = "Not enough money or item not found."
    return render_template('shop.html', items=items, message=message, character=character)


@app.route('/inventory', methods=['GET', 'POST'])
@login_required
def inventory():
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    if not character:
        flash("No character found.", "danger")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        item_id = int(request.form.get('item_id'))
        inventory_item = UserInventory.query.filter_by(user_id=current_user.id, item_id=item_id).first()
        item = ShopItem.query.get(item_id)

        if not inventory_item or not item:
            flash("Item not found in your inventory.", 'danger')
            return redirect(url_for('inventory'))

        sell_price = item.price // 2
        character.money += sell_price
        inventory_item.quantity -= 1

        # If it's the equipped gun, unequip it
        if current_user.gun_id == item.id:
            current_user.gun_id = None
            flash(f"You sold your equipped gun: {item.name}.", "info")

        if inventory_item.quantity <= 0:
            db.session.delete(inventory_item)

        # ✅ Add back to shop (increase stock)
        item.stock += 1

        db.session.commit()
        flash(f"Sold 1x {item.name} for ${sell_price}.", "success")
        return redirect(url_for('inventory'))

    
    inventory_items = UserInventory.query.filter_by(user_id=current_user.id).all()

    return render_template('inventory.html', inventory_items=inventory_items, character=character)

@app.route("/users_online")
@login_required
def users_online():
    cutoff = datetime.utcnow() - timedelta(minutes=1)
    users = User.query.filter(User.last_seen >= cutoff).all()

    # For each user, find their *first alive character* (you can tweak this logic as needed)
    user_character_map = {}
    for user in users:
        character = Character.query.filter_by(master_id=user.id, is_alive=True).first()
        if character:
            user_character_map[character.id] = character.name
        else:
            user_character_map[user.id] = user.username  # fallback

    return render_template("users_online.html", users=users, char_map=user_character_map)

@app.route('/player_search', methods=['GET', 'POST'])
@login_required
def player_search():
    results = []
    query = ""
    if request.method == 'POST':
        query = request.form.get('query', '').strip()
        if query:
            # Exclude self from results
            results = Character.query.filter(
                Character.name.ilike(f"%{query}%"),
                Character.name != current_user.id
            ).all()
    return render_template('player_search.html', results=results, query=query)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return redirect(url_for('register'))
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registered successfully. Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/send_crew_message', methods=['POST'])
@login_required
def send_crew_message():
    if not current_user.crew:
        return jsonify({'error': 'Not in a crew'}), 403

    message = request.form.get('message', '').strip()
    if not message:
        return jsonify({"error": "Empty message"}), 400
    chat_msg = ChatMessage(username=current_user.username, message=message, channel='public')
    db.session.add(chat_msg)
    db.session.commit()
    return jsonify(success=True)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            user.last_known_ip = request.remote_addr
            db.session.commit()
            return redirect(url_for('dashboard'))
        flash('Invalid credentials.')
    return render_template('login.html')

@app.route('/create_character', methods=['GET', 'POST'])
@login_required
def create_character():
    if request.method == 'POST':
        char_name = request.form.get('character_name', '').strip()
        if not char_name:
            flash("Character name is required.", "danger")
            return render_template('create_character.html')
        # Optionally check for duplicate names or add more validation here
        new_char = Character(
            master_id=current_user.id,
            name=char_name,
            health=100,
            money=0,
            level=1,
            is_alive=True
        )
        db.session.add(new_char)
        db.session.commit()
        flash("New character created!", "success")
        return redirect(url_for('dashboard'))
    return render_template('create_character.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/crew_chat')
@login_required
def crew_chat():
    return render_template('crew_chat.html')

@app.route('/get_messages')
@login_required
def get_messages():
    if not current_user.crew:
        return jsonify(success=False, error="Not in a crew"), 403

    messages = CrewMessage.query.filter_by(crew_id=current_user.crew.id)\
                                .order_by(CrewMessage.timestamp.desc())\
                                .limit(50).all()
    messages = ChatMessage.query.filter_by(crew_id=current_user.crew.id)\
                                .order_by(CrewMessage.timestamp.desc())\
                                .limit(50).all()
    return jsonify(messages=[{
        'username': msg.user.username,
        'message': msg.message,
        'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M:%S')
    } for msg in reversed(messages)]) 

@app.route('/join_crew', methods=['GET', 'POST'])
@login_required
def join_crew():
    if request.method == 'POST':
        crew_id = int(request.form['crew_id'])
        current_user.crew_id = crew_id
        db.session.commit()
        flash("You joined the crew!")
        return redirect(url_for('dashboard'))

    crews = Crew.query.all()
    invitations = CrewInvitation.query.filter_by(invitee_id=current_user.id).all()
    return render_template('notifications.html', crews=crews, invitations=invitations)

@app.route('/leave_crew', methods=['POST', 'GET'])
@login_required
def leave_crew():
    current_user.crew_id = None
    db.session.commit()
    flash("You left the crew!")
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Update last seen time
    current_user.last_seen = datetime.utcnow()
    online_threshold = datetime.utcnow() - timedelta(seconds=1)
    online_users = current_user.query.filter(User.last_seen >= online_threshold).all()
    crew = current_user.crew if hasattr(current_user, 'crew') else None
    
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    npcs = Character.query.filter_by(master_id=0, is_alive=True).all()
    online_users = current_user.query.all()  # however you get this list
    
    
    user_ids = [user.id for user in online_users]
    characters = Character.query.filter(Character.master_id.in_(user_ids), Character.is_alive == True).all()
    char_map = {char.master_id: char for char in characters}
    return render_template(
        "dashboard.html",
        current_character=character,
        online_users=online_users,
        char_map=char_map,
        user=current_user,
        crew=crew,
        npcs=npcs
    )

@app.route('/refresh_shop')
def refresh_shop():
    # Clear current shop if you want it to reset
    ShopItem.query.delete()

    # Choose random guns
    guns = Gun.query.all()
    random_guns = random.sample(guns, k=min(5, len(guns)))  # 5 random guns or fewer

    for gun in random_guns:
        item = ShopItem(gun=gun)
        db.session.add(item)

    db.session.commit()
    return {'success': True, 'message': f'{len(random_guns)} guns added to the shop.'}

@app.route('/invite_to_crew', methods=['GET', 'POST'])
@login_required
def invite_to_crew():
    if not current_user.crew:
        flash("You must be in a crew to invite others.")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        if not username:
            flash("Username is required.")
            return redirect(url_for('invite_to_crew'))

        invitee = User.query.filter_by(username=username).first()
        if not invitee:
            flash("User not found.")
            return redirect(url_for('invite_to_crew'))

        if invitee.crew:
            flash("User is already in a crew.")
            return redirect(url_for('invite_to_crew'))

        existing_invite = CrewInvitation.query.filter_by(invitee_id=invitee.id, crew_id=current_user.crew.id).first()
        if existing_invite:
            flash("Invite already sent.")
            return redirect(url_for('invite_to_crew'))

        invite = CrewInvitation(inviter_id=current_user.id, invitee_id=invitee.id, crew_id=current_user.crew.id)
        db.session.add(invite)
        db.session.commit()
        flash("Invite sent!")
        return redirect(url_for('dashboard'))

    return render_template('invite_to_crew.html', crew=current_user.crew)

@app.route('/create_crime', methods=['GET', 'POST'])
@login_required
def create_crime():
    if current_user.crime_group:
        return redirect(url_for('crime_group'))
    
    if current_user.crime_group:
        flash("You're already in a crime group!", 'warning')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        invite_code = generate_invite_code()
        crime = OrganizedCrime(leader_id=current_user.id, invite_code=invite_code)
        current_user.crime_group = crime  # add creator to group
        db.session.add(crime)
        db.session.commit()
        flash(f"Crime group created! Invite code: {invite_code}", 'success')
        return redirect(url_for('crime_group'))
    if is_on_crime_cooldown(current_user):
        wait_time = (current_user.last_crime_time + timedelta(hours=6)) - datetime.utcnow()
        flash(f"You must wait {wait_time.seconds // 3600}h {((wait_time.seconds // 60) % 60)}m before starting a new crime group.", "warning")
        return redirect(url_for('dashboard'))
    
    return render_template('create_crime.html')

@app.route('/join_crime', methods=['GET', 'POST'])
@login_required
def join_crime():
    if current_user.crime_group:
        flash("You're already in a crime group!", 'warning')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        code = request.form.get('invite_code').strip().upper()
        crime = OrganizedCrime.query.filter_by(invite_code=code).first()
        if not crime:
            flash("Invalid invite code.", 'danger')
        elif crime.is_full():
            flash("That crime group is full!", 'warning')
        else:
            current_user.crime_group = crime
            db.session.commit()
            flash("You joined the crime group!", 'success')
            return redirect(url_for('crime_group'))
    if is_on_crime_cooldown(current_user):
        wait_time = (current_user.last_crime_time + timedelta(hours=6)) - datetime.utcnow()
        flash(f"You must wait {wait_time.seconds // 3600}h {((wait_time.seconds // 60) % 60)}m before starting a new crime group.", "warning")
        return redirect(url_for('dashboard'))
    return render_template('join_crime.html')

@app.route('/crime_group')
@login_required
def crime_group():
    crime = current_user.crime_group
    if not crime:
        flash("You're not part of any crime group yet.", 'info')
        return redirect(url_for('dashboard'))
    
    members = User.query.filter_by(organized_crime_id=crime.id).all()
    return render_template('crime_group.html', crime=crime, members=members)

@app.route('/upload_profile_image', methods=['GET', 'POST'])
@login_required
def upload_profile_image():
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    if not character:
        flash("You don't have permission to upload a profile image.", "danger")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        file = request.files.get('profile_image')
        if file and allowed_file(file.filename):
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            filename = secure_filename(f"{current_user.id}_{file.filename}")
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            character.profile_image = f'uploads/{filename}'
            db.session.commit()

            flash('Profile image updated!', 'success')
            return redirect(url_for('profile', username=current_user.username))
        else:
            flash('Invalid file type.', 'danger')
    return render_template('upload_profile_image.html')

@app.route('/crew_messages')
@login_required
def crew_messages():
    if not current_user.crew:
        return jsonify([])

    messages = CrewMessage.query.filter_by(crew_id=current_user.crew.id)\
        .order_by(CrewMessage.timestamp.desc()).limit(50).all()

    return jsonify([{
        'username': msg.user.username,
        'message': msg.message,
        'timestamp': msg.timestamp.strftime('%H:%M')
    } for msg in reversed(messages)])  # return oldest first

@app.route('/crew_invitations')
@login_required
def crew_invitations():
    invitations = CrewInvitation.query.filter_by(invitee_id=current_user.id.name).all()
    return render_template('crew_invitations.html', invitations=invitations)

@app.route('/accept_invite/<int:invite_id>')
@login_required
def accept_invite(invite_id):
    invitation = CrewInvitation.query.get(invite_id)
    if invitation and invitation.invitee_id == current_user.id:
        current_user.crew_id = invitation.crew_id
        CrewMember.query.filter_by(user_id=current_user.id).delete()
        db.session.add(CrewMember(crew_id=invitation.crew_id, user_id=current_user.id, role='member'))
        db.session.delete(invitation)
        db.session.commit()
        flash("You’ve joined the crew!")
    else:
        flash("Invalid invitation.")
    return redirect(url_for('dashboard'))

@app.route('/decline_invite/<int:invite_id>')
@login_required
def decline_invite(invite_id):
    invitation = CrewInvitation.query.get(invite_id)
    if invitation and invitation.invitee_id == current_user.id:
        db.session.delete(invitation)
        db.session.commit()
        flash("Invitation declined.")
    else:
        flash("Invalid invitation.")
    return redirect(url_for('dashboard'))

@app.route('/create_crew', methods=['GET', 'POST'])
@login_required
def create_crew():
    MIN_LEVEL = 15
    CREW_COST = 1000000

    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    if not character:
        flash("You must have a character to create a crew.", "danger")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        crew_name = request.form.get('crew_name', '').strip()
        if Crew.query.filter_by(name=crew_name).first():
            flash("Crew name already exists.")
            return redirect(url_for('create_crew'))

        if character.level < MIN_LEVEL:
            flash(f"You must be at least level {MIN_LEVEL} to create a crew.")
            return redirect(url_for('create_crew'))

        if character.money < CREW_COST:
            flash(f"You need at least ${CREW_COST} to create a crew.")
            return redirect(url_for('create_crew'))

        # Deduct money and create crew
        character.money -= CREW_COST
        new_crew = Crew(name=crew_name)
        db.session.add(new_crew)
        db.session.commit()

        # Insert creator as leader
        crew_member = CrewMember(crew_id=new_crew.id, user_id=current_user.id, role='leader')
        db.session.add(crew_member)
        current_user.crew_id = new_crew.id
        db.session.commit()

        flash(f"Crew created and joined! You spent ${CREW_COST}.", "success")
        return redirect(url_for('dashboard'))

    return render_template('create_crew.html')

@app.route('/earn')
@login_required
def earn():
    cooldown = timedelta(seconds=5)
    now = datetime.utcnow()
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    if not character:
        return jsonify({'success': False, 'message': "No character found."})

    # ✅ Make sure cooldown check works
    if character.last_earned and (now - character.last_earned) < cooldown:
        remaining = cooldown - (now - character.last_earned)
        seconds = divmod(int(remaining.total_seconds()), 60)
        return flash({
            'success': False,
            'message': f"Wait {seconds}s before earning again."
        })

    # Earnings and streak handling (unchanged)
    earned_money = random.randint(200, 2000)
    earned_xp = random.randint(20, 120)
    
    character.money += earned_money
    character.xp += earned_xp
    character.last_earned = now
    
    # Level-up
    while character.xp >= character.level * 250:
        character.xp -= character.level * 250
        character.level += 1

    # Streak and item reward
    character.earn_streak = (character.earn_streak or 0) + 1
    reward_msg = ""
    
    # 🎲 Chance to find a random item (20% chance)
    if random.random() < 0.2:
        possible_items = ShopItem.query.filter(ShopItem.stock > 0).all()
        if possible_items:
            found_item = random.choice(possible_items)
            inventory = UserInventory.query.filter_by(user_id=current_user.id, item_id=found_item.id).first()
            if inventory:
                inventory.quantity += 1
            else:
                db.session.add(UserInventory(user_id=current_user.id, item_id=found_item.id, quantity=1))

            # Optional: auto-equip if it's a gun and player has none
            if found_item.is_gun and not character.gun_id:
                character.gun_id = found_item.id

            reward_msg = f" You found a {found_item.name}!"

    # 🔁 Reset streak every 3 earns, and guarantee a Starter Pistol
    if character.earn_streak >= 30:
        starter = ShopItem.query.filter_by(name='Starter Pistol').first()
        if starter:
            inventory = UserInventory.query.filter_by(user_id=current_user.id, item_id=starter.id).first()
            if inventory:
                inventory.quantity += 1
            else:
                db.session.add(UserInventory(user_id=current_user.id, item_id=starter.id, quantity=1))

            if not character.gun_id:
                character.gun_id = starter.id

            reward_msg += f" You also received a {starter.name} for your streak!"
            character.earn_streak = 0
            
    db.session.commit()
    flash(f"You earned ${earned_money} and {earned_xp} XP" + reward_msg, "success")

    return jsonify({'success': True})

@app.route('/user_stats')
@login_required
def user_stats():
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    if not character:
        return jsonify(money=0, xp=0, level=1)
    return jsonify(
        money=character.money,
        xp=character.xp,
        level=character.level
    )

@app.route('/earn_status')
@login_required
def earn_status():
    cooldown = timedelta(minutes=2, seconds=10)
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()

    if not character:
        return jsonify({'seconds_remaining': 0})

    if character.last_earned:
        elapsed = datetime.utcnow() - character.last_earned
        remaining = cooldown - elapsed
        seconds_remaining = max(0, int(remaining.total_seconds()))
    else:
        seconds_remaining = 0

    return jsonify({'seconds_remaining': seconds_remaining})

@app.route('/upgrade', methods=['POST'])
@login_required
def upgrade():
    PREMIUM_COST = 1500000
    PREMIUM_DAYS = 30
    now = datetime.utcnow()

    # Get the active character
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    if not character:
        flash("You must have a character to upgrade to premium.", "danger")
        return redirect(url_for('dashboard'))

    # Check if character has enough money
    if character.money < PREMIUM_COST:
        flash(f'You need at least ${PREMIUM_COST} to upgrade to premium.', 'danger')
        return redirect(url_for('dashboard'))

    # Deduct money from character
    character.money -= PREMIUM_COST

    # Update user's premium status
    if current_user.premium_until and current_user.premium_until > now:
        current_user.premium_until += timedelta(days=PREMIUM_DAYS)
    else:
        current_user.premium_until = now + timedelta(days=PREMIUM_DAYS)
        current_user.premium = True

    db.session.commit()
    flash(f'Your account has been upgraded to premium for {PREMIUM_DAYS} days for ${PREMIUM_COST}!', 'success')
    return redirect(url_for('dashboard'))


@app.route('/profile/<username>')
def profile(username):
    # Try to find a real user first
    user = User.query.filter_by(username=username).first()
    if user:
        character = Character.query.filter_by(master_id=user.id, is_alive=True).first()
        if not character:
            # If user exists but has no living character, show their dashboard
            return render_template('dashboard.html', user=user, character=None, crew=None)
        
    else:
        character = Character.query.filter_by(name=username, master_id=0).first()
        return render_template('dashboard.html', user=user, character=character, crew=character.crew if character else None)

    # If not found, try to find an NPC by name
    if not user and not character:
        npc_master = User.query.filter_by(username="NPC").first()
        if npc_master:
            character = Character.query.filter_by(name=username, master_id=npc_master.id, is_alive=True).first()
    
    if not character:
        return render_template('404.html')
    # Not found
    return render_template('profile.html', user=user, character=character)

@app.route('/create_fake_profile', methods=['GET', 'POST'])
@login_required
def create_fake_profile():
    npc_price = 150000
    npc_level = 10  # Cost to create a fake NPC profile
    npc_user = User.query.filter_by(username="NPC").first()

    if not npc_user:
        npc_user = User(
            username="NPC",
            is_admin=False,
            premium=False,
            password_hash="npc",  # Set something, but they won’t log in anyway
        )
        db.session.add(npc_user)
        db.session.commit()
        print("NPC user created.")

    # Step 2: Assign all orphan NPC characters to the dummy NPC user
    orphan_npcs = Character.query.filter_by(master_id=0).all()
    for npc in orphan_npcs:
        npc.master_id = npc_user.id
        npc.user_id = npc_user.id

    db.session.commit()
    print(f"Updated {len(orphan_npcs)} NPC(s) to link to user_id {npc_user.id}.")
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    if not character:
        flash("You must have a character to create a fake profile.", "danger")
        return redirect(url_for('dashboard'))

    if character.money < npc_price:
        flash("Not enough money to create a fake profile.", "danger")
        return redirect(url_for('dashboard'))

    if character.level < npc_level:
        flash(f"You must be at least level {npc_level} to create a fake profile.", "danger")
        return redirect(url_for('dashboard'))

    # Generate a unique name for the NPC
    npc_names = ['John Doe', 'Jane Smith', 'Alex Johnson', 'Chris Lee', 'Taylor Brown', 'Morgan Black', 'Riley Stone']
    attempts = 0
    max_attempts = 10
    while attempts < max_attempts:
        npc_name = random.choice(npc_names) + f" #{random.randint(100, 999)}"
        if not Character.query.filter_by(name=npc_name, master_id=0).first():
            break
        attempts += 1
    else:
        flash("Could not generate a unique NPC name. Try again later.", "danger")
        return redirect(url_for('dashboard'))

    character.money -= npc_price
    npc = Character(
        profile_image='uploads/default_npc.png',
        master_id=npc_user.id,  # NPCs have master_id=0
        name=npc_name,
        money=random.randint(200, 1000000000000),
        xp=random.randint(1, 500000),
        level=random.randint(1, 25),
        is_alive=True,
        health=100,
        user_id=npc_user.id,  # Link to the dummy NPC user
    )

    
    db.session.add(npc)
    db.session.commit()

    flash(f"Fake profile '{npc_name}' created for ${npc_price}!", "success")
    return redirect(url_for('dashboard'))

    # # For GET requests, show the creation form
    # return render_template('create_npc.html', npc_price=npc_price, npc_level=npc_level)

@app.route('/public_messages')
def public_messages():
    messages = ChatMessage.query.filter_by(channel='public').order_by(ChatMessage.timestamp.asc()).limit(50).all()
    return jsonify([{"username" : msg.username, "message": msg.message} for msg in messages])

@app.route('/send_public_message', methods=['POST'])
@login_required
def send_public_message():
    message = request.form.get('message', '').strip()
    if not message:
        return jsonify({"error": "Empty message"}), 400
    chat_msg = ChatMessage(username=current_user.username, message=message, channel='public')
    db.session.add(chat_msg)
    db.session.commit()
    return jsonify(success=True)

@app.context_processor
def inject_current_character():
    from flask_login import current_user
    if current_user.is_authenticated:
        character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
        return dict(current_character=character)
    return dict(current_character=None)
# Create DB (run once, or integrate with a CLI or shell)

admin = Admin(app, name='Admin Panel', template_mode='bootstrap4', index_view=MyAdminIndexView())
admin.add_view(ModelView(Character, db.session, endpoint='character_admin'))
admin.add_view(UserModelView(User, db.session, endpoint='admin_users'))
admin.add_view(ModelView(CrewMember, db.session))
admin.add_view(ModelView(UserInventory, db.session))
admin.add_view(ShopItemModelView(ShopItem, db.session))  # <-- use the new view here
admin.add_view(ModelView(Crew, db.session))
admin.add_view(ModelView(CrewMessage, db.session))
admin.add_view(ModelView(CrewInvitation, db.session))

@app.cli.command("init-db")
def init_db():
    db.create_all()
    print("Database tables created.")
    
@app.cli.command('create-admin')
def create_admin():
    user = User.query.filter_by(username='admin').first()
    if not user:
        user = User(username='admin')
        user.set_password('yep')
        user.is_admin = True
        db.session.add(user)
        db.session.commit()
        print("Admin user created.")
    else:
        user.is_admin = False
        db.session.commit()
        print("Admin user updated.")




def get_online_users():
    cutoff = datetime.utcnow() - timedelta(seconds=1)
    # Real users online
    real_online = current_user.name.query.filter(current_user.last_seen >= cutoff).all()
    # NPCs: Characters with master_id=0 (or whatever you use)
    npcs = Character.query.filter_by(master_id=0, is_alive=True).all()
    # Optionally, create a fake User object for each NPC if your template expects User
    return real_online, npcs

@app.cli.command("init-db")
def init_db():
    db.create_all()
    print("Database tables created.")


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
