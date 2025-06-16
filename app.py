from email.mime import base
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_admin import Admin
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
import random
import sqlite3
import os









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

migrate = Migrate(app, db)
DATABASE = 'users.db'
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@app.before_request
def update_last_seen():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        # Premium status auto-expiry
        if current_user.premium and current_user.premium_until and current_user.premium_until < datetime.utcnow():
            current_user.premium = False
            db.session.commit()
        db.session.commit()

@app.before_request
def check_character_alive():
    if current_user.is_authenticated:
        char = Character.query.filter_by(master_id=current_user.id).first()
        if not char or not char.is_alive:
            if request.endpoint not in ('create_character', 'logout', 'static'):
                return redirect(url_for('create_character'))

#Models -------------------------------
class MasterAccount(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    # Relationship to character(s)
    character = db.relationship('Character', backref='master', uselist=False)
    
class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    crew_id = db.Column(db.Integer, db.ForeignKey('crew.id'), nullable=True)
    xp = db.Column(db.Integer, default=0)
    level = db.Column(db.Integer, default=1)
    money = db.Column(db.Integer, default=0)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_earned = db.Column(db.DateTime, default=None, nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    premium = db.Column(db.Boolean, default=False)
    premium_until = db.Column(db.DateTime, nullable=True)
    last_known_ip = db.Column(db.String(45))
    health = db.Column(db.Integer, default=100)
    gun_id = db.Column(db.Integer, db.ForeignKey('shop_item.id'), nullable=True)
    gun = db.relationship('ShopItem', foreign_keys=[gun_id])
    character = db.relationship('Character', backref='user', uselist=False)
    kills = db.Column(db.Integer, default=0)


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
    
class UserEditForm(SecureForm):
    username = StringField('Username')
    password = PasswordField('Password')
    crew_id = StringField('Crew ID')
    is_admin = BooleanField('Is Admin')
    premium = BooleanField('Premium User')
    xp = IntegerField('XP')
    level = IntegerField('Level')
    money = IntegerField('Money', default=0, render_kw={"readonly": False})
    premium_until = DateTimeField('Premium Until', format='%Y-%m-%d %H:%M:%S')
    health = IntegerField('Health', default=100, render_kw={"readonly": False})
    gun_id = IntegerField('Equipped Gun ID', default=None, render_kw={"readonly": False})
    
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

class Character(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    master_id = db.Column(db.Integer, db.ForeignKey('master_account.id'), nullable=False)
    name = db.Column(db.String(32), nullable=False)
    health = db.Column(db.Integer, default=100)
    money = db.Column(db.Integer, default=0)
    level = db.Column(db.Integer, default=1)
    xp = db.Column(db.Integer, default=0)
    is_alive = db.Column(db.Boolean, default=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    gun_id = db.Column(db.Integer, db.ForeignKey('gun.id'), nullable=True)
    gun = db.relationship('Gun', backref='characters', uselist=False)
    profile_image = db.Column(db.String(256), nullable=True)


class Gun(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32))
    damage = db.Column(db.Integer)

class CharacterModelView(ModelView):
    column_list = ('id', 'name', 'master_id', 'health', 'money', 'level', 'is_alive')
    form_columns = ('name', 'master_id', 'health', 'money', 'level', 'is_alive')
# Admin -------------------------------

class UserModelView(ModelView):
    column_searchable_list = ('username',)
    can_create = True
    can_edit = True
    can_delete = False
    can_view_details = True
    form = UserEditForm

    form_excluded_columns = ['password_hash', 'last_seen', 'last_earned']
    form_columns = ['username', 'password', 'crew_id', 'is_admin', 'premium', 'xp', 'level', 'money', 'health', 'gun_id']  # <-- Add 'level'
    column_list = ('id', 'username', 'crew_id', 'xp', 'level', 'money', 'last_seen', 'is_admin','premium', 'premium_until', 'last_known_ip', 'health', 'gun_id')

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

class CrewInvitation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    inviter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    invitee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    crew_id = db.Column(db.Integer, db.ForeignKey('crew.id'), nullable=False)

    inviter = db.relationship('User', foreign_keys=[inviter_id])
    invitee = db.relationship('User', foreign_keys=[invitee_id])
    crew = db.relationship('Crew')


# customize admin homepage
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

@app.route('/crew/<int:crew_id>')
@login_required
def crew_page(crew_id):
    crew = Crew.query.get_or_404(crew_id)
    members = User.query.filter_by(crew_id=crew.id).all()
    messages = CrewMessage.query.filter_by(crew_id=crew.id).order_by(CrewMessage.timestamp.desc()).limit(50).all()
    return render_template('crew_page.html', crew=crew, members=members, messages=messages)

@app.route('/kill/<username>', methods=['POST'])
@login_required
def kill(username):
    # Find target: real user or NPC
    user = User.query.filter_by(username=username).first()
    if user:
        character = Character.query.filter_by(master_id=user.id, is_alive=True).first()
    else:
        character = Character.query.filter_by(name=username, master_id=0, is_alive=True).first()
    if not character:
        flash("Target not found.", "danger")
        return redirect(url_for('dashboard'))

    # Use current_user.gun (from ShopItem)
    if not current_user.gun or not character.is_alive:
        flash("You can't shoot!", "danger")
        return redirect(url_for('profile', username=username))

    character.health -= current_user.gun.damage
    killed = False
    if character.health <= 0:
        character.is_alive = False
        killed = True
        flash(f"You killed {character.name}!", "success")
    else:
            flash(f"You shot {character.name}!", "success")
            db.session.commit()
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
# ...existing code...

@app.route('/inventory')
@login_required
def inventory():
    inventory_items = UserInventory.query.filter_by(user_id=current_user.id).all()
    return render_template('inventory.html', inventory_items=inventory_items)

@app.route('/users_online')
@login_required
def users_online():
    online_threshold = datetime.utcnow() - timedelta(minutes=5)
    online_users = User.query.filter(User.last_seen >= online_threshold).all()
    return jsonify([u.username for u in online_users])

@app.route('/player_search', methods=['GET', 'POST'])
@login_required
def player_search():
    results = []
    query = ""
    if request.method == 'POST':
        query = request.form.get('query', '').strip()
        if query:
            # Exclude self from results
            results = User.query.filter(
                User.username.ilike(f"%{query}%"),
                User.id != current_user.id
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
        return jsonify({'error': 'Empty message'}), 400

    crew_msg = CrewMessage(
        crew_id=current_user.crew.id,
        user_id=current_user.id,
        message=message
    )
    db.session.add(crew_msg)
    db.session.commit()

    return jsonify({'success': True})

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
    online_threshold = datetime.utcnow() - timedelta(minutes=5)
    online_users = User.query.filter(User.last_seen >= online_threshold).all()
    crew = current_user.crew if hasattr(current_user, 'crew') else None
    
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    npcs = Character.query.filter_by(master_id=0, is_alive=True).all()
    online_users = User.query.all()  # however you get this list
    
    
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

@app.route('/upload_profile_image', methods=['GET', 'POST'])
@login_required
def upload_profile_image():
    if request.method == 'POST':
        file = request.files.get('profile_image')
        if file and allowed_file(file.filename):
            filename = secure_filename(f"{current_user.id}_{file.filename}")
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            current_user.profile_image = f'uploads/{filename}'
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
    invitations = CrewInvitation.query.filter_by(invitee_id=current_user.id).all()
    return render_template('crew_invitations.html', invitations=invitations)

@app.route('/accept_invite/<int:invite_id>')
@login_required
def accept_invite(invite_id):
    invitation = CrewInvitation.query.get(invite_id)
    if invitation and invitation.invitee_id == current_user.id:
        current_user.crew_id = invitation.crew_id
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
    MIN_LEVEL = 15         # Set your required level here
    CREW_COST = 1000000      # Set your required money cost here

    if request.method == 'POST':
        crew_name = request.form.get('crew_name', '').strip()
        if Crew.query.filter_by(name=crew_name).first():
            flash("Crew name already exists.")
            return redirect(url_for('create_crew'))

        if current_user.level < MIN_LEVEL:
            flash(f"You must be at least level {MIN_LEVEL} to create a crew.")
            return redirect(url_for('create_crew'))

        if current_user.money < CREW_COST:
            flash(f"You need at least ${CREW_COST} to create a crew.")
            return redirect(url_for('create_crew'))

        # Deduct money and create crew
        current_user.money -= CREW_COST
        new_crew = Crew(name=crew_name)
        db.session.add(new_crew)
        db.session.commit()
        current_user.crew_id = new_crew.id
        db.session.commit()
        flash(f"Crew created and joined! You spent ${CREW_COST}.")
        return redirect(url_for('dashboard'))

    return render_template('create_crew.html')

@app.route('/earn')
@login_required
def earn():
    from datetime import datetime, timedelta
    import random

    cooldown = timedelta(seconds=10)
    now = datetime.utcnow()
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    if not character:
        return jsonify({'success': False, 'message': "No character found."})

    if current_user.last_earned and now - current_user.last_earned < cooldown:
        remaining = cooldown - (now - current_user.last_earned)
        minutes, seconds = divmod(remaining.seconds, 60)
        return jsonify({'success': False, 'message': f"Wait {minutes}m {seconds}s before earning again."})

    earned_money = random.randint(200, 2000)
    earned_xp = random.randint(20, 120)
    character.money += earned_money
    character.xp += earned_xp
    while character.xp >= character.level * 250:
        character.xp -= character.level * 250
        character.level += 1

    current_user.last_earned = now
    db.session.commit()
    return jsonify({'success': True, 'message': f"You earned ${earned_money} and {earned_xp} XP!"})

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
    cooldown = timedelta(minutes=2, seconds=30)
    now = datetime.utcnow()

    if current_user.last_earned:
        elapsed = now - current_user.last_earned
        remaining = cooldown - elapsed
        seconds_remaining = max(0, int(remaining.total_seconds()))
    else:
        seconds_remaining = 0

    return jsonify({'seconds_remaining': seconds_remaining})

@app.route('/upgrade', methods=['POST'])
@login_required
def upgrade():
    PREMIUM_COST = 1500000
    PREMIUM_DAYS = 30  # Set how many days premium lasts

    now = datetime.utcnow()
    # If already premium, extend time
    if current_user.premium_until and current_user.premium_until > now:
        current_user.premium_until += timedelta(days=PREMIUM_DAYS)
    else:
        current_user.premium_until = now + timedelta(days=PREMIUM_DAYS)
        current_user.premium = True

    if current_user.money < PREMIUM_COST:
        flash(f'You need at least ${PREMIUM_COST} to upgrade to premium.', 'danger')
        return redirect(url_for('dashboard'))
    current_user.money -= PREMIUM_COST
    db.session.commit()
    flash(f'Your account has been upgraded to premium for {PREMIUM_DAYS} days for ${PREMIUM_COST}!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/profile/<username>')
def profile(username):
    # Try to find a real user first
    user = User.query.filter_by(username=username).first()
    if user:
        character = Character.query.filter_by(master_id=user.id, is_alive=True).first()
        crew = db.session.get(Crew, user.crew_id) if user.crew_id else None
        return render_template('profile.html', user=user, crew=crew, character=character)
    # If not found, try to find an NPC by name
    character = Character.query.filter_by(name=username, master_id=0).first()
    if character:
        return render_template('profile.html', user=None, crew=None, character=character)
    # Not found
    return render_template('404.html'), 404

@app.context_processor
def inject_current_character():
    from flask_login import current_user
    if current_user.is_authenticated:
        character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
        return dict(current_character=character)
    return dict(current_character=None)
# Create DB (run once, or integrate with a CLI or shell)

admin = Admin(
    app,
    name='Admin Panel',
    template_mode='bootstrap3',
    base_template='admin/dood_base.html'
)


admin.add_view(ModelView(Character, db.session, endpoint='character_admin'))
admin.add_view(UserModelView(User, db.session, endpoint='admin_users'))

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


@app.route('/create_fake_profile', methods=['GET', 'POST'])
def create_fake_profile():
    npc_price = 150000  # Set the price for creating an NPC

    if request.method == 'POST':
        npc_name = request.form.get('npc_name')
        if not npc_name:
            flash("NPC name is required.", "danger")
            return redirect(url_for('create_fake_profile'))

        # Check if user has enough money
        character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
        if not character or character.money < npc_price:
            flash("Not enough money to create a fake profile.", "danger")
            return redirect(url_for('create_fake_profile'))

        # Deduct money and create NPC
        character.money -= npc_price
        npc = Character(
            master_id=0,
            name=npc_name,
            money=500,  # Starting money for NPC
            xp=0,
            level=1,
            is_alive=True,
            health=100
        )
        db.session.add(npc)
        db.session.commit()
        flash(f"Fake profile '{npc_name}' created!", "success")
        return redirect(url_for('dashboard'))

    # Render the form for GET requests
    return render_template('create_npc.html', npc_price=npc_price)

def get_online_users():
    cutoff = datetime.utcnow() - timedelta(minutes=5)
    # Real users online
    real_online = User.query.filter(User.last_seen >= cutoff).all()
    # NPCs: Characters with master_id=0 (or whatever you use)
    npcs = Character.query.filter_by(master_id=0, is_alive=True).all()
    # Optionally, create a fake User object for each NPC if your template expects User
    return real_online, npcs

if __name__ == '__main__':
    if not os.path.exists('users.db'):
        with app.app_context():
            db.create_all()
        print("Registered endpoints:")
        for rule in app.url_map.iter_rules():
            print(f"Endpoint: {rule.endpoint} -> URL: {rule}")
    app.run(debug=True)
