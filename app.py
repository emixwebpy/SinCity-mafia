from email.mime import base
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_admin import expose, Admin, AdminIndexView, BaseView
from flask_admin.form import SecureForm, BaseForm
from wtforms import PasswordField, StringField, BooleanField, IntegerField
from werkzeug.security import generate_password_hash, check_password_hash
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

db = SQLAlchemy(app)
DATABASE = 'users.db'
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@app.before_request
def update_last_seen():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()

# Modelstestaa -------------------------------
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
    last_known_ip = db.Column(db.String(45))

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
    
class ShopItemModelView(ModelView):
    can_create = True
    can_edit = True
    can_delete = True
    can_view_details = True
    column_list = ('id', 'name', 'description', 'price', 'stock')
    form_columns = ('name', 'description', 'price', 'stock')
    column_searchable_list = ('name', 'description')

class ShopItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    description = db.Column(db.String(256))
    price = db.Column(db.Integer, nullable=False)
    stock = db.Column(db.Integer, nullable=False, default=0)

class UserInventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('shop_item.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1, nullable=False)

    user = db.relationship('User', backref='inventory')
    item = db.relationship('ShopItem')
# Admin -------------------------------

class UserModelView(ModelView):
    column_searchable_list = ('username',)
    can_create = True
    can_edit = True
    can_delete = False
    can_view_details = True
    form = UserEditForm

    form_excluded_columns = ['password_hash', 'last_seen', 'last_earned']
    form_columns = ['username', 'password', 'crew_id', 'is_admin', 'premium', 'xp', 'level', 'money']  # <-- Add 'level'
    column_list = ('id', 'username', 'crew_id', 'xp', 'level', 'money', 'last_seen', 'is_admin','premium', 'last_known_ip')

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

@app.route('/shop', methods=['GET', 'POST'])
@login_required
def shop():
    items = ShopItem.query.all()
    message = None
    if request.method == 'POST':
        item_id = request.form.get('item_id')
        item = ShopItem.query.get(item_id)
        if item and current_user.money >= item.price and item.stock > 0:
            current_user.money -= item.price
            item.stock -= 1

            # Add to inventory or increment quantity
            inventory_item = UserInventory.query.filter_by(user_id=current_user.id, item_id=item.id).first()
            if inventory_item:
                inventory_item.quantity += 1
            else:
                inventory_item = UserInventory(user_id=current_user.id, item_id=item.id, quantity=1)
                db.session.add(inventory_item)

            db.session.commit()
            message = f"You bought {item.name} for ${item.price}!"
        elif item and item.stock <= 0:
            message = "Sorry, this item is out of stock."
        else:
            message = "Not enough money or item not found."
    return render_template('shop.html', items=items, message=message)

@app.route('/user_stats')
@login_required
def user_stats():
    return jsonify({
        'money': current_user.money,
        'xp': current_user.xp,
        'level': current_user.level
    })

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
    return render_template(
        'dashboard.html',
        user=current_user,
        crew=crew,
        online_users=online_users
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
    cooldown = timedelta(minutes=0, seconds=10)
    now = datetime.utcnow()

    if current_user.last_earned and now - current_user.last_earned < cooldown:
        remaining = cooldown - (now - current_user.last_earned)
        minutes, seconds = divmod(remaining.seconds, 60)
        return jsonify({'success': False, 'message': f"Wait {minutes}m {seconds}s before earning again."})
    #randomise earned money and xp
    # For simplicity, let's say you earn a fixed amount 
    # In a real application, you might want to randomize this
    # or make it dependent on some game logic   
    earned_money = random.randint(200, 2000)
    earned_xp = random.randint(20, 120)
    current_user.money += earned_money
    current_user.add_xp(earned_xp)
    current_user.last_earned = now
    db.session.commit()
    return jsonify({'success': True, 'message': f"You earned ${earned_money} and {earned_xp} XP!"})


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
    PREMIUM_COST = 50000
    if current_user.premium:
        flash('You are already a premium user!', 'info')
        return redirect(url_for('dashboard'))
    if current_user.money < PREMIUM_COST:
        flash(f'You need at least ${PREMIUM_COST} to upgrade to premium.', 'danger')
        return redirect(url_for('dashboard'))
    current_user.money -= PREMIUM_COST
    current_user.premium = True
    db.session.commit()
    flash(f'Your account has been upgraded to premium for ${PREMIUM_COST}!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/profile/<username>')
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    crew = Crew.query.get(user.crew_id) if user.crew_id else None
    return render_template('profile.html', user=user, crew=crew)
# Create DB (run once, or integrate with a CLI or shell)

admin = Admin(
    app,
    name='Admin Panel',
    template_mode='bootstrap3',
    base_template='admin/dood_base.html'
)

admin.add_view(UserModelView(User, db.session, endpoint='admin_users'))
admin.add_view(ModelView(UserInventory, db.session))
admin.add_view(ShopItemModelView(ShopItem, db.session))  # <-- use the new view here
admin.add_view(ModelView(Crew, db.session))
admin.add_view(ModelView(CrewMessage, db.session))
admin.add_view(ModelView(CrewInvitation, db.session))

@app.cli.command('init-db')
def init_db():
    db.create_all()
    print("Database initialized.")
    
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


if __name__ == '__main__':
    if not os.path.exists('users.db'):
        with app.app_context():
            db.create_all()
        print("Registered endpoints:")
        for rule in app.url_map.iter_rules():
            print(f"Endpoint: {rule.endpoint} -> URL: {rule}")
    app.run(debug=True)
