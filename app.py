from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import os
import sqlite3
from datetime import datetime, timedelta
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_admin import expose, AdminIndexView
from flask_admin.form import SecureForm,BaseForm
from wtforms import PasswordField, StringField

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
    Crew_id = StringField('Crew ID')


class ShopItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    description = db.Column(db.String(256))
    price = db.Column(db.Integer, nullable=False)
    stock = db.Column(db.Integer, default=0)

class UserModelView(ModelView):
    column_list = ('id', 'username','password', 'crew_id', 'xp', 'level', 'money', 'last_seen')
    column_searchable_list = ('username',)
    can_create = False
    can_edit = True
    can_delete = False
    form = UserEditForm

    form_excluded_columns = ['password_hash', 'last_seen', 'last_earned']

    form_extra_fields = {
        'password': PasswordField('Password')
    }

    def is_accessible(self):
        return current_user.is_authenticated and current_user.username == 'admin'

    def on_model_change(self, form, model, is_created):
        if form.password.data:
            model.set_password(form.password.data)

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))
    
    def is_accessible(self):
        return current_user.is_authenticated and current_user.username == 'admin'


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


# Optional: customize admin homepage
class MyAdminIndexView(AdminIndexView):
    @expose('/')
    def index(self):
        if not current_user.is_authenticated or current_user.username != 'admin':
            return redirect(url_for('login'))
        return super().index()
    


admin = Admin(
    app,
    name='Admin Panel',
    template_mode='bootstrap3',
    index_view=MyAdminIndexView(),
    base_template='admin/base.html'  # <-- Add this line
)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


admin.add_view(UserModelView(User, db.session, endpoint='admin_user'))
admin.add_view(ModelView(ShopItem, db.session))
admin.add_view(ModelView(Crew, db.session))
admin.add_view(ModelView(CrewMessage, db.session))
admin.add_view(ModelView(CrewInvitation, db.session))
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
        if item and current_user.money >= item.price:
            current_user.money -= item.price
            db.session.commit()
            message = f"You bought {item.name} for ${item.price}!"
        else:
            message = "Not enough money or item not found."
    return render_template('shop.html', items=items, message=message)
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
        if user and user.check_password(password):
            login_user(user)
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
    if request.method == 'POST':
        crew_name = request.form.get('crew_name', '').strip()
        if Crew.query.filter_by(name=crew_name).first():
            flash("Crew name already exists.")
            return redirect(url_for('create_crew'))

        new_crew = Crew(name=crew_name)
        db.session.add(new_crew)
        db.session.commit()
        current_user.crew_id = new_crew.id
        db.session.commit()
        flash("Crew created and joined!")
        return redirect(url_for('dashboard'))

    return render_template('create_crew.html')

@app.route('/earn')
@login_required
def earn():
    cooldown = timedelta(minutes=5)
    now = datetime.utcnow()

    if current_user.last_earned and now - current_user.last_earned < cooldown:
        remaining = cooldown - (now - current_user.last_earned)
        minutes, seconds = divmod(remaining.seconds, 60)
        return jsonify({'success': False, 'message': f"Wait {minutes}m {seconds}s before earning again."})

    earned_money = 100
    earned_xp = 20
    current_user.money += earned_money
    current_user.add_xp(earned_xp)
    current_user.last_earned = now
    db.session.commit()
    return jsonify({'success': True, 'message': f"You earned ${earned_money} and {earned_xp} XP!"})

@app.route('/earn_status')
@login_required
def earn_status():
    cooldown = timedelta(minutes=5)
    now = datetime.utcnow()

    if current_user.last_earned:
        elapsed = now - current_user.last_earned
        remaining = cooldown - elapsed
        seconds_remaining = max(0, int(remaining.total_seconds()))
    else:
        seconds_remaining = 0

    return jsonify({'seconds_remaining': seconds_remaining})

# Create DB (run once, or integrate with a CLI or shell)
@app.cli.command('init-db')
def init_db():
    db.create_all()
    print("Database initialized.")
    
@app.cli.command('create-admin')
def create_admin():
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin')
        admin.set_password('yep')  # Change this to a secure password
        db.session.add(admin)
        db.session.commit()
        print("Admin user created.")

if __name__ == '__main__':
    if not os.path.exists('users.db'):
        with app.app_context():
            db.create_all()
        print("Registered endpoints:")
        for rule in app.url_map.iter_rules():
            print(f"Endpoint: {rule.endpoint} -> URL: {rule}")
    app.run(debug=True)
