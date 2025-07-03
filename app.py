# -*- coding: utf-8 -*-
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, Blueprint, session
from flask_mail import Mail, Message
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf import CSRFProtect
from flask_migrate import Migrate
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import  logging, random, os, logging
from markupsafe import Markup, escape
from itsdangerous import URLSafeTimedSerializer
from PIL import Image
from flask_limiter import Limiter
from extensions import db, login_manager, mail, migrate, csrf

app = Flask(__name__)

app.config['MAIL_SERVER'] = 'localhost'
app.config['MAIL_PORT'] = 1025
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = None
app.config['MAIL_PASSWORD'] = None
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@example.com')
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', os.urandom(32))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB max file size
app.config['LOGIN_MESSAGE'] = None
app.config['LOGIN_MESSAGE_CATEGORY'] = "info"
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)

db.init_app(app)
login_manager.init_app(app)
mail.init_app(app)
migrate.init_app(app, db)
csrf.init_app(app)


from models.user import User, CrewRequest
from models.character import Character, Godfather
from models.crew import Crew, CrewMember, CrewInvitation, CrewMessage
from models.organized_crime import OrganizedCrime
from models.private_message import PrivateMessage
from models.shop import ShopItem, ShopItemModelView, UserInventory, Gun
from models.drug import Drug, DrugDealer, CharacterDrugInventory
from models.notification import Notification
from models.forum import Forum, ForumTopic, ForumPost
from models.chat import ChatMessage
from models.admin import admin_bp
from models.forms import *
from models.constants import CITIES, ALLOWED_EXTENSIONS, ALLOWED_MIME_TYPES, BODYGUARD_NAMES, BODYGUARD_LASTNAMES, DRUG_LIST
from models.loggers import admin_logger
from models.utils import notify_admin_duplicate_ip, allowed_file, is_safe_url, limiter_key_func, generate_unique_invite_code, is_on_crime_cooldown, seed_drugs, randomize_all_drug_prices, update_crew_member_count, seed_territories, maybe_trigger_city_event
from models.background_tasks import start_jail_release_thread
from models.territory import Territory
from models.event import CityEvent



app.register_blueprint(admin_bp)
logging.getLogger('flask_limiter').setLevel(logging.ERROR)
with app.app_context():
    db.create_all()
    seed_territories()
    seed_drugs()
    randomize_all_drug_prices()
    start_jail_release_thread(app)
    update_crew_member_count(Crew)


# Database -------------------------------


serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
mail = Mail(app)
admin_logger = logging.getLogger('admin_actions')
admin_logger.setLevel(logging.INFO)
fh = logging.FileHandler('admin_actions.log')
admin_logger.addHandler(fh)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}





DATABASE = 'users.db'
login_manager = LoginManager(app)
login_manager.login_view = 'login'
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')
migrate = Migrate(app, db)
csrf = CSRFProtect(app)
limiter = Limiter(key_func=limiter_key_func, app=app, default_limits=["200 per day", "50 per hour"])



# Middleware -------------------------------

@app.before_request
def update_last_seen():
    if current_user.is_authenticated:
        now = datetime.utcnow()
        if not current_user.last_seen or (now - current_user.last_seen).seconds > 1:
            current_user.last_seen = now
            db.session.commit()
# Middleware to enable SQLite foreign key constraints
@app.before_request
def enable_sqlite_fk():
    if db.engine.url.drivername == 'sqlite':
        with db.engine.connect() as conn:
            conn.execute(db.text("PRAGMA foreign_keys=ON"))
# Middleware to check if character is alive
@app.before_request
def check_character_alive():
    allowed_endpoints = (
         'logout', 'static', 'dashboard', 'register', 'login', 'admin','create_character', 'forums', 'forum_view', 'gun_detail', 'send_beer', 'new_topic', 'topic_view', 'create_forum', 'inbox', 'notifications', 'send_message', 'view_message', 'leave_crime', 'attempt_organized_crime', 'crew_page', 'update_crew_role', 'hire_bodyguard', 'kill', 'profile_by_id', 'crew_member_update_role', 'crew_member_leave', 'crew_member_invite', 'crews', 'crew_member_view_profile', 'crew_member_edit_profile', 'crew_member_delete_profile', 'crew_member_view_crew', 'crew_member_create_crew', 'crew_member_edit_crew', 'crew_member_delete_crew', 'crew_member_view_members', 'crew_member_add_member', 'crew_member_remove_member', 'crew_member_view_requests', 'crew_member_accept_request', 'crew_member_decline_request', 'crew_member_view_notifications', 'crew_member_mark_notification_read', 'crew_member_delete_notification', 'crew_member_view_messages', 'crew_member_send_message', 'crew_member_view_message', 'crew_member_delete_message', 'crew_member_view_sent_messages', 'crew_member_view_received_messages', 'crew_member_view_chat', 'crew_member_send_chat_message', 'crew_member_delete_chat_message', 'crew_member_view_chat_history', 'crew_member_clear_chat_history', 'crew_member_view_crime_history', 'crew_member_clear_crime_history', 'crew_member_edit_crime_group', 'crew_member_delete_crime_group', 'crew_member_view_crime_group_members', 'crew_member_add_crime_group_member', 'crew_member_remove_crime_group_member', 'crew_member_view_crime_group_requests', 'crew_member_accept_crime_group_request', 'crew_member_decline_crime_group_request', 'crew_member_view_crime_group_invitations', 'crew_member_accept_crime_group_invitation', 'public_message_view', 'public_message_send','player_search','travel','godfathers_page','send_beer','claim_godfather','create_crime','crime_group','send_public_message', 'public_message','get_messages', 'crew_messages','earn','jail','breakout','upload_profile_image','disband_crime', 'leave_crime', 'profile_by_id', 'shop', 'buy_item', 'view_item', 'delete_item', 'edit_item', 'create_item','kill', 'graveyard'
    )
    if current_user.is_authenticated:
        char = Character.query.filter_by(master_id=current_user.id).first()
        # Always allow admin users to access admin endpoints
        if getattr(current_user, 'is_admin', False) and request.endpoint and request.endpoint.startswith('admin'):
            return
        if not char or not char.is_alive:
            if request.endpoint not in allowed_endpoints:
                return redirect(url_for('create_character'))


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))
# Routes -------------------------------
@app.route('/')
def home():
    return redirect(url_for('dashboard'))

@app.route('/forums')
def forums():
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    forums = Forum.query.all()
    if character.in_jail and character.jail_until and character.jail_until > datetime.utcnow():
        remaining = character.jail_until - datetime.utcnow()
        mins, secs = divmod(int(remaining.total_seconds()), 60)
        flash(f"You are in jail for {mins}m {secs}s.", "danger")
        return redirect(url_for('jail'))
    return render_template('forums.html', forums=forums,character=character)

@app.route('/forum/<int:forum_id>')
def forum_view(forum_id):
    forum = Forum.query.get_or_404(forum_id)
    topics = ForumTopic.query.filter_by(forum_id=forum.id).order_by(ForumTopic.created_at.desc()).all()
    author_ids = {topic.author_id for topic in topics}
    char_map = {}
    for uid in author_ids:
        char = Character.query.filter_by(master_id=uid).first()
        char_map[uid] = char.name if char else f'User #{uid}'
    return render_template('forum_view.html', forum=forum, topics=topics, char_map=char_map)

@app.route('/gun/<int:gun_id>')
def gun_detail(gun_id):
    gun = Gun.query.get_or_404(gun_id)
    return render_template('gun_detail.html', gun=gun)

@app.route('/send_beer', methods=['GET', 'POST'])
@login_required
def send_beer():
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    form = SendBeerForm()
    if not character:
        flash("You need to create a character first.", "warning")
        return redirect(url_for('create_character'))
    # Check if the character is on bar cooldown
    if character.in_jail and character.jail_until and character.jail_until > datetime.utcnow():
            remaining = character.jail_until - datetime.utcnow()
            mins, secs = divmod(int(remaining.total_seconds()), 60)
            flash(f"You are in jail for {mins}m {secs}s.", "danger")
            return redirect(url_for('jail'))
    

    if form.validate_on_submit():
        recipient_name = form.recipient_name.data.strip()
        drink_type = form.drink_type.data
        recipient = Character.query.filter_by(name=recipient_name, is_alive=True).first()
        
        if not recipient:
            flash(f"No character found with name {recipient_name}.", "danger")
            return redirect(url_for('send_beer'))
        # Check if recipient is the same as sender
        if recipient.master_id == current_user.id:
            flash("You cannot send a drink to yourself.", "danger")
            return redirect(url_for('send_beer'))
        # Check if recipient is in jail
        if recipient.in_jail and recipient.jail_until and recipient.jail_until > datetime.utcnow():
            remaining = recipient.jail_until - datetime.utcnow()
            mins, secs = divmod(int(remaining.total_seconds()), 60)
            flash(f"{recipient_name} is in jail for {mins}m {secs}s and cannot receive drinks.", "danger")
            return redirect(url_for('send_beer'))
        
        #check if recipient is in the same city
        if character.city != recipient.city:
            flash(f"{recipient_name} is not in the same city as you. You can only send drinks to characters in your city.", "danger")
            return redirect(url_for('send_beer'))
        # Check if sender is on bar cooldown
        if character.bar_cooldown and isinstance(character.bar_cooldown, datetime) and character.bar_cooldown > datetime.utcnow():
            remaining = character.bar_cooldown - datetime.utcnow()
            hour, remainder = divmod(int(remaining.total_seconds()), 3600)
            mins, secs = divmod(remainder, 60)
            flash(f"You are on bar cooldown for {hour}h {mins}m {secs}s.", "danger")
            return redirect(url_for('send_beer'))
        # Set drink cost and effect
        if drink_type == 'beer':
            drink_cost = 1000
            recipient.xp += random.randint(5, 15)
            print(f"{current_user.username} sent beer to {recipient_name}")
            logging.warning(f"{current_user.username} sent beer to {recipient_name}")
            
        elif drink_type == 'whiskey':
            drink_cost = 20
            recipient.xp += random.randint(100, 250)
        elif drink_type == 'wine':
            drink_cost = 15
            recipient.xp += random.randint(150, 350)
        elif drink_type == 'vodka':
            drink_cost = 25
            recipient.xp += random.randint(250, 500)
        elif drink_type == 'rum':
            drink_cost = 30
            recipient.xp += random.randint(200, 400)
        elif drink_type == 'gin':
            drink_cost = 35
            recipient.health += random.randint(1, 10)
        else:
            flash("Invalid drink type selected.", "danger")
            return redirect(url_for('send_beer'))

        # Check if sender has enough money
        if character.money < drink_cost:
            flash("You don't have enough money to send this drink.", "danger")
            return redirect(url_for('send_beer'))
        
        # Deduct money from sender
        character.money -= drink_cost
        
        # Set bar cooldown for sender
        character.bar_cooldown = datetime.utcnow() + timedelta(hours=8)  # 8 hours cooldown
        # Commit changes
        db.session.commit()

        flash(f"Sent {drink_type.title()} to {recipient_name}!", "success")
        return redirect(url_for('dashboard'))

    return render_template('send_beer.html', form=form)

@app.route('/forum/<int:forum_id>/new_topic', methods=['GET', 'POST'])
@login_required
def new_topic(forum_id):
    forum = Forum.query.get_or_404(forum_id)
    form = NewTopicForm()
    if form.validate_on_submit():
        title = form.title.data.strip()
        content = form.content.data.strip()
        topic = ForumTopic(forum_id=forum.id, title=title, author_id=current_user.id)
        db.session.add(topic)
        db.session.commit()
        post = ForumPost(topic_id=topic.id, author_id=current_user.id, content=content)
        db.session.add(post)
        db.session.commit()
        flash("Topic created!", "success")
        return redirect(url_for('topic_view', topic_id=topic.id))
    return render_template('new_topic.html', forum=forum, form=form)

@app.route('/topic/<int:topic_id>', methods=['GET', 'POST'])
def topic_view(topic_id):
    topic = ForumTopic.query.get_or_404(topic_id)
    posts = ForumPost.query.filter_by(topic_id=topic.id).order_by(ForumPost.created_at.asc()).all()
    author_ids = {post.author_id for post in posts}
    char_map = {}
    for uid in author_ids:
        char = Character.query.filter_by(master_id=uid).first()
        char_map[uid] = char.name if char else f'User #{uid}'

    # Attach processed HTML to each post
    for post in posts:
        post.html_content = Markup(escape(post.content).replace('\n', Markup('<br>')))

    form = ReplyForm()
    if form.validate_on_submit() and current_user.is_authenticated:
        content = form.content.data.strip()
        if content:
            post = ForumPost(topic_id=topic.id, author_id=current_user.id, content=content)
            db.session.add(post)
            db.session.commit()
            flash("Reply posted.", "success")
            return redirect(url_for('topic_view', topic_id=topic.id))
    return render_template('topic_view.html', topic=topic, posts=posts, char_map=char_map, form=form)

@app.route('/create_forum', methods=['GET', 'POST'])
@login_required
def create_forum():
    form = CreateForumForm()
    if not getattr(current_user, 'is_admin', False):
        flash("Only admins can create forums.", "danger")
        return redirect(url_for('forums'))
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        if not title:
            flash("Forum title is required.", "danger")
            return redirect(url_for('create_forum'))
        forum = Forum(title=title, description=description)
        db.session.add(forum)
        db.session.commit()
        flash("Forum created!", "success")
        return redirect(url_for('forums'))
    return render_template('create_forum.html', form=form)
@app.route('/messages', methods=['GET'])
@login_required
def inbox():
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    page = request.args.get('page', 1, type=int)
    per_page = 50
    messages_query = PrivateMessage.query.filter_by(recipient_id=current_user.id).order_by(PrivateMessage.timestamp.desc())
    pagination = messages_query.paginate(page=page, per_page=per_page, error_out=False)
    messages = pagination.items
    char_map = {}
    if character.in_jail and character.jail_until and character.jail_until > datetime.utcnow():
        remaining = character.jail_until - datetime.utcnow()
        mins, secs = divmod(int(remaining.total_seconds()), 60)
        flash(f"You are in jail for {mins}m {secs}s.", "danger")
        return redirect(url_for('jail'))
    for msg in messages:
        char = Character.query.filter_by(master_id=msg.sender.id, is_alive=True).first()
        char_map[msg.sender.id] = char.name if char else ""
    return render_template(
        "inbox.html",
        messages=messages,
        char_map=char_map,
        character=character,
        pagination=pagination
    )
@app.route('/messages/sent_messages', methods=['GET'])
@login_required
def sent_messages():
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    page = request.args.get('page', 1, type=int)
    per_page = 50
    messages_query = PrivateMessage.query.filter_by(sender_id=current_user.id).order_by(PrivateMessage.timestamp.desc())
    pagination = messages_query.paginate(page=page, per_page=per_page, error_out=False)
    messages = pagination.items
    char_map = {}
    if character.in_jail and character.jail_until and character.jail_until > datetime.utcnow():
        remaining = character.jail_until - datetime.utcnow()
        mins, secs = divmod(int(remaining.total_seconds()), 60)
        flash(f"You are in jail for {mins}m {secs}s.", "danger")
        return redirect(url_for('jail'))
    for msg in messages:
        char = Character.query.filter_by(master_id=msg.recipient.id, is_alive=True).first()
        char_map[msg.recipient.id] = char.name if char else ""
    return render_template(
        "sent_messages.html",
        messages=messages,
        char_map=char_map,
        character=character,
        pagination=pagination
    )
@app.route('/notifications')
@login_required
def notifications():
    online_timeout = datetime.utcnow() - timedelta(minutes=5)
    online_users = User.query.filter(User.last_seen >= online_timeout).all()
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.timestamp.desc()).all()
    online_characters = []
    for u in online_users:
        char = Character.query.filter_by(master_id=u.id, is_alive=True).first()
        if char:
            online_characters.append(char)
    if character.in_jail and character.jail_until and character.jail_until > datetime.utcnow():
        remaining = character.jail_until - datetime.utcnow()
        mins, secs = divmod(int(remaining.total_seconds()), 60)
        flash(f"You are in jail for {mins}m {secs}s.", "danger")
        return redirect(url_for('jail'))
    messages = PrivateMessage.query.filter_by(recipient_id=current_user.id, is_read=False).order_by(PrivateMessage.timestamp.desc()).all()
    for msg in messages:
        notifications.append({
            "type": "message",
            "from": msg.sender.character.name if msg.sender and msg.sender.character else "Unknown",
            "content": msg.content,
            "msg_id": msg.id,
            "timestamp": msg.timestamp,
            "is_read": msg.is_read,
        })
    # Fetch crew invitations for the current user
    invitations = CrewInvitation.query.filter_by(invitee_id=current_user.id).all()
    # Sort notifications by timestamp descending
    notifications = sorted(
        notifications,
        key=lambda n: n.timestamp if hasattr(n, 'timestamp') else n.get("timestamp", datetime.min),
        reverse=True
    )
    return render_template('notifications.html', notifications=notifications, invitations=invitations,character=character)
    
    

@app.route('/messages/send/<int:user_id>', methods=['GET', 'POST'])
@login_required
def send_message(user_id):
    recipient = User.query.get_or_404(user_id)
    form = SendMessageForm()
    if form.validate_on_submit():
        content = request.form.get('content', '').strip()
        if not content:
            flash("Message cannot be empty.", "danger")
            return redirect(url_for('send_message', user_id=user_id))
        msg = PrivateMessage(sender_id=current_user.id, recipient_id=recipient.id, content=content)
        db.session.add(msg)
        db.session.commit()
        flash("Message sent!", "success")
        return redirect(url_for('inbox'))
    return render_template("send_message.html", form=form, recipient=recipient)
@app.route('/leave_crime', methods=['POST', 'GET'])
@login_required
def leave_crime():
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    if not character or not character.crime_group:
        flash("You're not in any crime group.", "warning")
        return redirect(url_for('dashboard'))
    
    crime = character.crime_group
    # If the character is the leader, prevent leaving and advise disbanding
    if crime.leader_id == character.id:
        flash("You are the leader of this crime group. To leave, you must disband the group.", "danger")
        return redirect(url_for('crime_group'))
    
    # Remove the character from the crime group
    character.crime_group_id = None
    db.session.commit()
    
    flash("You have left the crime group.", "success")
    return redirect(url_for('dashboard'))
@app.route('/messages/view/<int:msg_id>', methods=['GET', 'POST'])
@login_required
def view_message(msg_id):
    msg = PrivateMessage.query.get_or_404(msg_id)
    if msg.recipient_id != current_user.id and msg.sender_id != current_user.id:
        flash("You do not have permission to view this message.", "danger")
        return redirect(url_for('inbox'))
    if msg.recipient_id == current_user.id:
        msg.is_read = True
        db.session.commit()
    form = SendMessageForm()
    if form.validate_on_submit() and current_user.id != msg.sender_id:
        content = form.content.data.strip()
        if not content:
            flash("Message cannot be empty.", "danger")
            return redirect(url_for('view_message', msg_id=msg_id))
        reply = PrivateMessage(sender_id=current_user.id, recipient_id=msg.sender_id, content=content)
        db.session.add(reply)
        db.session.commit()
        flash("Reply sent!", "success")
        return redirect(url_for('inbox'))
    char = Character.query.filter_by(master_id=msg.sender_id, is_alive=True).first()
    char_map = {msg.sender_id: char.name if char else "Unknown"}
    return render_template("view_message.html", msg=msg, form=form, char_map=char_map)
@app.route('/organized_crime/attempt', methods=['POST'])
@login_required
def attempt_organized_crime():
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    if not character or not character.crime_group:
        flash("You are not in a crime group.", "danger")
        return redirect(url_for('dashboard'))

    crime = character.crime_group


    # Only allow the group leader to start the crime
    if crime.leader_id != character.id:
        flash("Only the group leader can start the crime.", "danger")
        return redirect(url_for('dashboard'))

    members = crime.members
    if len(members) < 2:
        flash("You need at least 2 members to attempt the crime.", "warning")
        return redirect(url_for('dashboard'))

    
    success = random.random() < 0.35
    reward_money = random.randint(500, 1500) if success else 25
    reward_xp = random.randint(10, 30) if success else 25

    for member in members:
        if member:
            member.last_crime_time = datetime.utcnow()
            if success:
                member.money += reward_money
                member.xp += reward_xp
                member.crime_group_id = None  # Disband the crime group
                logging.info(f"{member.name} successfully completed the crime and earned ${reward_money} and {reward_xp} XP.")
                flash(f"{member.name} successfully completed the crime and earned ${reward_money} and {reward_xp} XP.", "success")
                db.session.commit()
            else:
                # 20% chance to go to jail on failed crime
                if random.random() < 0.2:
                    jail_minutes = random.randint(5, 15)
                    member.in_jail = True
                    member.jail_until = datetime.utcnow() + timedelta(minutes=jail_minutes)
                    member.crime_group_id = None
                    flash(f"{member.name} has been jailed for {jail_minutes} minutes due to failed crime.", "warning")
                    db.session.commit()
            member.crime_group_id = None  # Disband the crime group

    db.session.delete(crime)
    db.session.commit()

    if success:
        
        flash(f"Crime successful! Each member earned ${reward_money} and {reward_xp} XP.", "success")
    else:
        flash(f"Crime failed! The crew has disbanded.", "danger")

    return redirect(url_for('dashboard'))

@app.route('/graveyard')
@login_required
def graveyard():
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    if character.in_jail and character.jail_until and character.jail_until > datetime.utcnow():
        remaining = character.jail_until - datetime.utcnow()
        mins, secs = divmod(int(remaining.total_seconds()), 60)
        flash(f"You are in jail for {mins}m {secs}s.", "danger")
        return redirect(url_for('jail'))
    # Fetch all dead characters
    all_characters = Character.query.filter_by(is_alive=False).all()
    # Sort by death_date if available, most recent first
    all_characters.sort(key=lambda c: getattr(c, 'death_date', None) or datetime.min, reverse=True)
    return render_template("graveyard.html", all_characters=all_characters, character=character)

@app.route('/crew/<int:crew_id>')
@login_required
def crew_page(crew_id):
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    crew = Crew.query.get_or_404(crew_id)
    members = CrewMember.query.filter_by(crew_id=crew.id).all()
    invite_form = InviteForm()
    leave_form = LeaveForm()
    member_forms = [(member, RoleForm(new_role=member.role)) for member in members]
    # Determine current user's role in the crew
    current_user_role = None
    for m in members:
        if m.user_id == current_user.id:
            current_user_role = m.role
    if character.in_jail and character.jail_until and character.jail_until > datetime.utcnow():
        remaining = character.jail_until - datetime.utcnow()
        mins, secs = divmod(int(remaining.total_seconds()), 60)
        flash(f"You are in jail for {mins}m {secs}s.", "danger")
        return redirect(url_for('jail'))
    member_forms = []
    for member in members:
        form = CrewRoleForm(prefix=str(member.id))
        form.new_role.data = member.role  # Set default
        member_forms.append((member, form))
    return render_template(
        'crew_page.html',
        crew=crew,
        members=members,
        invite_form=invite_form,
        leave_form=leave_form,
        member_forms=member_forms,
        current_user_role=current_user_role,
        character=character
    )

@app.route('/crew_member/<int:crew_member_id>/update_role', methods=['POST'])
@login_required
def update_crew_role(crew_member_id):
    crew_member = CrewMember.query.get_or_404(crew_member_id)
    crew_id = crew_member.crew_id

    # Only leader can change roles
    my_member = CrewMember.query.filter_by(user_id=current_user.id, crew_id=crew_id).first()
    if not my_member or my_member.role != 'leader':
        flash("Only the leader can change roles.", "danger")
        return redirect(url_for('crew_page', crew_id=crew_id))

    form = CrewRoleForm(prefix=str(crew_member.id))
    if form.validate_on_submit():
        new_role = form.new_role.data

        # Prevent self-demotion
        if crew_member.user_id == current_user.id:
            flash("You can't change your own role.", "danger")
            return redirect(url_for('crew_page', crew_id=crew_id))

        # Only one left hand/right hand per crew
        if new_role in ['left hand', 'right hand']:
            existing = CrewMember.query.filter_by(crew_id=crew_id, role=new_role).first()
            if existing and existing.id != crew_member.id:
                flash(f"There is already a {new_role} in this crew.", "danger")
                return redirect(url_for('crew_page', crew_id=crew_id))

        crew_member.role = new_role
        db.session.commit()
        flash("Role updated.", "success")
    else:
        flash("Invalid form submission.", "danger")
    return redirect(url_for('crew_page', crew_id=crew_id))

@app.route('/hire_bodyguard', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
@login_required
def hire_bodyguard():
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    COST_PER_BODYGUARD = 1000
    MAX_BODYGUARDS = 200
    if not character:
        flash("No character found.", "danger")
        return redirect(url_for('dashboard'))
    if character.in_jail and character.jail_until and character.jail_until > datetime.utcnow():
        remaining = character.jail_until - datetime.utcnow()
        mins, secs = divmod(int(remaining.total_seconds()), 60)
        flash(f"You are in jail for {mins}m {secs}s.", "danger")
        return redirect(url_for('jail'))
    max_hire = MAX_BODYGUARDS - (character.bodyguards or 0)
    form = HireBodyguardForm()
    form.num.validators[1].max = max_hire  # Dynamically set max

    if form.validate_on_submit():
        num = form.num.data
        if num < 1 or num > max_hire:
            flash(f"You can only hire up to {max_hire} more bodyguards.", "danger")
            return redirect(url_for('hire_bodyguard'))
        total_cost = character.bodyguards + COST_PER_BODYGUARD * num
        if character.money < total_cost:
            flash("Not enough money to hire bodyguards.", "danger")
            return redirect(url_for('hire_bodyguard'))
        character.money -= total_cost
        character.bodyguards = (character.bodyguards or 0) + num
        new_names = [f"{random.choice(BODYGUARD_NAMES)} {random.choice(BODYGUARD_LASTNAMES)}" for _ in range(num)]
        character.add_bodyguards(new_names)
        db.session.commit()
        flash(f"Hired {num} bodyguard(s)! You now have {character.bodyguards}.", "success")
        return redirect(url_for('hire_bodyguard'))

    return render_template("hire_bodyguard.html", character=character, form=form, max_hire=max_hire)

@app.route('/kill/character/<character_name>', methods=['POST'])
@login_required
def kill(character_name):
    # Get the attacker's character
    attacker = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    if not attacker:
        flash("You must have a living character to attack.", "danger")
        return redirect(url_for('dashboard'))
    
        return redirect(url_for('profile_by_id', char_id=target.id))
    gun = attacker.equipped_gun or current_user.gun
    if not gun:
        flash("You don't have a gun equipped!", "danger")
        target_char = Character.query.filter_by(name=character_name).first()
        if target_char:
            return redirect(url_for('profile_by_id', char_id=target_char.id))
        return redirect(url_for('dashboard'))
    # Always target by character name
    target = Character.query.filter_by(name=character_name, is_alive=True).first()
    if attacker.city != target.city:
        flash(f"You can only attack characters in your current city ({attacker.city}).", "danger")
        return redirect(url_for('dashboard'))
    
    if not target:
        flash("Target not found or already dead.", "danger")
        return redirect(url_for('dashboard'))

    # Prevent killing your own character
    if target.master_id == current_user.id:
        flash("You can't kill your own character!", "danger")
        return redirect(url_for('dashboard'))
    
    if target.bodyguards and target.bodyguards > 0:
        target.bodyguards -= gun.damage + gun.accuracy * 10  # Bodyguards take some damage
        
        db.session.commit()
        flash(f"{target.name}'s bodyguard protected them! One bodyguard was lost.", "warning")
        return redirect(url_for('profile_by_id', char_id=target.id))

    # Prevent killing admin characters
    if hasattr(target, "immortal") and target.immortal:
        flash("You cannot kill an admin!", "danger")
        return redirect(url_for('dashboard'))

    # Prevent killing characters that are not alive
    if not target.is_alive:
        flash(f"{target.name} is already dead!", "danger")
        return redirect(url_for('dashboard'))

    # Gun accuracy check (if using accuracy stat)
    if hasattr(gun, "accuracy") and random.random() > gun.accuracy:
        flash(f"You missed your shot with {gun.name}!", "warning")
        return redirect(url_for('profile_by_id', char_id=target.id))

    # Apply damage
    target.health -= gun.damage
    killed = False

    if target.health <= 0:
        target.is_alive = False
        killed = True
        target.master_id = None
        flash(f"You killed {target.name}!", "success")
        db.session.commit()
    else:
        flash(f"You shot {target.name} for {gun.damage} damage!", "success")

    

    # Update kill count if the target was killed
    if killed:
        current_user.kills = (current_user.kills or 0) + 1
        db.session.commit()

    return redirect(url_for('profile_by_id', char_id=target.id))


@app.route('/shop', methods=['GET', 'POST'])
@login_required
def shop():
    items = ShopItem.query.all()
    message = None
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    if character.in_jail and character.jail_until and character.jail_until > datetime.utcnow():
            remaining = character.jail_until - datetime.utcnow()
            mins, secs = divmod(int(remaining.total_seconds()), 60)
            flash(f"You are in jail for {mins}m {secs}s.", "danger")
            return redirect(url_for('jail'))
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

            # Auto-equip if the item is a gun
            if item.is_gun:
                message = f"You bought {item.name} for ${item.price}! Go to your inventory to equip it."
            else:
                message = f"You bought {item.name} for ${item.price}!"

            db.session.commit()
        elif item and item.stock <= 0:
            message = "Sorry, this item is out of stock."
        else:
            message = "Not enough money or item not found."
    return render_template(
        "shop.html",
        character=character,
        items=items,
        message=message,
        buy_form=BuyForm()
    )

@app.route('/travel', methods=['GET', 'POST'])
@login_required
def travel():
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()

    if character.in_jail and character.jail_until and character.jail_until > datetime.utcnow():
        remaining = character.jail_until - datetime.utcnow()
        mins, secs = divmod(int(remaining.total_seconds()), 60)
        flash(f"You are in jail for {mins}m {secs}s.", "danger")
        return redirect(url_for('jail'))
    
    if not character:
        flash("No character found.", "danger")
        return redirect(url_for('dashboard'))

    cooldown = timedelta(hours=8)  # 8-hour cooldown for travel
    now = datetime.utcnow()
    can_travel = (
        not character.last_travel_time or
        (now - character.last_travel_time) >= cooldown
    )
    time_left = None
    if character.last_travel_time and not can_travel:
        time_left = cooldown - (now - character.last_travel_time)

    if request.method == 'POST':
        new_city = request.form.get('city')
        if not can_travel:
            mins, secs = divmod(int(time_left.total_seconds()), 60)
            hours, mins = divmod(mins, 60)
            flash(f"You must wait {hours}h {mins}m before traveling again.", "warning")
        elif new_city not in CITIES:
            flash("Invalid city selected.", "danger")
        elif new_city == character.city:
            flash("You are already in this city.", "info")
        else:
            character.city = new_city
            character.last_travel_time = now
            db.session.commit()
            # --- Random Encounter Logic ---
            encounter_roll = random.random()
            if encounter_roll < 0.10:
                # 10% chance: ambushed, lose money
                loss = random.randint(1000, 5000)
                character.money = max(0, character.money - loss)
                db.session.commit()
                flash(f"You were ambushed on the road and lost ${loss}!", "danger")
            elif encounter_roll < 0.20:
                # 10% chance: bonus find
                gain = random.randint(1000, 5000)
                character.money += gain
                db.session.commit()
                flash(f"You found a hidden stash and gained ${gain}!", "success")
            elif encounter_roll < 0.25:
                # 5% chance: police checkpoint (jail)
                jail_minutes = random.randint(2, 10)
                character.in_jail = True
                character.jail_until = datetime.utcnow() + timedelta(minutes=jail_minutes)
                db.session.commit()
                flash(f"You were caught at a police checkpoint and jailed for {jail_minutes} minutes!", "danger")
                return redirect(url_for('jail'))
            else:
                flash(f"You traveled to {new_city} safely.", "success")
            return redirect(url_for('dashboard'))
    return render_template('travel.html', character=character, cities=CITIES, time_left=time_left,
    travel_form=TravelForm())

@app.route('/inventory', methods=['GET', 'POST'])
@login_required
def inventory():
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    if not character:
        flash("No character found.", "danger")
        return redirect(url_for('dashboard'))
    if character.in_jail and character.jail_until and character.jail_until > datetime.utcnow():
            remaining = character.jail_until - datetime.utcnow()
            mins, secs = divmod(int(remaining.total_seconds()), 60)
            flash(f"You are in jail for {mins}m {secs}s.", "danger")
            return redirect(url_for('jail'))
    if request.method == 'POST':
        item_id = int(request.form.get('item_id'))
        inventory_item = UserInventory.query.filter_by(user_id=current_user.id, item_id=item_id).first()
        item = ShopItem.query.get(item_id)
        # Check if the item is a gun and if the user has it in their inventory
        if not inventory_item or not item:
            flash("Item not found in your inventory.", 'danger')
            return redirect(url_for('inventory'))
        # Check if gun is equipped and sell it
        if current_user.gun_id == item.id:
            current_user.gun_id = None
            flash(f"You sold your equipped gun: {item.name}.", "info")
        # Deletes item from inventory
        if inventory_item.quantity <= 0:
            db.session.delete(inventory_item)
        sell_price = item.price // 2
        character.money += sell_price
        inventory_item.quantity -= 1
        item.stock += 1
        db.session.commit()
        flash(f"Sold 1x {item.name} for ${sell_price}.", "success")
        return redirect(url_for('inventory'))

    
    inventory_items = UserInventory.query.filter_by(user_id=current_user.id).all()
    equip_forms = {inv.item.gun.id: EquipGunForm() for inv in inventory_items if inv.item.is_gun and inv.item.gun}
    return render_template('inventory.html', inventory_items=inventory_items, character=character,equip_forms=equip_forms)

@app.route("/users_online")
@login_required
def users_online():
    cutoff = datetime.utcnow() - timedelta(minutes=5)
    users = User.query.filter(User.last_seen >= cutoff).all()
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
    search_form = PlayerSearchForm()
    kill_form = KillForm()
    query = None
    results = []
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    if character.in_jail and character.jail_until and character.jail_until > datetime.utcnow():
        remaining = character.jail_until - datetime.utcnow()
        mins, secs = divmod(int(remaining.total_seconds()), 60)
        flash(f"You are in jail for {mins}m {secs}s.", "danger")
        return redirect(url_for('jail'))
    if request.method == 'POST':
        query = request.form.get('query')
        if query:
            results = Character.query.filter(
                Character.name.ilike(f'%{query}%'),
                Character.master_id != current_user.id
            ).all()
    return render_template(
        'player_search.html',
        query=query,
        results=results,
        search_form=search_form,
        kill_form=kill_form
    )

@app.route('/npc/<int:id>')
def npc_profile(id):
    npc = Character.query.filter_by(id=id, master_id=0).first_or_404()
    return render_template('npc_profile.html', npc=npc)

@app.route('/register', methods=['GET', 'POST'])
# @limiter.limit("3 per minute")
def register():
    # Only generate a new CAPTCHA if it's a GET request or not present in session
    if 'captcha_question' not in session or request.method == 'GET':
        a, b = random.randint(1, 10), random.randint(1, 10)
        session['captcha_question'] = f"{a} + {b}"
        session['captcha_solution'] = str(a + b)
    form = RegisterForm()
    # Set the captcha fields for the form (so they are rendered in the template)
    form.captcha_question.data = session['captcha_question']
    
    next_page = request.args.get('next')

    if form.validate_on_submit():
        # Check the answer against the solution in the session
        if form.captcha_answer.data.strip() != session.get('captcha_solution', ''):
            flash(f"Incorrect CAPTCHA answer.", "danger")
            return render_template('register.html', form=form, captcha_question=session['captcha_question'])

        username = form.username.data.strip()
        email = form.email.data.strip().lower()
        password = form.password.data
        user_exists = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        if not user_exists:
            new_user = User(username=username, email=email)
            new_user.set_password(password)
            token = serializer.dumps(email, salt='email-verify')
            new_user.email_verification_token = token
            db.session.add(new_user)
            new_user.last_known_ip = request.remote_addr
            db.session.add(new_user)
            db.session.commit()
            notify_admin_duplicate_ip(new_user, admin_logger)
            verify_url = url_for('verify_email', token=token, _external=True)
            msg = Message('Verify your email', recipients=[email])
            msg.body = f'Click to verify your email: {verify_url}'
            mail.send(msg)
        # Always show the same message, even if user/email exists
        if next_page and is_safe_url(next_page):
            return redirect(next_page)
        flash('If your credentials are correct, you will receive an email.', 'info')
        return redirect(url_for('login'))
    return render_template('register.html', form=form, captcha_question=session['captcha_question'])

@app.route('/verify_email/<token>')
def verify_email(token):
    next_page = request.args.get('next')
    try:
        email = serializer.loads(token, salt='email-verify', max_age=3600)
    except Exception:
        flash('Verification link is invalid or expired.', 'danger')
        return redirect(url_for('login'))
    user = User.query.filter_by(email=email).first()
    if user:
        user.email_verified = True
        user.email_verification_token = None
        db.session.commit()
        flash('Email verified! You can now log in.', 'success')
    else:
        flash('User not found.', 'danger')
    if next_page and is_safe_url(next_page):
        return redirect(next_page)
    
    return redirect(url_for('login'))

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    form = PasswordResetRequestForm()
    next_page = request.args.get('next')
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        user = User.query.filter_by(email=email).first()
        if user:
            token = serializer.dumps(email, salt='reset-password')
            user.reset_token = token
            user.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message('Password Reset', recipients=[email])
            msg.body = f'Click to reset your password: {reset_url}'
            mail.send(msg)
        # Always show the same message
        flash('If your credentials are correct, you will receive an email.', 'info')
        if next_page and is_safe_url(next_page):
                return redirect(next_page)
        return redirect(url_for('login'))
    return render_template('reset_password_request.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='reset-password', max_age=3600)
    except Exception:
        flash('Reset link is invalid or expired.', 'danger')
        return redirect(url_for('login'))
    user = User.query.filter_by(email=email).first()
    if not user or user.reset_token != token or user.reset_token_expiry < datetime.utcnow():
        flash('Invalid or expired reset link.', 'danger')
        return redirect(url_for('login'))
    form = PasswordResetForm()
    next_page = request.args.get('next')
    if form.validate_on_submit():
        user.set_password(form.password.data)
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.commit()
        flash('Password reset successful. You can now log in.', 'success')
        if next_page and is_safe_url(next_page):
            return redirect(next_page)
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)

@app.route('/send_crew_message', methods=['POST'])
@login_required
def send_crew_message():
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    if not character or not character.crew_id:
        return jsonify({'error': 'Not in a crew'}), 403

    # Defensive: Check that crew exists
    crew = Crew.query.get(character.crew_id)
    if not crew:
        return jsonify({'error': 'Crew does not exist.'}), 400

    message = request.form.get('message', '').strip()
    if not message:
        return jsonify({"error": "Empty message"}), 400

    # Defensive: Check that character exists
    db_character = Character.query.get(character.id)
    if not db_character:
        return jsonify({'error': 'Character does not exist.'}), 400

    chat_msg = ChatMessage(
        username=character.name,
        message=message,
        channel='crew',
        user_id=current_user.id,      # Must be a valid Character.id
        crew_id=character.crew_id  # Must be a valid Crew.id
    )
    db.session.add(chat_msg)
    db.session.commit()
    return jsonify(success=True)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
def login():
    form = LoginForm()
    next_page = request.args.get('next')
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            if not user.email_verified:
                flash('Please verify your email before logging in.', 'warning')
                return redirect(url_for('login'))
            login_user(user)
            session.permanent = True
            # Set session timeout based on premium status
            if user.premium and user.premium_until and user.premium_until > datetime.utcnow():
                session.permanent_session_lifetime = timedelta(minutes=15)
            else:
                session.permanent_session_lifetime = timedelta(minutes=30)
            user.last_known_ip = request.remote_addr
            db.session.commit()
            notify_admin_duplicate_ip(user, admin_logger)
            if next_page and is_safe_url(next_page):
                return redirect(next_page)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/create_character', methods=['GET', 'POST'])
def create_character():
    form = CreateCharacterForm()
    if form.validate_on_submit():
        char_name = request.form.get('character_name', '').strip()
        if not char_name:
            flash("Character name is required.", "danger")
            return render_template('create_character.html', form=form)
        
        last_dead = Character.query.filter_by(master_id=current_user.id, is_alive=False).order_by(Character.id.desc()).first()
        
        city= random.choice(CITIES)  # Randomly assign a city from the list
        # Optionally check for duplicate names or add more validation here
        new_char = Character(
            master_id=current_user.id,
            name=char_name,
            health=100,
            money=0,
            level=1,
            is_alive=True,
            city=city,
            date_created=datetime.utcnow()
        )
        db.session.add(new_char)
        db.session.commit()
        flash("New character created!", "success")
        return redirect(url_for('dashboard'))
    return render_template('create_character.html', form=form)

@app.route('/messages/compose', methods=['GET', 'POST'])
@login_required
def compose_message():
    form = ComposeMessageForm()
    if form.validate_on_submit():
        recipient_name = form.recipient_name.data.strip()
        content = form.content.data.strip()
        character = Character.query.filter_by(name=recipient_name, is_alive=True).first()
        if not character:
            flash("No player with that character name.", "danger")
            return render_template("compose_message.html", form=form)
        recipient = User.query.get(character.master_id)
        if not recipient:
            flash("No user found for that character.", "danger")
            return render_template("compose_message.html", form=form)
        msg = PrivateMessage(sender_id=current_user.id, recipient_id=recipient.id, content=content)
        db.session.add(msg)
        db.session.commit()
        flash("Message sent!", "success")
        return redirect(url_for('inbox'))
    return render_template("compose_message.html", form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/equip_gun/<int:gun_id>', methods=['POST'])
@login_required
def equip_gun(gun_id):
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    gun = Gun.query.get_or_404(gun_id)
    # Optionally: check if user owns this gun (in inventory)
    owned = UserInventory.query.filter_by(user_id=current_user.id, item_id=gun.id).first()
    if not owned:
        flash("You don't own this gun.", "danger")
        return redirect(url_for('inventory'))
    character.equipped_gun_id = gun.id
    db.session.commit()
    flash(f"You equipped {gun.name}!", "success")
    return redirect(url_for('inventory'))

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

@app.route('/jail')
@login_required
def jail():
    now = datetime.utcnow()
    # List all currently jailed, alive characters
    jailed_characters = Character.query.filter(
        Character.in_jail == True,
        Character.is_alive == True,
        Character.jail_until != None,
        Character.jail_until > now
    ).order_by(Character.jail_until.asc()).all()
    # Get the current user's character
    current_character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    character = Character.query.filter_by(master_id=current_user.id).first()
    return render_template(
        "jail.html",
        jailed_characters=jailed_characters,
        current_character=current_character,
        now=now,
        breakout_form=BreakoutForm(),
        character=character
    )

@app.route('/breakout/<int:char_id>', methods=['POST'])
@login_required
def breakout(char_id):
    target = Character.query.get_or_404(char_id)
    actor = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    success_chance = 0.25  # 25% chance to succeed
    if random.random() < success_chance:
        target.in_jail = False
        target.jail_until = None
        db.session.commit()
        # --- Add notification for the broken out user ---
        notif = Notification(
            user_id=target.master_id,
            message=f"You were broken out of jail by {actor.name}!",
        )
        db.session.add(notif)
        db.session.commit()
        flash(f"You successfully broke {target.name} out of jail!", "success")
    # Checks
    if not actor:
        flash("You must have a living character to attempt a breakout.", "danger")
        return redirect(url_for('jail'))
    if not target.in_jail or not target.is_alive:
        flash("This character is not in jail.", "warning")
        return redirect(url_for('jail'))
    if actor.id == target.id:
        flash("You can't break yourself out!", "warning")
        return redirect(url_for('jail'))
    if actor.in_jail:
        flash("You can't attempt a breakout while in jail.", "danger")
        return redirect(url_for('jail'))

    # Breakout logic
    success_chance = 0.25  # 25% chance to succeed
    if random.random() < success_chance:
        target.in_jail = False
        target.jail_until = None
        db.session.commit()
        flash(f"You successfully broke {target.name} out of jail!", "success")
    else:
        # Fail: actor goes to jail for 2-6 minutes
        jail_minutes = random.randint(2, 6)
        actor.in_jail = True
        actor.jail_until = datetime.utcnow() + timedelta(minutes=jail_minutes)
        db.session.commit()
        flash(f"You failed and got caught! You're in jail for {jail_minutes} minutes.", "danger")
    return redirect(url_for('jail'))

@app.route('/join_crew', methods=['GET', 'POST'])
@login_required
def join_crew():
    if request.method == 'POST':
        crew = Crew.query.get(crew_id)
        try:
            crew_id = int(request.form['crew_id'])
        except (ValueError, KeyError):
            flash("Invalid crew selected.", "danger")
            return redirect(url_for('join_crew'))
            
        # Optionally check if user is already in a crew
        if current_user.crew_id:
            flash("You're already in a crew.", "warning")
            return redirect(url_for('dashboard'))
            
        # Check if the crew exists
        if not crew:
            flash("Crew not found.", "danger")
            return redirect(url_for('join_crew'))

        # Update the user's crew
        current_user.crew_id = crew_id
        # If using CrewMember, create that record too
        db.session.add(CrewMember(crew_id=crew_id, user_id=current_user.id, role='member'))
        db.session.commit()
        flash("You joined the crew!", "success")
        return redirect(url_for('dashboard'))

    crews = Crew.query.all()
    invitations = CrewInvitation.query.filter_by(invitee_id=current_user.id).all()
    return render_template('notifications.html', crews=crews, invitations=invitations)

@app.route('/leave_crew', methods=['POST', 'GET'])
@login_required
def leave_crew():
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()

    if not character or not character.crew_id:
        flash("You are not in a crew.", "warning")
        return redirect(url_for('dashboard'))
    crew = Crew.query.get(character.crew_id)
    leader_member = CrewMember.query.filter_by(crew_id=crew.id, role='leader').first()
    if leader_member and leader_member.user_id == current_user.id:
        flash("You must assign a new leader before leaving the crew.", "danger")
        return redirect(url_for('dashboard'))
    
    # Remove the character from the crew
    crew_member = CrewMember.query.filter_by(user_id=current_user.id, crew_id=character.crew_id).first()
    if crew_member:
        db.session.delete(crew_member)
        db.session.commit()  # Commit immediately to avoid NOT NULL constraint error
        character.crew_id = None
        character.crime_group_id = None
        db.session.commit()
    else:
        flash("You are not a member of this crew.", "warning")
        return redirect(url_for('dashboard'))
    
    # Optionally: remove the crew if it's empty
    if not CrewMember.query.filter_by(crew_id=crew.id).count():
        db.session.delete(crew)
        db.session.commit()
    flash("You left the crew.", "success")
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(current_user.id)  # Use a different variable name
    godfathers = {g.city: g.character for g in Godfather.query.all()}
    online_timeout = datetime.utcnow() - timedelta(minutes=5)
    online_users = User.query.filter(User.last_seen >= online_timeout).all()
    maybe_trigger_city_event()
    active_events = CityEvent.query.filter(CityEvent.end_time > datetime.utcnow()).all()
    online_characters = []
    for u in online_users:
        char = Character.query.filter_by(master_id=u.id, is_alive=True).first()
        if char:
            online_characters.append(char)
    npcs = Character.query.filter_by(master_id=0, is_alive=True).all()
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    earn_form = EarnForm()
    cities = CITIES
    claim_forms = {city: ClaimGodfatherForm(prefix=city.replace(" ", "_")) for city in cities}
    if character.in_jail and character.jail_until and character.jail_until > datetime.utcnow():
        remaining = character.jail_until - datetime.utcnow()
        mins, secs = divmod(int(remaining.total_seconds()), 60)
        flash(f"You are in jail for {mins}m {secs}s.", "danger")
        return redirect(url_for('jail'))
    if not character:
        flash("You must have a character to access the dashboard.", "danger")
        return redirect(url_for('create_character'))
    return render_template(
        'dashboard.html',
        character=character,
        online_users=online_users,
        online_characters=online_characters,
        earn_form=earn_form,
        npcs=npcs, godfathers=godfathers,
        cities=cities,
        claim_forms=claim_forms,
        active_events=active_events,
    )

@app.route('/casino', methods=['GET', 'POST'])
@login_required
def casino():
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    result = None
    hand = []
    dealer_hand = []
    bet = 0
    table = request.args.get('table', 'blackjack')  # Default to blackjack
    flip = None
    roulette_result = None
    user_choice = None

    blackjack_form = BlackjackForm()
    coinflip_form = CoinflipForm()
    roulette_form = RouletteForm()
    if character.in_jail and character.jail_until and character.jail_until > datetime.utcnow():
            remaining = character.jail_until - datetime.utcnow()
            mins, secs = divmod(int(remaining.total_seconds()), 60)
            flash(f"You are in jail for {mins}m {secs}s.", "danger")
            return redirect(url_for('jail'))
    if request.method == 'POST':
        table = request.form.get('table', 'blackjack')
        bet = int(request.form.get('bet', 0))
        if bet <= 0 or bet > character.money:
            flash("Invalid bet amount.", "danger")
            return redirect(url_for('casino', table=table))

        if table == 'blackjack':
            def hand_value(cards):
                total = sum(cards)
                aces = cards.count(11)
                while total > 21 and aces:
                    total -= 10
                    aces -= 1
                return total
            deck = [2, 3, 4, 5, 6, 7, 8, 9, 10, 10, 10, 10, 11] * 4
            random.shuffle(deck)
            hand = [deck.pop(), deck.pop()]
            dealer_hand = [deck.pop(), deck.pop()]
            player_val = hand_value(hand)
            dealer_val = hand_value(dealer_hand)
            def hand_value(cards):
                value = sum(cards)
                aces = cards.count(11)
                while value > 21 and aces:
                    value -= 10
                    aces -= 1
                return value
            # Player's turn
            while dealer_val < 17:
                dealer_hand.append(deck.pop())
                dealer_val = hand_value(dealer_hand)
            # Determine result
            if player_val > 21:
                result = f"You busted! Lost ${bet}."
                character.money -= bet
            # you win if dealer busts or player has higher value    
            elif dealer_val > 21 or player_val > dealer_val:
                win_amount = bet * 2
                result = f"You win! Won ${win_amount}."
                character.money += win_amount
            # you tie if both have same value    
            elif player_val == dealer_val:
                result = "Push! It's a tie."
            # you lose if dealer has higher value    
            else:
                result = f"You lose! Lost ${bet}."
                character.money -= bet
                

            # Store in session
            session['casino_result'] = result
            session['casino_hand'] = hand
            session['casino_dealer_hand'] = dealer_hand

        elif table == 'coinflip':
            import secrets
            flip = secrets.choice(['heads', 'tails'])
            user_choice = request.form.get('coin_choice', 'heads')
            if user_choice == flip:
                win_amount = bet * 2
                result = f"You won the coin flip! Won ${win_amount}."
                character.money += win_amount
                
            else:
                result = f"You lost the coin flip! Lost ${bet}."
                character.money -= bet
                
            session['casino_result'] = result
            session['casino_flip'] = flip

        elif table == 'roulette':
            import secrets
            user_choice = request.form.get('roulette_choice', 'red')
            roulette_result = secrets.choice(['red', 'black', 'green'])
            if user_choice == roulette_result:
                if roulette_result == 'green':
                    win_amount = bet * 14
                    result = f"Green! You won ${win_amount}!"
                    character.money += win_amount
                    
                else:
                    win_amount = bet * 2
                    result = f"You won on {roulette_result}! Won ${win_amount}."
                    character.money += win_amount
                    
            else:
                result = f"You lost on {roulette_result}! Lost ${bet}."
                character.money -= bet
                flash(result, "danger")
            session['casino_result'] = result
            session['casino_roulette_result'] = roulette_result

        db.session.commit()
        return redirect(url_for('casino', table=table))

    # GET: retrieve from session if present
    result = session.pop('casino_result', None)
    hand = session.pop('casino_hand', [])
    dealer_hand = session.pop('casino_dealer_hand', [])
    flip = session.pop('casino_flip', None)
    roulette_result = session.pop('casino_roulette_result', None)

    return render_template(
        'casino.html',
        result=result,
        hand=hand,
        dealer_hand=dealer_hand,
        bet=bet,
        character=character,
        table=table,
        blackjack_form=blackjack_form,
        coinflip_form=coinflip_form,
        roulette_form=roulette_form,
        user_choice=user_choice,
        flip=flip,
        roulette_result=roulette_result
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
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()

    if not character or not character.crew_id:
        flash("You must be in a crew to invite others.")
        return redirect(url_for('dashboard'))

    crew = Crew.query.get(character.crew_id)
    form = InviteToCrewForm()

    if form.validate_on_submit():
        username = form.username.data.strip()
        invitee = Character.query.filter_by(name=username, is_alive=True).first()
        if not invitee:
            flash("Character not found.")
            return redirect(url_for('invite_to_crew'))

        if invitee.crew_id:
            flash("This character is already in a crew.")
            return redirect(url_for('invite_to_crew'))

        existing_invite = CrewInvitation.query.filter_by(invitee_id=invitee.id, crew_id=crew.id).first()
        if existing_invite:
            flash("An invite has already been sent to this character.")
            return redirect(url_for('invite_to_crew'))

        new_invite = CrewInvitation(
            inviter_id=current_user.id,
            invitee_id=invitee.master_id,
            crew_id=crew.id
        )
        db.session.add(new_invite)
        db.session.commit()

        flash(f"Invite sent to {invitee.name}!", "success")
        return redirect(url_for('dashboard'))

    return render_template('invite_to_crew.html', crew=crew, form=form)

@app.route('/claim_godfather/<city>', methods=['POST'])
@login_required
def claim_godfather(city):
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    form = ClaimGodfatherForm(prefix=city.replace(" ", "_"))
    if not form.validate_on_submit():
        flash("Invalid form submission.", "danger")
        return redirect(url_for('dashboard'))
    if not character:
        flash("No character found.", "danger")
        return redirect(url_for('dashboard'))
    
    # Check if city already has a Godfather
    existing = Godfather.query.filter_by(city=city).first()
    if existing:
        flash(f"{city} already has a Godfather!", "danger")
        return redirect(url_for('dashboard'))

    # Check if this character is already Godfather somewhere
    if Godfather.query.filter_by(character_id=character.id).first():
        flash("You are already a Godfather of another city!", "danger")
        return redirect(url_for('dashboard'))
    # Define ClaimGodfatherForm if not already defined
    
    if character.level < 40:
        flash("You must be at least level 40 to claim a Godfather position.", "danger")
        return redirect(url_for('dashboard'))
    claim_forms = {city: ClaimGodfatherForm() for city in CITIES}
    godfather = Godfather(city=city, character_id=character.id)
    db.session.add(godfather)
    db.session.commit()
    flash(f"You are now the Godfather of {city}!", "success")
    return redirect(url_for('dashboard'))

@app.route('/create_crime', methods=['GET', 'POST'])
@login_required
def create_crime():
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    if not character:
        flash("No active character found.", "danger")
        return redirect(url_for('dashboard'))
    if character.in_jail and character.jail_until and character.jail_until > datetime.utcnow():
        remaining = character.jail_until - datetime.utcnow()
        mins, secs = divmod(int(remaining.total_seconds()), 60)
        flash(f"You are in jail for {mins}m {secs}s.", "danger")
        return redirect(url_for('jail'))
    # If already in a crime group, redirect and do NOT create a new one
    
    form = CreateCrimeForm()
    if form.validate_on_submit():
        character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
        db_character = Character.query.get(character.id)
        if character.crime_group:
            flash("You are already in a crime group!", "warning")
            return redirect(url_for('crime_group'))
        if not db_character:
            flash("Your character does not exist in the database.", "danger")
            return redirect(url_for('dashboard'))
        if not character:
            flash("You must have an active character to create a crime group.", "danger")
            return redirect(url_for('dashboard'))
        
        cooldown_minutes = 360  # 6 hours for leaders
        if is_on_crime_cooldown(character, cooldown_minutes):
            wait_time = (character.last_crime_time + timedelta(minutes=cooldown_minutes)) - datetime.utcnow()
            flash(f"You must wait {wait_time.seconds // 3600}h {((wait_time.seconds // 60) % 60)}m before starting a new crime group.", "warning")
            return redirect(url_for('dashboard'))

        crime_name = request.form.get('crime_name', '').strip()
        if not crime_name:
            crime_name = f"{character.name}'s Crew"

        invite_code = generate_unique_invite_code()

        # --- Only use character.id as leader_id ---
        crime = OrganizedCrime(name=crime_name, leader_id=character.id, invite_code=invite_code)
        db.session.add(crime)
        db.session.commit()
        # FIX: Set the creator's crime_group_id to the new crime group
        character.crime_group_id = crime.id
        db.session.commit()
        flash(f"Crime group '{crime_name}' created! Invite code: {invite_code}", 'success')
        return redirect(url_for('crime_group'))

    return render_template('create_crime.html', create_crime_form=form)

@app.route('/join_crime', methods=['GET', 'POST'])
@login_required
def join_crime():
    form = JoinCrimeForm()
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    if not character:
        flash("No active character found. Please create one first.", "danger")
        return redirect(url_for('dashboard'))

    if character.crime_group:
        flash("You're already in a crime group!", 'warning')
        return redirect(url_for('dashboard'))

    cooldown_minutes = 20  # 20 minutes for members
    if is_on_crime_cooldown(character, cooldown_minutes):
        wait_time = (character.last_crime_time + timedelta(minutes=cooldown_minutes)) - datetime.utcnow()
        flash(f"You must wait {wait_time.seconds // 60}m before joining a new crime group.", "warning")
        return redirect(url_for('dashboard'))

    if form.validate_on_submit():
        code = form.invite_code.data.strip().upper()
        crime = OrganizedCrime.query.filter_by(invite_code=code).first()
        if not crime:
            flash("Invalid invite code.", 'danger')
        elif crime.is_full():
            flash("That crime group is full!", 'warning')
        else:
            character.crime_group_id = crime.id
            
            db.session.commit()
            flash("You joined the crime group!", 'success')
            return redirect(url_for('crime_group'))
    return render_template('join_crime.html', join_crime_form=form)



@app.route('/territories', methods=['GET', 'POST'])
@login_required
def territories():
    
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    territories = Territory.query.all()
    crews = Crew.query.all()
    if character.in_jail and character.jail_until and character.jail_until > datetime.utcnow():
        remaining = character.jail_until - datetime.utcnow()
        mins, secs = divmod(int(remaining.total_seconds()), 60)
        flash(f"You are in jail for {mins}m {secs}s.", "danger")
        return redirect(url_for('jail'))
    crews_by_id = {c.id: c for c in crews}
    
    claim_forms = {t.id: ClaimTerritoryForm(prefix=f"claim_{t.id}") for t in territories}
    takeover_forms = {t.id: StartTakeoverForm(prefix=f"takeover_{t.id}") for t in territories}
    resolve_forms = {t.id: ResolveTakeoverForm(prefix=f"resolve_{t.id}") for t in territories}
    payout_form = CrewPayoutForm(prefix="payout")
    
    return render_template(
        'territories.html',
        territories=territories,
        character=character,
        crews_by_id=crews_by_id,
        claim_forms=claim_forms,
        takeover_forms=takeover_forms,
        resolve_forms=resolve_forms,
        payout_form=payout_form
    )
@app.route('/territory_minigame/<city>', methods=['POST', 'GET'])
@login_required
def territory_minigame(city):
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    territory = Territory.query.filter_by(city=city).first()
    if not character or not character.crew_id or not territory:
        flash("Invalid request.", "danger")
        return redirect(url_for('territories'))

    # Only allow if territory is being contested and your crew is the challenger
    if territory.contesting_crew_id != character.crew_id:
        flash("Your crew is not contesting this territory.", "danger")
        return redirect(url_for('territories'))

    # Only allow after contest period is over
    if not territory.contested_until or territory.contested_until > datetime.utcnow():
        flash("The contest is not over yet!", "warning")
        return redirect(url_for('territories'))

    # Minigame: Each crew rolls a dice (1-100), highest wins
    
    challenger_roll = random.randint(1, 100)
    defender_roll = random.randint(1, 100)
    winner = None
    if territory.owner_crew_id:
        defender_crew = Crew.query.get(territory.owner_crew_id)
    else:
        defender_crew = None

    if challenger_roll > defender_roll:
        # Challenger wins
        territory.owner_crew_id = character.crew_id
        winner = "challenger"
        flash(f"Your crew rolled {challenger_roll} vs {defender_roll} and WON the territory!", "success")
    elif defender_roll > challenger_roll:
        winner = "defender"
        flash(f"Your crew rolled {challenger_roll} vs {defender_roll} and LOST the territory.", "danger")
    else:
        winner = "tie"
        flash(f"It's a tie! Both crews rolled {challenger_roll}. Try again.", "info")

    # End contest
    territory.contesting_crew_id = None
    territory.contested_until = None
    db.session.commit()
    return redirect(url_for('territories'))
@app.route('/start_takeover/<city>', methods=['POST'])
@login_required
def start_takeover(city):
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    if not character or not character.crew_id:
        flash("You must be in a crew to start a takeover.", "danger")
        return redirect(url_for('dashboard'))
    crew = Crew.query.get(character.crew_id)
    territory = Territory.query.filter_by(city=city).first()
    if not territory:
        flash("No such territory.", "danger")
        return redirect(url_for('dashboard'))
    if territory.owner_crew_id == crew.id:
        flash("You already own this territory.", "info")
        return redirect(url_for('dashboard'))
    if territory.contested_until and territory.contested_until > datetime.utcnow():
        flash("This territory is already being contested!", "warning")
        return redirect(url_for('dashboard'))
    # Start contest (e.g., 30 minutes)
    territory.contested_until = datetime.utcnow() + timedelta(minutes=30)
    territory.contesting_crew_id = crew.id
    db.session.commit()
    flash(f"Takeover started! Your crew must win the contest in 30 minutes.", "success")
    return redirect(url_for('dashboard'))
@app.route('/resolve_takeover/<city>', methods=['POST'])
@login_required
def resolve_takeover(city):
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    if not character or not character.crew_id:
        flash("You must be in a crew.", "danger")
        return redirect(url_for('dashboard'))
    crew = Crew.query.get(character.crew_id)
    territory = Territory.query.filter_by(city=city).first()
    if not territory or not territory.contesting_crew_id:
        flash("No ongoing contest for this territory.", "info")
        return redirect(url_for('dashboard'))
    if territory.contesting_crew_id != crew.id:
        flash("Your crew is not contesting this territory.", "danger")
        return redirect(url_for('dashboard'))
    if not territory.contested_until or territory.contested_until > datetime.utcnow():
        flash("The contest is not over yet!", "warning")
        return redirect(url_for('dashboard'))
    # Transfer ownership
    territory.owner_crew_id = crew.id
    territory.contesting_crew_id = None
    territory.contested_until = None
    db.session.commit()
    flash(f"Your crew has taken over {city}!", "success")
    return redirect(url_for('dashboard'))
@app.route('/crime_group')
@login_required
def crime_group():
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    crime = character.crime_group

    if not character or not crime:
        flash("You must be in a crime group to access this page.", "warning")
        return redirect(url_for('dashboard'))

    members = Character.query.filter_by(crime_group_id=crime.id).all()
    

    if character.in_jail and character.jail_until and character.jail_until > datetime.utcnow():
        remaining = character.jail_until - datetime.utcnow()
        mins, secs = divmod(int(remaining.total_seconds()), 60)
        flash(f"You are in jail for {mins}m {secs}s.", "danger")
        return redirect(url_for('dashboard'))

    return render_template(
        "crime_group.html",
        crime=crime,
        members=members,
        leave_crime_form=LeaveCrimeForm(),
        disband_crime_form=DisbandCrimeForm(),
        attempt_crime_form=AttemptCrimeForm()
    )

@app.route('/disband_crime', methods=['POST'])
@login_required
def disband_crime():
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    if not character or not character.crime_group:
        flash("You're not in any crime group.", "warning")
        return redirect(url_for('dashboard'))
        
    crime = character.crime_group
    if crime.leader_id != character.id:
        flash("Only the group leader can disband the crime group.", "danger")
        return redirect(url_for('crime_group'))
    
    for member in crime.members:
        member.crime_group_id = None

    db.session.delete(crime)
    db.session.commit()
    
    flash("Crime group has been disbanded.", "success")
    return redirect(url_for('dashboard'))

@app.route('/upload_profile_image', methods=['POST'])
@login_required
def upload_profile_image():
    form = UploadImageForm()
    if not form.validate_on_submit():
        flash('Invalid form submission.', 'danger')
        return redirect(request.referrer or url_for('dashboard'))
    file = form.profile_image.data
    if file and allowed_file(file.filename, ALLOWED_EXTENSIONS):
        # Check MIME type
        file.seek(0)
        try:
            img = Image.open(file)
            img.verify()
            file.seek(0)
        except Exception:
            flash('Uploaded file is not a valid image.', 'danger')
            return redirect(request.referrer or url_for('dashboard'))
        if file.mimetype not in ALLOWED_MIME_TYPES:
            flash('Invalid image type.', 'danger')
            return redirect(request.referrer or url_for('dashboard'))
        file.seek(0, os.SEEK_END)
        file_length = file.tell()
        file.seek(0)
        if file_length > app.config['MAX_CONTENT_LENGTH']:
            flash('File is too large.', 'danger')
            return redirect(request.referrer or url_for('dashboard'))
        filename = secure_filename(file.filename)
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(save_path)
        # Save the path to the user's character
        character = Character.query.filter_by(master_id=current_user.id).first()
        if character:
            character.profile_image = f'uploads/{filename}'
            db.session.commit()
        flash('Profile image uploaded successfully.', 'success')
        return redirect(url_for('profile_by_id', char_id=character.id))
    else:
        flash('Invalid file type.', 'danger')
        return redirect(request.referrer or url_for('dashboard'))

@app.route('/crew_messages')
@login_required
def crew_messages():
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    if not character or not character.crew_id:
        return jsonify([])

    messages = ChatMessage.query.filter_by(channel='crew', crew_id=character.crew_id)\
        .order_by(ChatMessage.timestamp.asc())\
        .limit(50).all()

    result = []
    for m in messages:
        char = Character.query.filter_by(master_id=m.user_id).first()
        result.append({
            'character_name': char.name if char else m.username,
            'character_id': char.id if char else None,
            'message': m.message,
            'timestamp': m.timestamp.strftime('%H:%M') if hasattr(m, 'timestamp') and m.timestamp else ''
        })
    return jsonify(result)

@app.route('/crew_invitations')
@login_required
def crew_invitations():
    invitations = CrewInvitation.query.filter_by(invitee_id=current_user.id).all()
    return render_template('crew_invitations.html', invitations=invitations)

@app.route('/crews')
@login_required
def crews():
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    all_crews = Crew.query.all()
    # For each crew, find the leader, left hand, and right hand
    crew_roles = {}
    if character.in_jail and character.jail_until and character.jail_until > datetime.utcnow():
        remaining = character.jail_until - datetime.utcnow()
        mins, secs = divmod(int(remaining.total_seconds()), 60)
        flash(f"You are in jail for {mins}m {secs}s.", "danger")
        return redirect(url_for('jail'))
    for crew in all_crews:
        leader = left_hand = right_hand = None

        leader_member = CrewMember.query.filter_by(crew_id=crew.id, role='leader').first()
        if leader_member:
            leader_user = User.query.get(leader_member.user_id)
            if leader_user:
                leader_char = Character.query.filter_by(master_id=leader_user.id).first()
                leader = leader_char.name if leader_char else leader_user.username

        left_member = CrewMember.query.filter_by(crew_id=crew.id, role='left hand').first()
        if left_member:
            left_user = User.query.get(left_member.user_id)
            if left_user:
                left_char = Character.query.filter_by(master_id=left_user.id).first()
                left_hand = left_char.name if left_char else left_user.username

        right_member = CrewMember.query.filter_by(crew_id=crew.id, role='right hand').first()
        if right_member:
            right_user = User.query.get(right_member.user_id)
            if right_user:
                right_char = Character.query.filter_by(master_id=right_user.id).first()
                right_hand = right_char.name if right_char else right_user.username

        crew_roles[crew.id] = {
            'leader': leader,
            'left_hand': left_hand,
            'right_hand': right_hand
        }
    return render_template('crews.html', crews=all_crews, crew_roles=crew_roles)

@app.route('/godfathers', methods=['GET', 'POST'])
@login_required
def godfathers_page():
    godfathers = {g.city: g.character for g in Godfather.query.all()}
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    cities = CITIES
    claim_forms = {city: ClaimGodfatherForm(prefix=city.replace(" ", "_")) for city in cities}
    step_down_form = StepDownGodfatherForm()
    if character.in_jail and character.jail_until and character.jail_until > datetime.utcnow():
        remaining = character.jail_until - datetime.utcnow()
        mins, secs = divmod(int(remaining.total_seconds()), 60)
        flash(f"You are in jail for {mins}m {secs}s.", "danger")
        return redirect(url_for('jail'))
    return render_template(
        'godfathers.html',
        character=character,
        godfathers=godfathers,
        cities=cities,
        claim_forms=claim_forms,
        step_down_form=step_down_form
    )

@app.route('/accept_invite/<int:invite_id>')
@login_required
def accept_invite(invite_id):
    invitation = CrewInvitation.query.get(invite_id)
    if invitation and invitation.invitee_id == current_user.id:
        current_user.crew_id = invitation.crew_id
        CrewMember.query.filter_by(user_id=current_user.id).delete()
        db.session.add(CrewMember(crew_id=invitation.crew_id, user_id=current_user.id, role='member'))
        # --- FIX: update character's crew_id ---
        character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
        if character:
            character.crew_id = invitation.crew_id
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
    CREW_COST = 1500000
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    if not character:
        flash("You must have a character to create a crew.", "danger")
        return redirect(url_for('dashboard'))

    form = CreateCrewForm()
    if form.validate_on_submit():
        crew_name = request.form.get('crew_name', '').strip()
        city = character.city  # Use character's current city

        if Crew.query.filter_by(name=crew_name).first():
            flash("Crew name already exists.")
            return redirect(url_for('create_crew'))

        if character.level < MIN_LEVEL:
            flash(f"You must be at least level {MIN_LEVEL} to create a crew.")
            return redirect(url_for('create_crew'))

        if character.money < CREW_COST:
            flash(f"You need at least ${CREW_COST} to create a crew.")
            return redirect(url_for('create_crew'))

        # If any Godfather exists, submit a request instead of creating
        if Crew.query.filter_by(city=city).first():
            # Check for existing pending request
            if CrewRequest.query.filter_by(user_id=current_user.id, status='pending').first():
                flash("You already have a pending crew request.", "warning")
                return redirect(url_for('dashboard'))
            req = CrewRequest(crew_name=crew_name, user_id=current_user.id, city=city)
            db.session.add(req)
            db.session.commit()
            flash("Your crew request has been sent to the Godfather for approval.", "info")
            return redirect(url_for('dashboard'))

        # Otherwise, create the crew immediately
        character.money -= CREW_COST
        new_crew = Crew(name=crew_name, city=city)
        db.session.add(new_crew)
        db.session.commit()

        crew_member = CrewMember(crew_id=new_crew.id, user_id=current_user.id, role='leader')
        db.session.add(crew_member)
        character.crew_id = new_crew.id
        db.session.commit()

        flash(f"Crew created and joined! You spent ${CREW_COST}.", "success")
        return redirect(url_for('dashboard'))

    return render_template('create_crew.html', form=form)

@app.route('/crew_requests')
@login_required
def crew_requests():
    user = User.query.get(current_user.is_admin)
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    godfather = Godfather.query.filter_by(character_id=character.id).first()
    if character.in_jail and character.jail_until and character.jail_until > datetime.utcnow():
            remaining = character.jail_until - datetime.utcnow()
            mins, secs = divmod(int(remaining.total_seconds()), 60)
            flash(f"You are in jail for {mins}m {secs}s.", "danger")
            return redirect(url_for('jail'))
    if not godfather:
        flash("Only Godfathers can approve crew requests.", "danger")
        return redirect(url_for('dashboard'))
    requests = CrewRequest.query.filter_by(city=godfather.city, status='pending').all()
    approve_forms = {req.id: ApproveCrewRequestForm() for req in requests}
    deny_forms = {req.id: DenyCrewRequestForm() for req in requests}
    return render_template(
        'crew_requests.html',
        requests=requests,
        character=character,
        approve_forms=approve_forms,
        deny_forms=deny_forms
    )

@app.route('/approve_crew_request/<int:req_id>', methods=['POST'])
@login_required
def approve_crew_request(req_id):
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    godfather = Godfather.query.filter_by(character_id=character.id).first()
    req = CrewRequest.query.get_or_404(req_id)
    if not godfather or godfather.city != req.city:
        flash("You are not authorized to approve this request.", "danger")
        return redirect(url_for('dashboard'))
    # Approve: create crew, assign leader, deduct money
    user = req.user
    leader_char = Character.query.filter_by(master_id=user.id, is_alive=True).first()
    if not leader_char or leader_char.money < 1500000:
        req.status = 'denied'
        db.session.commit()
        flash("User does not have enough money or character is missing.", "danger")
        return redirect(url_for('crew_requests'))
    leader_char.money -= 1500000
    new_crew = Crew(name=req.crew_name, city=req.city)
    db.session.add(new_crew)
    db.session.commit()
    crew_member = CrewMember(crew_id=new_crew.id, user_id=user.id, role='leader')
    db.session.add(crew_member)
    leader_char.crew_id = new_crew.id
    req.status = 'approved'
    db.session.commit()
    flash(f"Crew '{req.crew_name}' approved and created.", "success")
    return redirect(url_for('crew_requests'))

@app.route('/deny_crew_request/<int:req_id>', methods=['POST'])
@login_required
def deny_crew_request(req_id):
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    godfather = Godfather.query.filter_by(character_id=character.id).first()
    req = CrewRequest.query.get_or_404(req_id)
    if not godfather or godfather.city != req.city:
        flash("You are not authorized to deny this request.", "danger")
        return redirect(url_for('dashboard'))
    req.status = 'denied'
    db.session.commit()
    flash("Crew request denied.", "info")
    return redirect(url_for('crew_requests'))

@app.route('/earn', methods=['POST', 'GET'])
@login_required
def earn():
    if not hasattr(current_user, 'character') or current_user.character is None:
        flash('No character found.', 'danger')
        return redirect(url_for('dashboard'))

    character = current_user.character

    now = datetime.utcnow()

    if character.in_jail and character.jail_until and character.jail_until > now:
        remaining = character.jail_until - now
        mins, secs = divmod(int(remaining.total_seconds()), 60)
        flash(f"You are in jail for {mins}m {secs}s.", "danger")
        return redirect(url_for('dashboard'))

    if hasattr(character, 'last_earned') and character.last_earned:
        cooldown = timedelta(seconds=120) # Random cooldown between 30 and 120 seconds
        if now - character.last_earned < cooldown:
            seconds_remaining = int((cooldown - (now - character.last_earned)).total_seconds())
            flash(f'Cooldown active. Please wait {seconds_remaining} seconds.', 'warning')
            return redirect(url_for('dashboard'))

    # Jail chance: 10% chance to be sent to jail for 1-5 minutes
    jail_chance = 0.50
    if random.random() < jail_chance:
        jail_minutes = random.randint(2, 15)
        character.in_jail = True
        character.jail_until = now + timedelta(minutes=jail_minutes)
        character.last_earned = now
        db.session.commit()
        flash(f"You got caught and are in jail for {jail_minutes} minutes!", "danger")
        return redirect(url_for('dashboard'))
    
    # Premium bonus
    
    money_min, money_max = 5000, 10000
    xp_min, xp_max = 25, 50
    if current_user.premium and current_user.premium_until and current_user.premium_until > now:
        money_min, money_max = int(money_min * 1.5), int(money_max * 1.5)
        xp_min, xp_max = int(xp_min * 1.5), int(xp_max * 1.5)
        cooldown = timedelta(seconds=-30)

    earned_money = random.randint(money_min, money_max)
    earned_xp = random.randint(xp_min, xp_max)
    character.money += earned_money
    character.xp += earned_xp
    character.last_earned = now

    # Level up: each level requires level * 250 XP
    leveled_up = False
    while character.xp >= character.level * 250:
        character.xp -= character.level * 250
        character.level += 1
        leveled_up = True

    db.session.commit()  # Always commit after earning

    if leveled_up:
        flash(f"You leveled up to level {character.level}!", "success")

    flash(f"You earned ${earned_money} and {earned_xp} XP!", "success")
    return redirect(url_for('dashboard'))

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

@app.route('/steal', methods=['GET', 'POST'])
@login_required
def steal():
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    form = StealForm()
    if not character:
        flash("No character found.", "danger")
        return redirect(url_for('dashboard'))

    if character.in_jail and character.jail_until and character.jail_until > datetime.utcnow():
        remaining = character.jail_until - datetime.utcnow()
        mins, secs = divmod(int(remaining.total_seconds()), 60)
        flash(f"You are in jail for {mins}m {secs}s.", "danger")
        return redirect(url_for('jail'))
    
    if character.steal_cooldown and character.steal_cooldown > datetime.utcnow():
        remaining = character.steal_cooldown - datetime.utcnow()
        hours, mins, secs = 0, 0, 0
        if remaining.total_seconds() > 0:
            hours, remainder = divmod(int(remaining.total_seconds()), 3600)
            mins, secs = divmod(remainder, 60)
        flash(f"You must wait {hours}h {mins}m {secs}s before stealing again.", "warning")
        return redirect(url_for('dashboard'))
    
    if form.validate_on_submit():
        target_name = form.target_name.data.strip()
        target = Character.query.filter_by(name=target_name, is_alive=True).first()
        
        if not target:
            flash("Target not found.", "danger")
            return redirect(url_for('dashboard'))

        if target.id == character.id:
            flash("You can't steal from yourself!", "warning")
            return redirect(url_for('dashboard'))
        if target.city != character.city:
            flash("Target is not in your city.", "warning")
            return redirect(url_for('dashboard'))
        if target.money < 100:
            flash("Target doesn't have enough money to steal.", "info")
            return redirect(url_for('dashboard'))
        
        # 30% chance to succeed
        if random.random() < 0.3:
            amount = random.randint(10000, min(2000000, target.money))
            target.money -= amount
            character.money += amount
            character.steal_cooldown = datetime.utcnow() + timedelta(minutes=1)
            db.session.commit()
            flash(f"Success! You stole ${amount} from {target.name}.", "success")

            # --- Notify the victim, sometimes with the thief's name ---
            reveal_chance = 0.2  # 20% chance to reveal thief
            if random.random() < reveal_chance:
                notif_msg = f"{character.name} stole ${amount} from you!"
            else:
                notif_msg = f"Someone stole ${amount} from you!"
            notif = Notification(
                user_id=target.master_id,
                message=notif_msg,
                timestamp=datetime.utcnow()
            )
            db.session.add(notif)
            db.session.commit()
        else:

            if random.random() < 0.1: # 10% chance to go to jail for 0 minutes
                jail_minutes = random.randint(0, 0)
                character.in_jail = True
                character.jail_until = datetime.utcnow() + timedelta(minutes=jail_minutes)
                db.session.commit()
                flash(f"You got caught and are in jail for {jail_minutes} minutes!", "danger")
                return redirect(url_for('jail'))
            else:
                flash("You failed to steal and got nothing.", "warning")
        # Set cooldown for stealing
        character.steal_cooldown = datetime.utcnow() + timedelta(hours=5)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('steal.html', form=form, character=character)

@app.route('/earn_status')
@login_required
def earn_status():
    # Use the same cooldown logic as in the /earn route
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    if not character:
        return jsonify({'seconds_remaining': 0})

    now = datetime.utcnow()
    cooldown = timedelta(seconds=120)  # Cooldown of 2 minutes

    if character.last_earned:
        elapsed = now - character.last_earned
        remaining = cooldown - elapsed
        seconds_remaining = max(0, int(remaining.total_seconds()))
    elif current_user.premium and current_user.premium_until and current_user.premium_until > now:
        cooldown = timedelta(seconds=30)
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

@app.route('/profile/id/<int:char_id>', methods=['GET', 'POST'])
def profile_by_id(char_id):
    character = Character.query.get_or_404(char_id)
    user = User.query.filter_by(id=character.master_id).first()
    crew = db.session.get(Crew, character.crew_id) if character.crew_id else None
    form = EditBioForm(obj=character)
    if form.validate_on_submit() and current_user.id == user.id:
        character.bio = form.bio.data
        db.session.commit()
        flash('Bio updated!', 'success')
        return redirect(url_for('profile_by_id', char_id=character.id))
    return render_template('profile.html', user=user, character=character,
    upload_image_form=UploadImageForm(),
    kill_form=KillForm(), crew=crew, form=form)

@app.route('/step_down_godfather', methods=['POST'])
@login_required
def step_down_godfather():
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    godfather = Godfather.query.filter_by(character_id=character.id).first()
    if not godfather:
        flash("You are not a Godfather.", "danger")
        return redirect(url_for('dashboard'))
    db.session.delete(godfather)
    db.session.commit()
    flash("You have stepped down as Godfather.", "success")
    return redirect(url_for('dashboard'))

@app.route('/send_public_message', methods=['POST'])
@limiter.limit("10 per minute, 10 per second")
@login_required
def send_public_message():
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    if not character:
        return jsonify({"error": "No active character found."}), 400
    form = ChatForm()
    if form.validate_on_submit():
        message = form.message.data.strip()
        if not message:
            return jsonify({"error": "Empty message"}), 400
        chat_msg = ChatMessage(
            username=character.name,
            message=message,
            channel='public',
            user_id=current_user.id
        )
        db.session.add(chat_msg)
        db.session.commit()
        return jsonify(success=True)
    return jsonify(error="Invalid message or CSRF token."), 400

@app.route('/drug_dashboard', methods=['GET', 'POST'])
@login_required
def drug_dashboard():
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    if not character:
        flash("No character found.", "danger")
        return redirect(url_for('dashboard'))

    if character.in_jail and character.jail_until and character.jail_until > datetime.utcnow():
        remaining = character.jail_until - datetime.utcnow()
        mins, secs = divmod(int(remaining.total_seconds()), 60)
        flash(f"You are in jail for {mins}m {secs}s.", "danger")
        return redirect(url_for('jail'))

    drugs = Drug.query.all()
    dealers = {dealer.drug_id: dealer for dealer in DrugDealer.query.filter_by(city=character.city).all()}
    inventory = {inv.drug_id: inv for inv in CharacterDrugInventory.query.filter_by(character_id=character.id).all()}

    buy_forms = {drug.id: BuyDrugForm(prefix=f'buy_{drug.id}') for drug in drugs}
    sell_forms = {drug.id: SellDrugForm(prefix=f'sell_{drug.id}') for drug in drugs}

    # Handle buy POSTs
    for drug in drugs:
        dealer = dealers.get(drug.id)
        form = buy_forms[drug.id]
        if dealer and form.validate_on_submit() and form.submit.data and form.quantity.data and f'buy_{drug.id}-submit' in request.form:
            quantity = form.quantity.data
            if quantity < 1 or quantity > dealer.stock:
                flash("Invalid quantity.", "danger")
                return redirect(url_for('drug_dashboard'))
            total_price = dealer.price * quantity
            if character.money < total_price:
                flash("Not enough money.", "danger")
                return redirect(url_for('drug_dashboard'))
            character.money -= total_price
            dealer.stock -= quantity
            inv = inventory.get(drug.id)
            if not inv:
                inv = CharacterDrugInventory(character_id=character.id, drug_id=drug.id, quantity=0)
                db.session.add(inv)
                inventory[drug.id] = inv
            inv.quantity += quantity
            db.session.commit()
            flash(f"You bought {quantity}x {drug.name} for ${total_price}.", "success")
            return redirect(url_for('drug_dashboard'))

    # Handle sell POSTs
    for drug in drugs:
        dealer = dealers.get(drug.id)
        inv = inventory.get(drug.id)
        form = sell_forms[drug.id]
        if dealer and inv and form.validate_on_submit() and form.submit.data and form.quantity.data and f'sell_{drug.id}-submit' in request.form:
            quantity = form.quantity.data
            if quantity < 1 or quantity > inv.quantity:
                flash("Invalid quantity.", "danger")
                return redirect(url_for('drug_dashboard'))
            total_price = dealer.price * quantity
            character.money += total_price
            inv.quantity -= quantity
            dealer.stock += quantity
            db.session.commit()
            flash(f"You sold {quantity}x {drug.name} for ${total_price}.", "success")
            return redirect(url_for('drug_dashboard'))

    return render_template(
        'drug_dashboard.html',
        character=character,
        drugs=drugs,
        dealers=dealers,
        inventory=inventory,
        buy_forms=buy_forms,
        sell_forms=sell_forms
    )

@app.route('/public_messages')
@limiter.limit("1000 per minute")
@login_required
def public_messages():
    messages = ChatMessage.query.filter_by(channel='public')\
        .order_by(ChatMessage.timestamp.desc())\
        .limit(50).all()
    if not messages:
        return jsonify([])
    result = []
    for m in reversed(messages):
        char = Character.query.filter_by(master_id=m.user_id).first()
        result.append({
            'character_name': char.name if char else m.username,
            'character_id': char.id if char else None,
            'message': m.message,
            'timestamp': m.timestamp.strftime('%H:%M') if hasattr(m, 'timestamp') and m.timestamp else ''
        })
    return jsonify(result)

@app.route('/buy_drug/<int:dealer_id>', methods=['POST'])
@login_required
def buy_drug_form(dealer_id, form=None):
    if form is None:
        form = BuyDrugForm(request.form, prefix=f'buy_{dealer_id}')
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    dealer = DrugDealer.query.get_or_404(dealer_id)
    quantity = form.quantity.data

    # Fix: Ensure quantity is valid
    if quantity is None:
        flash("Please enter a quantity.", "danger")
        return redirect(url_for('drug_dashboard'))

    if dealer.city != character.city:
        flash("Dealer not in your city.", "danger")
        return redirect(url_for('drug_dashboard'))
    if quantity < 1 or quantity > dealer.stock:
        flash("Invalid quantity.", "danger")
        return redirect(url_for('drug_dashboard'))
    total_price = dealer.price * quantity
    if character.money < total_price:
        flash("Not enough money.", "danger")
        return redirect(url_for('drug_dashboard'))
    character.money -= total_price
    dealer.stock -= quantity
    inv = CharacterDrugInventory.query.filter_by(character_id=character.id, drug_id=dealer.drug_id).first()
    if not inv:
        inv = CharacterDrugInventory(character_id=character.id, drug_id=dealer.drug_id, quantity=0)
        db.session.add(inv)
    inv.quantity += quantity
    db.session.commit()
    flash(f"You bought {quantity}x {dealer.drug.name} for ${total_price}.", "success")
    return redirect(url_for('drug_dashboard'))

@app.route('/sell_drug/<int:drug_id>', methods=['POST'])
@login_required
def sell_drug_form(drug_id, form=None):
    if form is None:
        form = SellDrugForm(request.form, prefix=f'sell_{drug_id}')
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    quantity = form.quantity.data

    # Fix: Ensure quantity is valid
    if quantity is None:
        flash("Please enter a quantity.", "danger")
        return redirect(url_for('drug_dashboard'))

    inv = CharacterDrugInventory.query.filter_by(character_id=character.id, drug_id=drug_id).first()
    if not inv or inv.quantity < quantity or quantity < 1:
        flash("Not enough drugs to sell.", "danger")
        return redirect(url_for('drug_dashboard'))
    dealer = DrugDealer.query.filter_by(city=character.city, drug_id=drug_id).first()
    if not dealer:
        flash("No dealer in your city buys this drug.", "danger")
        return redirect(url_for('drug_dashboard'))
    total_price = dealer.price * quantity
    character.money += total_price
    inv.quantity -= quantity
    dealer.stock += quantity
    db.session.commit()
    flash(f"You sold {quantity}x {dealer.drug.name} for ${total_price}.", "success")
    return redirect(url_for('drug_dashboard'))

@app.route('/city/<city_name>')
@login_required
def city_characters(city_name):
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    if character.in_jail and character.jail_until and character.jail_until > datetime.utcnow():
        remaining = character.jail_until - datetime.utcnow()
        mins, secs = divmod(int(remaining.total_seconds()), 60)
        flash(f"You are in jail for {mins}m {secs}s.", "danger")
        return redirect(url_for('jail'))
    # Only allow valid cities
    if city_name not in CITIES:
        flash("Invalid city.", "danger")
        return redirect(url_for('dashboard'))
    # Show only alive, non-NPC characters in the city
    characters = Character.query.filter_by(city=city_name, is_alive=True).filter(Character.master_id != 0).all()
    return render_template('city_characters.html', city=city_name, characters=characters)

@app.route('/claim_territory/<city>', methods=['POST'])
@login_required
def claim_territory(city):
    
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    if not character or not character.crew_id:
        flash("You must be in a crew to claim a city.", "danger")
        return redirect(url_for('territories'))
    crew = Crew.query.get(character.crew_id)
    territory = Territory.query.filter_by(city=city).first()
    if not territory:
        flash("No such city.", "danger")
        return redirect(url_for('territories'))
    if territory.owner_crew_id:
        flash("This city is already claimed.", "warning")
        return redirect(url_for('territories'))
    territory.owner_crew_id = crew.id
    db.session.commit()
    flash(f"{city} is now controlled by your crew!", "success")
    return redirect(url_for('territories'))
@app.route('/territory/<int:territory_id>/customize', methods=['GET', 'POST'])
@login_required
def customize_territory(territory_id):
    territory = Territory.query.get_or_404(territory_id)
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    if not character or not character.crew_id or territory.owner_crew_id != character.crew_id:
        flash("Only the owning crew can customize this territory.", "danger")
        return redirect(url_for('territories'))
    form = RenameTerritoryForm(obj=territory)
    if form.validate_on_submit():
        territory.custom_name = form.custom_name.data.strip() or None
        territory.theme = form.theme.data.strip() or None
        db.session.commit()
        flash("Territory updated!", "success")
        return redirect(url_for('territories'))
    return render_template('customize_territory.html', form=form, territory=territory)
@app.route('/crew_payout', methods=['POST'])
@login_required
def crew_payout():
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    if not character or not character.crew_id:
        flash("You must be in a crew to receive payouts.", "danger")
        return redirect(url_for('dashboard'))
    crew = Crew.query.get(character.crew_id)
    # Sum all territory payouts
    total_payout = sum(t.payout for t in crew.territories_owned)
    members = CrewMember.query.filter_by(crew_id=crew.id).all()
    if not members or total_payout == 0:
        flash("No payout available.", "info")
        return redirect(url_for('crew_page', crew_id=crew.id))
    split = total_payout // len(members)
    for member in members:
        char = Character.query.filter_by(master_id=member.user_id, is_alive=True).first()
        if char:
            char.money += split
    db.session.commit()
    flash(f"Crew territory payout distributed! Each member received ${split}.", "success")
    return redirect(url_for('crew_page', crew_id=crew.id))
# Create Flask app and configure it

@app.context_processor
def inject_upgrade_form():
    return dict(upgrade_form=UpgradeForm())
@app.context_processor
def inject_user():
    return dict(user=current_user)
@app.context_processor
def inject_current_character():
    from flask_login import current_user
    if current_user.is_authenticated:
        character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
        return dict(current_character=character)
    return dict(current_character=None)
@app.context_processor
def inject_is_godfather():
    if current_user.is_authenticated:
        character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
        if character and Godfather.query.filter_by(character_id=character.id).first():
            return dict(is_godfather=True)
    return dict(is_godfather=False)
@app.context_processor
def inject_now():
    from datetime import datetime
    return {'now': datetime.utcnow}

@app.context_processor
def inject_chat_form():
    return dict(chat_form=ChatForm())


# Start the background thread when the app starts

@app.cli.command("randomize-drug-prices")
def randomize_drug_prices_command():
    """Randomize all drug dealer prices (manual trigger)."""
    randomize_all_drug_prices()
    print("Drug dealer prices randomized.")

@app.cli.command("init-db")
def init_db():
    db.create_all()
    print("Database tables created.")

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    # Optionally log the error here
    return render_template('error/500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('error/403.html'), 403

@app.errorhandler(401)
def unauthorized_error(error):
    return render_template('error/401.html'), 401

@app.errorhandler(429)
def ratelimit_handler(e):
    flash("Too many requests, please slow down!", "warning")
    # Try to redirect to the referring page, or fallback to dashboard
    return redirect(request.referrer or url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
