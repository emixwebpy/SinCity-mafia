# -*- coding: utf-8 -*-
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, Blueprint, session, request
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_admin.contrib.sqla import ModelView
from flask_admin.form import SecureForm
from flask_wtf import CSRFProtect, FlaskForm,RecaptchaField
from flask_migrate import Migrate
from wtforms import PasswordField, StringField, BooleanField, IntegerField,SubmitField, SelectField,FileField,RadioField,TextAreaField,HiddenField
from wtforms.fields import DateTimeField
from wtforms.validators import DataRequired,NumberRange, Optional,Length
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from sqlalchemy import  true
from operator import is_
import  string, logging, random,threading, os, time, logging
from markupsafe import Markup, escape
from itsdangerous import URLSafeTimedSerializer
from PIL import Image
from urllib.parse import urlparse, urljoin
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# Constants -------------------------------
CITIES = ["New York", "Los Angeles", "Chicago", "Miami", "Las Vegas"]
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
ALLOWED_MIME_TYPES = {'image/png', 'image/jpeg', 'image/gif'}

# Database -------------------------------
app = Flask(__name__)
app.config['MAIL_SERVER'] = 'localhost'
app.config['MAIL_PORT'] = 1025
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = None
app.config['MAIL_PASSWORD'] = None
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@example.com')
mail = Mail(app)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', os.urandom(32))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB max file size
app.config['LOGIN_MESSAGE'] = None
app.config['LOGIN_MESSAGE_CATEGORY'] = "info"

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)
admin_logger = logging.getLogger('admin_actions')
admin_logger.setLevel(logging.INFO)
fh = logging.FileHandler('admin_actions.log')
admin_logger.addHandler(fh)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return (
        test_url.scheme in ('http', 'https') and
        ref_url.netloc == test_url.netloc
    )
def limiter_key_func():
    # Disable limiting for localhost
    if request.remote_addr in ('127.0.0.1', '::1'):
        return None  # disables limiting for this request
    return get_remote_address()
db = SQLAlchemy(app)
with app.app_context():
    db.create_all()

DATABASE = 'users.db'
login_manager = LoginManager(app)
login_manager.login_view = 'login'
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')
migrate = Migrate(app, db)
csrf = CSRFProtect(app)
limiter = Limiter(key_func=limiter_key_func, app=app, default_limits=["200 per day", "50 per hour"])
# Admin Authentication -------------------------------
def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not getattr(current_user, 'is_admin', False):
            flash("Admin access required.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Admin Interface -------------------------------

@admin_bp.route('/')
@admin_required
def admin_dashboard():
    
    user_count = User.query.count()
    forum_count = Forum.query.count()
    topic_count = ForumTopic.query.count()
    jailed_count = Character.query.filter_by(in_jail=True).count()
    
    return render_template('admin/dashboard.html',
                           user_count=user_count,
                           forum_count=forum_count,
                           topic_count=topic_count,
                           jailed_count=jailed_count)
# --- Admin users ---
@admin_bp.route('/users')
@admin_required
def admin_users():
    users = User.query.order_by(User.id.desc()).all()
    return render_template('admin/users.html', users=users)
# --- Admin forums ---
@admin_bp.route('/forums')
@admin_required
def admin_forums():
    forums = Forum.query.order_by(Forum.id.desc()).all()
    return render_template('admin/forums.html', forums=forums)
# --- Admin jail ---
@admin_bp.route('/jail')
@admin_required
def admin_jail():
    jailed = Character.query.filter_by(in_jail=True).all()
    return render_template('admin/jail.html', jailed=jailed)
# --- Admin characters ---
@admin_bp.route('/characters')
@admin_required
def admin_characters():
    characters = Character.query.order_by(Character.id.desc()).all()
    return render_template('admin/characters.html', characters=characters)
# --- Admin character edit ---
@admin_bp.route('/character/<int:char_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_character(char_id):
    character = Character.query.get_or_404(char_id)
    if request.method == 'POST':
        character.name = request.form.get('name', character.name)
        character.health = int(request.form.get('health', character.health))
        character.money = int(request.form.get('money', character.money))
        character.level = int(request.form.get('level', character.level))
        character.xp = int(request.form.get('xp', character.xp))
        character.is_alive = bool(request.form.get('is_alive', character.is_alive))
        db.session.commit()
        
        flash("Character updated.", "success")
        return redirect(url_for('admin.admin_characters'))
    return render_template('admin/edit_character.html', character=character,
    form=EditCharacterForm(obj=character))

# --- Admin Edit Forum ---
@admin_bp.route('/forums/<int:forum_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_forum(forum_id):
    forum = Forum.query.get_or_404(forum_id)
    form = EditForumForm(obj=forum)
    if form.validate_on_submit():
        forum.title = form.title.data
        forum.description = form.description.data
        db.session.commit()
        flash("Forum updated.", "success")
        return redirect(url_for('admin.admin_forums'))
    return render_template('admin/edit_forum.html', form=form, forum=forum)

# --- Admin Delete Forum ---
@admin_bp.route('/forums/<int:forum_id>/delete', methods=['POST'])
@admin_required
def admin_delete_forum(forum_id):
    forum = Forum.query.get_or_404(forum_id)
    db.session.delete(forum)
    db.session.commit()
    flash("Forum deleted.", "success")
    return redirect(url_for('admin.admin_forums'))

# --- Admin Delete Character ---
@admin_bp.route('/character/<int:char_id>/delete', methods=['POST'])
@admin_required
def admin_delete_character(char_id):
    character = Character.query.get_or_404(char_id)
    db.session.delete(character)
    db.session.commit()
    admin_logger.info(f"Admin {current_user.username} deleted user {character.name} at {datetime.utcnow()}")
    flash("Character deleted.", "success")
    return redirect(url_for('admin.admin_characters'))

# --- Admin Edit User ---
@admin_bp.route('/user/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        # Only assign fields you explicitly allow
        username = request.form.get('username', user.username)
        premium = request.form.get('premium')
        crew_id = request.form.get('crew_id')
        password = request.form.get('password', '')

        # Only allow admins to set is_admin, and never allow self-promotion
        if current_user.id == user.id and not current_user.is_admin:
            flash("You cannot promote yourself to admin.", "danger")
            return redirect(url_for('admin.admin_users'))
        if current_user.id != user.id:
            is_admin = request.form.get('is_admin')
            user.is_admin = bool(is_admin) if is_admin is not None else user.is_admin

        user.username = username
        user.premium = bool(premium) if premium is not None else user.premium
        user.crew_id = int(crew_id) if crew_id and crew_id.isdigit() else None

        if password:
            user.set_password(password)
        db.session.commit()
        flash("User updated.", "success")
        return redirect(url_for('admin.admin_users'))
    return render_template('admin/edit_user.html', user=user, form=EditUserForm(obj=user))

# --- Admin shop management ---
@admin_bp.route('/shop')
@admin_required
def admin_shop():
    items = ShopItem.query.order_by(ShopItem.id.desc()).all()
    return render_template('admin/shop.html', items=items)

# --- Admin Add Shop Item ---
@admin_bp.route('/shop/add', methods=['GET', 'POST'])
@admin_required
def admin_add_shop_item():
    form = AddShopItemForm()
    if form.validate_on_submit():
        name = form.name.data.strip()
        description = form.description.data.strip()
        price = form.price.data
        stock = form.stock.data
        is_gun = form.is_gun.data

        gun = None
        if is_gun:
            # Create a new Gun entry
            gun = Gun(
                name=form.gun_name.data.strip() or name,
                damage=form.gun_damage.data or 0,
                accuracy=float(form.gun_accuracy.data or 0.7),
                rarity=form.gun_rarity.data or "Common",
                price=form.gun_price.data or price,
                image=form.gun_image.data or "",
                description=form.gun_description.data or ""
            )

            db.session.add(gun)
            db.session.commit()
        if gun:
            admin_logger.info(f"Admin {current_user.username} added gun {gun.name} at {datetime.utcnow()}")
        else:
            admin_logger.info(f"Admin {current_user.username} added shop item {name} at {datetime.utcnow()}")
            
        item = ShopItem(
            name=name,
            description=description,
            price=price,
            stock=stock,
            is_gun=is_gun,
            gun=gun
        )
        db.session.add(item)
        db.session.commit()
        flash("Shop item added!", "success")
        return redirect(url_for('admin.admin_shop'))
    
    return render_template('admin/add_shop_item.html', form=form)

# --- Admin Edit Shop Item ---
@admin_bp.route('/shop/<int:item_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_shop_item(item_id):
    item = ShopItem.query.get_or_404(item_id)
    gun = item.gun if item.is_gun else None
    form = EditShopItemForm(
        name=item.name,
        description=item.description,
        price=item.price,
        stock=item.stock,
        is_gun=item.is_gun,
        gun_name=gun.name if gun else "",
        gun_damage=gun.damage if gun else 0,
        gun_accuracy=str(gun.accuracy) if gun else "0.7",
        gun_rarity=gun.rarity if gun else "Common",
        gun_price=gun.price if gun else item.price,
        gun_image=gun.image if gun else "",
        gun_description=gun.description if gun else ""
    )
    if form.validate_on_submit():
        item.name = form.name.data.strip()
        item.description = form.description.data.strip()
        item.price = form.price.data
        item.stock = form.stock.data
        item.is_gun = form.is_gun.data

        if item.is_gun:
            if not item.gun:
                # Create new Gun if not exists
                gun = Gun()
                db.session.add(gun)
                db.session.commit()
                item.gun = gun
            gun = item.gun
            gun.name = form.gun_name.data.strip() or item.name
            gun.damage = form.gun_damage.data or 0
            gun.accuracy = float(form.gun_accuracy.data or 0.7)
            gun.rarity = form.gun_rarity.data or "Common"
            gun.price = form.gun_price.data or item.price
            gun.image = form.gun_image.data or ""
            gun.description = form.gun_description.data or ""
            db.session.commit()
        else:
            item.gun = None

        db.session.commit()
        flash("Shop item updated.", "success")
        return redirect(url_for('admin.admin_shop'))
    return render_template('admin/edit_shop_item.html', form=form, item=item)

# --- Admin Delete Shop Item ---
@admin_bp.route('/shop/<int:item_id>/delete', methods=['POST'])
@admin_required
def admin_delete_shop_item(item_id):
    item = ShopItem.query.get_or_404(item_id)

    # Remove references from UserInventory
    UserInventory.query.filter_by(item_id=item.id).delete()

    # Remove references from User.gun_id
    users_with_gun = User.query.filter_by(gun_id=item.id).all()
    for user in users_with_gun:
        user.gun_id = None

    # Remove references from Character.gun_id
    characters_with_gun = Character.query.filter_by(gun_id=item.id).all()
    for char in characters_with_gun:
        char.gun_id = None

    db.session.delete(item)
    db.session.commit()
    flash("Shop item deleted.", "success")
    return redirect(url_for('admin.admin_shop'))

# --- Admin Organized Crimes ---
@admin_bp.route('/organized_crimes')
@admin_required
def admin_organized_crimes():
    crimes = OrganizedCrime.query.order_by(OrganizedCrime.id.desc()).all()
    crime_forms = [(crime, DeleteCrimeForm(prefix=str(crime.id))) for crime in crimes]
    return render_template('admin/organized_crimes.html', crime_forms=crime_forms)

# --- Admin Add Organized Crime ---
@admin_bp.route('/organized_crimes/<int:crime_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_organized_crime(crime_id):
    crime = OrganizedCrime.query.get_or_404(crime_id)
    if request.method == 'POST':
        crime.name = request.form.get('name', crime.name)
        invite_code = request.form.get('invite_code', crime.invite_code)
        if invite_code and invite_code != crime.invite_code:
            # Ensure invite code is unique
            if OrganizedCrime.query.filter_by(invite_code=invite_code).first():
                flash("Invite code already exists.", "danger")
                return redirect(url_for('admin.admin_edit_organized_crime', crime_id=crime.id))
            crime.invite_code = invite_code
        db.session.commit()
        flash("Organized crime updated.", "success")
        return redirect(url_for('admin.admin_organized_crimes'))
    return render_template('admin/edit_organized_crime.html', crime=crime)

# --- Admin search ---
@admin_bp.route('/search')
@admin_required
def admin_search():
    q = request.args.get('q', '').strip()
    users = []
    characters = []
    if q:
        users = User.query.filter(User.username.ilike(f'%{q}%')).all()
        characters = Character.query.filter(Character.name.ilike(f'%{q}%')).all()
    return render_template('admin/search_results.html', q=q, users=users, characters=characters)

# --- Admin Delete Organized Crime ---
@admin_bp.route('/organized_crimes/<int:crime_id>/delete', methods=['POST'])
@admin_required
def admin_delete_organized_crime(crime_id):
    crime = OrganizedCrime.query.get_or_404(crime_id)
    # Remove members' crime_group_id
    for member in crime.members:
        member.crime_group_id = None
    db.session.delete(crime)
    db.session.commit()
    flash("Organized crime deleted.", "success")
    return redirect(url_for('admin.admin_organized_crimes'))
# --- Admin Drugs ---
@admin_bp.route('/drugs')
@admin_required
def admin_drugs():
    drugs = Drug.query.order_by(Drug.id.desc()).all()
    return render_template('admin/drugs.html', drugs=drugs)

@admin_bp.route('/drugs/add', methods=['GET', 'POST'])
@admin_required
def admin_add_drug():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        drug_type = request.form.get('type', 'Other')
        if not name:
            flash("Drug name is required.", "danger")
            return redirect(url_for('admin.admin_add_drug'))
        if Drug.query.filter_by(name=name).first():
            flash("Drug already exists.", "danger")
            return redirect(url_for('admin.admin_add_drug'))
        db.session.add(Drug(name=name, type=drug_type))
        db.session.commit()
        flash("Drug added!", "success")
        return redirect(url_for('admin.admin_drugs'))
    return render_template('admin/add_drug.html',
    form=AddDrugForm())

@admin_bp.route('/topics/<int:topic_id>/delete', methods=['POST'])
@admin_required
def admin_delete_topic(topic_id):
    topic = ForumTopic.query.get_or_404(topic_id)
    # Delete all posts in the topic
    ForumPost.query.filter_by(topic_id=topic.id).delete()
    db.session.delete(topic)
    db.session.commit()
    flash("Topic deleted.", "success")
    return redirect(url_for('admin.admin_topics'))

@admin_bp.route('/topics')
@admin_required
def admin_topics():
    topics = ForumTopic.query.order_by(ForumTopic.created_at.desc()).all()
    user_ids = {t.author_id for t in topics}
    users_map = {u.id: u for u in User.query.filter(User.id.in_(user_ids)).all()}
    delete_form = DeleteForm()
    return render_template('admin/topics.html', topics=topics, users_map=users_map, delete_form=delete_form)

# --- Admin Drug Dealers ---
@admin_bp.route('/dealers')
@admin_required
def admin_dealers():
    dealers = DrugDealer.query.order_by(DrugDealer.city, DrugDealer.drug_id).all()
    return render_template('admin/dealers.html', dealers=dealers)

@admin_bp.route('/dealers/add', methods=['GET', 'POST'])
@admin_required
def admin_add_dealer():
    form = AddDealerForm()
    # Dynamically set drug choices from the database
    form.drug_id.choices = [(drug.id, drug.name) for drug in Drug.query.all()]
    if form.validate_on_submit():
        city = form.city.data
        drug_id = form.drug_id.data
        price = form.price.data
        stock = form.stock.data

        db.session.add(DrugDealer(city=city, drug_id=drug_id, price=price, stock=stock))
        db.session.commit()
        flash("Dealer added!", "success")
        return redirect(url_for('admin.admin_drugs_dashboard'))
    return render_template('admin/drugs_dashboard.html',
        form=form,
        drugs=Drug.query.all(),
        cities=CITIES
    )
@admin_bp.route('/delete_drug/<int:drug_id>', methods=['POST'])
@admin_required
def admin_delete_drug(drug_id):
    drug = Drug.query.get_or_404(drug_id)
    # Optionally: delete all dealers for this drug
    DrugDealer.query.filter_by(drug_id=drug.id).delete()
    # Optionally: delete all inventory for this drug
    CharacterDrugInventory.query.filter_by(drug_id=drug.id).delete()
    db.session.delete(drug)
    db.session.commit()
    flash("Drug deleted.", "success")
    return redirect(url_for('admin.admin_drugs_dashboard'))

@admin_bp.route('/dealers/<int:dealer_id>/delete', methods=['POST'])
@admin_required
def admin_delete_dealer(dealer_id):
    dealer = DrugDealer.query.get_or_404(dealer_id)
    db.session.delete(dealer)
    db.session.commit()
    flash("Dealer deleted.", "success")
    return redirect(url_for('admin.admin_drugs_dashboard'))
@admin_bp.route('/drugs_dashboard', methods=['GET', 'POST'])
@admin_required
def admin_drugs_dashboard():
    drugs = Drug.query.order_by(Drug.id.desc()).all()
    dealers = DrugDealer.query.order_by(DrugDealer.city, DrugDealer.drug_id).all()
    delete_drug_forms = {drug.id: DeleteDrugForm(prefix=f"drug_{drug.id}") for drug in drugs}
    delete_dealer_forms = {dealer.id: DeleteDealerForm(prefix=f"dealer_{dealer.id}") for dealer in dealers}

    # Handle POSTs for delete actions
    for drug in drugs:
        form = delete_drug_forms[drug.id]
        if form.validate_on_submit() and form.submit.data and f"drug_{drug.id}-submit" in request.form:
            # Delete all dealers and inventories for this drug
            DrugDealer.query.filter_by(drug_id=drug.id).delete()
            CharacterDrugInventory.query.filter_by(drug_id=drug.id).delete()
            db.session.delete(drug)
            db.session.commit()
            flash("Drug deleted.", "success")
            return redirect(url_for('admin.admin_drugs_dashboard'))

    for dealer in dealers:
        form = delete_dealer_forms[dealer.id]
        if form.validate_on_submit() and form.submit.data and f"dealer_{dealer.id}-submit" in request.form:
            db.session.delete(dealer)
            db.session.commit()
            flash("Dealer deleted.", "success")
            return redirect(url_for('admin.admin_drugs_dashboard'))

    return render_template(
        'admin/drugs_dashboard.html',
        drugs=drugs,
        dealers=dealers,
        delete_drug_forms=delete_drug_forms,
        delete_dealer_forms=delete_dealer_forms
    )
@admin_bp.route('/reset_crime_cooldown', methods=['GET', 'POST'])
@login_required
def reset_crime_cooldown():
    form = ResetCrimeCooldownForm()
    if form.validate_on_submit():
        char_id = form.character_id.data
        character = Character.query.get(char_id)
        if character:
            character.last_crime_time = None
            db.session.commit()
            flash(f"Crime cooldown reset for {character.name}.", "success")
        else:
            flash("Character not found.", "danger")
        return redirect(url_for('admin.reset_crime_cooldown'))
    return render_template('admin/reset_crime_cooldown.html', form=form)
@admin_bp.route('/crews')
@admin_required
def admin_crews():
    crews = Crew.query.all()
    crew_forms = [(crew, DeleteCrewForm()) for crew in crews]
    return render_template('admin/crews.html', crew_forms=crew_forms)

@admin_bp.route('/crews/<int:crew_id>/delete', methods=['POST'])
@admin_required
def admin_delete_crew(crew_id):
    crew = Crew.query.get_or_404(crew_id)
    # Remove all members' crew_id
    for user in crew.members:
        user.crew_id = None
    # Remove all CrewMember records
    CrewMember.query.filter_by(crew_id=crew.id).delete()
    db.session.delete(crew)
    db.session.commit()
    flash("Crew deleted.", "success")
    return redirect(url_for('admin.admin_crews'))
# Register the admin blueprint
app.register_blueprint(admin_bp)
# Admin Interface -------------------------------
@app.context_processor
def inject_user():
    return dict(user=current_user)
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
    if current_user.is_authenticated:
        char = Character.query.filter_by(master_id=current_user.id).first()
        if not char or not char.is_alive:
            if request.endpoint not in ('create_character', 'logout', 'static'):
                return redirect(url_for('create_character'))

#Flask Forms -------------------------------
class ApproveCrewRequestForm(FlaskForm):
    pass
class StepDownGodfatherForm(FlaskForm):
    submit = SubmitField("Step Down")
class DenyCrewRequestForm(FlaskForm):
    pass
class ChatForm(FlaskForm):
    message = StringField('Message', validators=[DataRequired()])
    submit = SubmitField('Send')
class PasswordResetRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    submit = SubmitField('Request Password Reset')
class SimpleCaptchaForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    captcha_question = StringField('Captcha Question', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    
    
    captcha_answer = StringField('What is {{captcha_question}}?', validators=[DataRequired()])
    captcha_solution = HiddenField()  # Store the answer in a hidden field
    submit = SubmitField('Register')
class PasswordResetForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired()])
    submit = SubmitField('Reset Password')
class CreateCrewForm(FlaskForm):
    crew_name = StringField('Crew Name', validators=[DataRequired(), Length(max=64)])
    submit = SubmitField('Create')
class CreateCharacterForm(FlaskForm):
    character_name = StringField('Character Name', validators=[DataRequired(), Length(max=32)])
    submit = SubmitField('Create Character')
class ResetCrimeCooldownForm(FlaskForm):
    character_id = IntegerField('Character ID', validators=[DataRequired()])
    submit = SubmitField('Reset Cooldown')
class DeleteCrimeForm(FlaskForm):
    submit = SubmitField('Delete')
class CrewRoleForm(FlaskForm):
    new_role = SelectField('Role', choices=[
        ('member', 'Member'),
        ('left hand', 'Left Hand'),
        ('right hand', 'Right Hand')
    ])
    submit = SubmitField('Update')
class ClaimGodfatherForm(FlaskForm):
        submit = SubmitField('Claim Godfather')
class DeleteDrugForm(FlaskForm):
    submit = SubmitField('Delete')
class EditForumForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    submit = SubmitField('Save')
class DeleteDealerForm(FlaskForm):
    submit = SubmitField('Delete')
class EditShopItemForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    description = StringField('Description', validators=[Optional()])
    price = IntegerField('Price', validators=[DataRequired()])
    stock = IntegerField('Stock', validators=[DataRequired()])
    is_gun = BooleanField('Is Gun')
    # Gun fields
    gun_name = StringField('Gun Name')
    gun_damage = IntegerField('Gun Damage', default=0)
    gun_accuracy = StringField('Gun Accuracy', default="0.7")
    gun_rarity = StringField('Gun Rarity', default="Common")
    gun_price = IntegerField('Gun Price', default=100)
    gun_image = StringField('Gun Image URL')
    gun_description = StringField('Gun Description')
    submit = SubmitField('Add Item')
class AddShopItemForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    description = StringField('Description', validators=[Optional()])
    price = IntegerField('Price', validators=[DataRequired()])
    stock = IntegerField('Stock', validators=[DataRequired()])
    is_gun = BooleanField('Is Gun')
    # Gun fields
    gun_name = StringField('Gun Name')
    gun_damage = IntegerField('Gun Damage', default=0)
    gun_accuracy = StringField('Gun Accuracy', default="0.7")
    gun_rarity = StringField('Gun Rarity', default="Common")
    gun_price = IntegerField('Gun Price', default=100)
    gun_image = StringField('Gun Image URL')
    gun_description = StringField('Gun Description')
    submit = SubmitField('Add Item')
class ReplyForm(FlaskForm):
    content = TextAreaField('Reply', validators=[DataRequired()])
    submit = SubmitField('Reply')
class BuyDrugForm(FlaskForm):
    quantity = IntegerField('Quantity', validators=[DataRequired(), NumberRange(min=1)])
    submit = SubmitField('Buy')
class SellDrugForm(FlaskForm):
    quantity = IntegerField('Quantity', validators=[DataRequired(), NumberRange(min=1)])
    submit = SubmitField('Sell')
class DeleteForm(FlaskForm):
    submit = SubmitField('Delete')
class NewTopicForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Create Topic')
class InviteToCrewForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    submit = SubmitField('Send Invite')
class AddDrugForm(FlaskForm):
    name = StringField('Drug Name', validators=[DataRequired()])
    type = SelectField('Drug Type', choices=[
        ('Stimulant', 'Stimulant'),
        ('Opiate', 'Opiate'),
        ('Hallucinogen', 'Hallucinogen'),
        ('Depressant', 'Depressant'),
        ('Other', 'Other')
    ], validators=[DataRequired()])
    submit = SubmitField('Add')
class AddDealerForm(FlaskForm):
    city = SelectField('City', choices=[(c, c) for c in CITIES], validators=[DataRequired()])
    drug_id = SelectField('Drug', coerce=int, validators=[DataRequired()])
    price = IntegerField('Price', validators=[DataRequired(), NumberRange(min=1)])
    stock = IntegerField('Stock', default=10, validators=[DataRequired(), NumberRange(min=0)])
    submit = SubmitField('Add Dealer')
class TravelForm(FlaskForm):
    city = RadioField('City', choices=[(c, c) for c in CITIES], validators=[DataRequired()])
    submit = SubmitField('Travel')
class EditUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[Optional()])
    crew_id = IntegerField('Crew ID', validators=[Optional()])
    is_admin = BooleanField('Is Admin')
    premium = BooleanField('Premium')
    submit = SubmitField('Save')
class EditCharacterForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    health = IntegerField('Health', validators=[DataRequired()])
    money = IntegerField('Money', validators=[DataRequired()])
    level = IntegerField('Level', validators=[DataRequired()])
    xp = IntegerField('XP', validators=[DataRequired()])
    is_alive = BooleanField('Alive')
    submit = SubmitField('Save')
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    
    submit = SubmitField('Login')
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    captcha_answer = StringField('Captcha Answer', validators=[DataRequired()])
    captcha_question = StringField('Captcha Question', validators=[DataRequired()])
    submit = SubmitField('Register')
class BreakoutForm(FlaskForm):
    submit = SubmitField('Break Out')
class BuyForm(FlaskForm):
    submit = SubmitField('Buy')
class UploadImageForm(FlaskForm):
    profile_image = FileField('Profile Image', validators=[DataRequired()])
    submit = SubmitField('Change Profile Image')
class PlayerSearchForm(FlaskForm):
    query = StringField('Search', validators=[DataRequired()])
    submit = SubmitField('Search')
class KillForm(FlaskForm):
    submit = SubmitField('Shoot')
class EquipGunForm(FlaskForm):
    submit = SubmitField('Equip')
class KillForm(FlaskForm):
    submit = SubmitField('Shoot')
class LeaveCrimeForm(FlaskForm):
    submit = SubmitField('Leave Group')
class DisbandCrimeForm(FlaskForm):
    submit = SubmitField('Disband Group')
class AttemptCrimeForm(FlaskForm):
    submit = SubmitField('Attempt')
class JoinCrimeForm(FlaskForm):
    invite_code = StringField('Invite Code', validators=[DataRequired()])
    submit = SubmitField('Join')
class CreateCrimeForm(FlaskForm):
    submit = SubmitField('Create Group')
class UpgradeForm(FlaskForm):
    submit = SubmitField('Upgrade')
class EarnForm(FlaskForm):
    submit = SubmitField('Earn')
class CharacterEditForm(SecureForm):
    name = StringField('Name')
    health = IntegerField('Health')
    money = IntegerField('Money')
    level = IntegerField('Level')
    xp = IntegerField('XP')
    is_alive = BooleanField('Is Alive', default=True)
    profile_image = StringField('Profile Image URL')
class DeleteCrewForm(FlaskForm):
    submit = SubmitField('Delete')
class UserEditForm(SecureForm):
    username = StringField('Username')
    password = PasswordField('Password')
    crew_id = StringField('Crew ID')
    is_admin = BooleanField('Is Admin')
    premium = BooleanField('Premium User')
    premium_until = DateTimeField('Premium Until', format='%Y-%m-%d %H:%M:%S')
class InviteForm(FlaskForm):
    submit = SubmitField('Invite Member')
class LeaveForm(FlaskForm):
    submit = SubmitField('Leave Crew')
class RoleForm(FlaskForm):
    new_role = SelectField('Role', choices=[
        ('member', 'Member'),
        ('left_hand', 'Left-Hand'),
        ('right_hand', 'Right-Hand'),
        ('leader', 'Leader')
    ])
    submit = SubmitField('Update')
class BlackjackForm(FlaskForm):
    bet = IntegerField('Bet', validators=[DataRequired(), NumberRange(min=1)])
    submit = SubmitField('Play Blackjack')
class CoinflipForm(FlaskForm):
    bet = IntegerField('Bet', validators=[DataRequired(), NumberRange(min=1)])
    coin_choice = SelectField('Coin Side', choices=[('heads', 'Heads'), ('tails', 'Tails')], validators=[DataRequired()])
    submit = SubmitField('Flip Coin')
class RouletteForm(FlaskForm):
    bet = IntegerField('Bet', validators=[DataRequired(), NumberRange(min=1)])
    roulette_choice = SelectField('Roulette Choice', choices=[('red', 'Red'), ('black', 'Black'), ('green', 'Green (14x)')], validators=[DataRequired()])
    submit = SubmitField('Spin Roulette')
class SendMessageForm(FlaskForm):
    content = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Send')
class ComposeMessageForm(FlaskForm):
    recipient_name = StringField('Recipient Name', validators=[DataRequired()])
    content = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Send')

# Player Models -------------------------------
class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(12), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    crew_id = db.Column(db.Integer, db.ForeignKey('crew.id'), nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    email_verified = db.Column(db.Boolean, default=False)
    email_verification_token = db.Column(db.String(128), nullable=True)
    reset_token = db.Column(db.String(128), nullable=True)
    reset_token_expiry = db.Column(db.DateTime, nullable=True)
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
    characters = db.relationship(
    'Character',
    backref=db.backref('owner', overlaps="character,master"),
    lazy=True,
    foreign_keys='Character.master_id',
    overlaps="character,master"
)
    kills = db.Column(db.Integer, default=0)
    # Characters owned by this user
    
    
    # Optional: characters linked for crew, etc.
    linked_characters = db.relationship('Character', foreign_keys='Character.user_id')
    def set_password(self, password):
        # Explicitly use pbkdf2:sha256 with 260,000 iterations (Werkzeug 2.3+ default)
        self.password_hash = generate_password_hash(
            password,
            method='pbkdf2:sha256',
            salt_length=16
        )
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
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
class CrewRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    crew_name = db.Column(db.String(150), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    city = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, denied
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User')
class Character(db.Model):
    __tablename__ = 'character'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    user = db.relationship('User', backref=db.backref('linked_character', overlaps="linked_characters"), foreign_keys=[user_id], overlaps="linked_characters")
    name = db.Column(db.String(64), unique=True, nullable=False)
    bodyguards = db.Column(db.Integer, default=0)
    health = db.Column(db.Integer, default=100)
    money = db.Column(db.Integer, default=250)
    level = db.Column(db.Integer, default=1)
    xp = db.Column(db.Integer, default=0)
    
    last_crime_time = db.Column(db.DateTime, nullable=True)
    last_travel_time = db.Column(db.DateTime, nullable=True)
    city = db.Column(db.String(64), default="New York")
    gun_id = db.Column(db.Integer, db.ForeignKey('shop_item.id'))
    gun = db.relationship('ShopItem', foreign_keys=[gun_id])

    in_jail = db.Column(db.Boolean, default=False)
    jail_until = db.Column(db.DateTime, nullable=True)

    crime_group_id = db.Column(db.Integer, db.ForeignKey('organized_crime.id'))
    crime_group = db.relationship("OrganizedCrime", back_populates="members", foreign_keys=[crime_group_id])
    # The actual owner of the character
    master_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    equipped_gun_id = db.Column(db.Integer, db.ForeignKey('gun.id'), nullable=True)
    equipped_gun = db.relationship('Gun', foreign_keys=[equipped_gun_id])
    
    earn_streak = db.Column(db.Integer, default=0)
    last_earned = db.Column(db.DateTime, nullable=True)
    is_alive = db.Column(db.Boolean, default=True)
    
    
    profile_image = db.Column(db.String(255), nullable=True)
    
    crew_id = db.Column(db.Integer, db.ForeignKey('crew.id'))
    
    linked_user = db.relationship('User', foreign_keys=[user_id], overlaps="linked_character,linked_characters,user")
    crew = db.relationship('Crew', backref='characters')
    
    @property
    def immortal(self):
        # Admin users' characters are immortal
        if self.master and getattr(self.master, "is_admin", False):
            return True
        return False
class Godfather(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    city = db.Column(db.String(64), unique=True, nullable=False)
    character_id = db.Column(db.Integer, db.ForeignKey('character.id'), unique=True, nullable=False)
    character = db.relationship('Character', backref='godfather_of')    
class CrewMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    crew_id = db.Column(db.Integer, db.ForeignKey('crew.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    role = db.Column(db.String(20), default='member')  # leader, right_hand, left_hand, member

    crew = db.relationship('Crew', backref='crew_members')
    
    
    user = db.relationship('User', backref='crew_roles')

class OrganizedCrime(db.Model):
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=True)
    invite_code = db.Column(db.String(8), unique=True, nullable=False)

    leader_id = db.Column(db.Integer, db.ForeignKey('character.id'), nullable=False)
    leader = db.relationship("Character", backref="led_crime_groups", foreign_keys=[leader_id])
    
    members = db.relationship(
    "Character",
    back_populates="crime_group",
    foreign_keys="Character.crime_group_id"
)


    def is_full(self):
        return len(self.members) >= 4
class PrivateMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_messages')    
class ShopItemModelView(ModelView):
    can_create = True
    can_edit = True
    can_delete = True
    can_view_details = True
    column_list = ('id', 'name', 'description', 'price', 'stock', 'is_gun', 'damage')  
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
    gun_id = db.Column(db.Integer, db.ForeignKey('gun.id', ondelete='CASCADE'), nullable=True)
    gun = db.relationship('Gun')


class UserInventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('shop_item.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1, nullable=False)

    user = db.relationship('User', backref='inventory')
    item = db.relationship('ShopItem')

class Drug(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    type = db.Column(db.String(32), nullable=False, default="Other")

class DrugDealer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    city = db.Column(db.String(64), nullable=False)
    drug_id = db.Column(db.Integer, db.ForeignKey('drug.id'), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    stock = db.Column(db.Integer, nullable=False, default=10)
    drug = db.relationship('Drug')

class CharacterDrugInventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    character_id = db.Column(db.Integer, db.ForeignKey('character.id'), nullable=False)
    drug_id = db.Column(db.Integer, db.ForeignKey('drug.id'), nullable=False)
    quantity = db.Column(db.Integer, default=0)
    drug = db.relationship('Drug')
    character = db.relationship('Character')

class Gun(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    damage = db.Column(db.Integer, nullable=False)
    accuracy = db.Column(db.Float, default=0.7)  # 0-1
    rarity = db.Column(db.String(32), default='Common')
    price = db.Column(db.Integer, nullable=False)
    image = db.Column(db.String(255), nullable=True)
    description = db.Column(db.String(255), nullable=True)
    

class CharacterModelView(ModelView):
    column_list = ('id', 'name', 'master_id', 'health', 'money', 'level', 'is_alive')
    form_columns = ('name', 'master_id', 'health', 'money', 'level', 'is_alive')




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
    crew_id = db.Column(db.Integer, nullable=True)

class CrewInvitation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    inviter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    invitee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    crew_id = db.Column(db.Integer, db.ForeignKey('crew.id'), nullable=False)
    inviter = db.relationship('User', foreign_keys=[inviter_id])
    invitee = db.relationship('User', foreign_keys=[invitee_id])
    crew = db.relationship('Crew')

class Forum(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128), nullable=False)
    description = db.Column(db.String(256), nullable=True)
    topics = db.relationship('ForumTopic', backref='forum', lazy=True)

class ForumTopic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    forum_id = db.Column(db.Integer, db.ForeignKey('forum.id'), nullable=False)
    title = db.Column(db.String(128), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    posts = db.relationship('ForumPost', backref='topic', lazy=True)

class ForumPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    topic_id = db.Column(db.Integer, db.ForeignKey('forum_topic.id'), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# def generation of unique invite codes for OrganizedCrime
def generate_unique_invite_code(length=6):
    """Generate a unique invite code for OrganizedCrime."""
    while True:
        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
        if not OrganizedCrime.query.filter_by(invite_code=code).first():
            return code
# Function to check if a character is on crime cooldown
def is_on_crime_cooldown(character, cooldown_minutes=360):
    if character.last_crime_time:
        return datetime.utcnow() < character.last_crime_time + timedelta(minutes=cooldown_minutes)
    return False
# Function to release characters from jail if their jail time has expired
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


# Admin Interface -------------------------------
# class MyAdminIndexView(AdminIndexView):
#     def is_accessible(self):
#         return current_user.is_authenticated and getattr(current_user, 'is_admin', False)
    
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))
# Routes -------------------------------
@app.route('/')
def home():
    return redirect(url_for('dashboard'))

@app.route('/forums')
def forums():
    forums = Forum.query.all()
    return render_template('forums.html', forums=forums)

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
    if not getattr(current_user, 'is_admin', False):
        flash("Only admins can create forums.", "danger")
        return redirect(url_for('forums'))
    if request.method == 'POST':
        forum = Forum(title=title, description=description)
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        if not title:
            flash("Forum title is required.", "danger")
            return redirect(url_for('create_forum'))
        
        db.session.add(forum)
        db.session.commit()
        flash("Forum created!", "success")
        return redirect(url_for('forums'))
    return render_template('create_forum.html')
@app.route('/messages', methods=['GET'])
@login_required
def inbox():
    messages = PrivateMessage.query.filter_by(recipient_id=current_user.id).order_by(PrivateMessage.timestamp.desc()).all()
    char_map = {}
    for msg in messages:
        char = Character.query.filter_by(master_id=msg.sender.id, is_alive=True).first()
        char_map[msg.sender.id] = char.name if char else ""
    return render_template("inbox.html", messages=messages, char_map=char_map)

@app.route('/notifications')
@login_required
def notifications():
    # Fetch notifications for the current user
    notifications = []
    # Only show unread private messages as notifications
    messages = PrivateMessage.query.filter_by(recipient_id=current_user.id, is_read=False).order_by(PrivateMessage.timestamp.desc()).all()
    for msg in messages:
        notifications.append({
            "type": "message",
            "from": msg.sender.username if msg.sender else "Unknown",
            "content": msg.content,
            "timestamp": msg.timestamp,
            "is_read": msg.is_read,
            "msg_id": msg.id
        })

    # Fetch crew invitations for the current user
    invitations = CrewInvitation.query.filter_by(invitee_id=current_user.id).all()

    # Sort notifications by timestamp descending
    notifications.sort(key=lambda n: n["timestamp"], reverse=True)

    return render_template('notifications.html', notifications=notifications, invitations=invitations)

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
            else:
                # 20% chance to go to jail on failed crime
                if random.random() < 0.2:
                    jail_minutes = random.randint(5, 15)
                    member.in_jail = True
                    member.jail_until = datetime.utcnow() + timedelta(minutes=jail_minutes)
                    flash(f"{member.name} has been jailed for {jail_minutes} minutes due to failed crime.", "warning")
            member.crime_group_id = None  # Disband the crime group

    db.session.delete(crime)
    db.session.commit()

    if success:
        
        flash(f"Crime successful! Each member earned ${reward_money} and {reward_xp} XP.", "success")
    else:
        flash(f"Crime failed! The crew has disbanded.", "danger")

    return redirect(url_for('dashboard'))

@app.route('/crew/<int:crew_id>')
@login_required
def crew_page(crew_id):
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
        current_user_role=current_user_role
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

@app.route('/hire_bodyguard', methods=['POST'])
@login_required
def hire_bodyguard():
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    if not character:
        flash("No character found.", "danger")
        return redirect(url_for('dashboard'))
    COST_PER_BODYGUARD = 50000
    MAX_BODYGUARDS = 5
    num = int(request.form.get('num', 1))
    if num < 1 or num > (MAX_BODYGUARDS - character.bodyguards):
        flash(f"You can only hire up to {MAX_BODYGUARDS - character.bodyguards} more bodyguards.", "danger")
        return redirect(url_for('dashboard'))
    total_cost = COST_PER_BODYGUARD * num
    if character.money < total_cost:
        flash("Not enough money to hire bodyguards.", "danger")
        return redirect(url_for('dashboard'))
    character.money -= total_cost
    character.bodyguards += num
    # Optional: set expiry
    # character.bodyguard_until = datetime.utcnow() + timedelta(hours=24)
    db.session.commit()
    flash(f"Hired {num} bodyguard(s)! You now have {character.bodyguards}.", "success")
    return redirect(url_for('dashboard'))

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
        flash(f"You killed {target.name}!", "success")
    else:
        flash(f"You shot {target.name} for {gun.damage} damage!", "success")

    db.session.commit()

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
        return redirect(url_for('dashboard'))
    
    if not character:
        flash("No character found.", "danger")
        return redirect(url_for('dashboard'))

    cooldown = timedelta(hours=8)  # 6-hour cooldown for travel
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
            flash(f"You traveled to {new_city}!", "success")
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
    return render_template(
    "player_search.html",
    search_form=PlayerSearchForm(),
    kill_form=KillForm(),
    results=results,
    query=query
)

@app.route('/npc/<int:id>')
def npc_profile(id):
    npc = Character.query.filter_by(id=id, master_id=0).first_or_404()
    return render_template('npc_profile.html', npc=npc)

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
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
            db.session.commit()
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
@limiter.limit("5 per minute")
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
            if next_page and is_safe_url(next_page):
                return redirect(next_page)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/create_character', methods=['GET', 'POST'])
@login_required
def create_character():
    form = CreateCharacterForm()
    if form.validate_on_submit():
        char_name = request.form.get('character_name', '').strip()
        if not char_name:
            flash("Character name is required.", "danger")
            return render_template('create_character.html', form=form)
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
    release_expired_jail()
    now = datetime.utcnow()
    jailed_characters = Character.query.filter(
        Character.in_jail == True,
        Character.is_alive == True,
        Character.jail_until != None,
        Character.jail_until > now
    ).order_by(Character.jail_until.asc()).all()
    current_character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    return render_template(
    "jail.html",
    jailed_characters=jailed_characters,
    current_character=current_character,
    now=datetime.utcnow(),
    breakout_form=BreakoutForm()
)

@app.route('/breakout/<int:char_id>', methods=['POST'])
@login_required
def breakout(char_id):
    target = Character.query.get_or_404(char_id)
    actor = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()

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

    # Prevent leader from leaving without assigning a new one
    # if crew.leader_id == character.id:
    #     flash("You must assign a new leader before leaving the crew.", "danger")
    #     return redirect(url_for('dashboard'))

    # Remove the character from the crew
    character.crew_id = None
    db.session.commit()

    flash("You left the crew.", "success")
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    godfathers = {g.city: g.character for g in Godfather.query.all()}
    online_timeout = datetime.utcnow() - timedelta(minutes=5)
    # Get all users online
    online_users = User.query.filter(User.last_seen >= online_timeout).all()
    # For each user, get their alive character
    online_characters = []
    for user in online_users:
        char = Character.query.filter_by(master_id=user.id, is_alive=True).first()
        if char:
            online_characters.append(char)
    npcs = Character.query.filter_by(master_id=0, is_alive=True).all()
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    earn_form = EarnForm()
    cities = CITIES  # Make sure CITIES is defined globally
    claim_forms = {city: ClaimGodfatherForm(prefix=city.replace(" ", "_")) for city in cities}
    return render_template(
        'dashboard.html',
        character=character,
        online_users=online_users,
        online_characters=online_characters,
        earn_form=earn_form,  # now a list of Character objects
        npcs=npcs, godfathers=godfathers,
        cities=cities,                # <-- Pass cities
        claim_forms=claim_forms)

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

    if request.method == 'POST':
        table = request.form.get('table', 'blackjack')
        bet = int(request.form.get('bet', 0))
        if bet <= 0 or bet > character.money:
            flash("Invalid bet amount.", "danger")
            return redirect(url_for('casino', table=table))

        if table == 'blackjack':
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
    form = CreateCrimeForm()
    if form.validate_on_submit():
        character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
        db_character = Character.query.get(character.id)
        if not db_character:
            flash("Your character does not exist in the database.", "danger")
            return redirect(url_for('dashboard'))
        if not character:
            flash("You must have an active character to create a crime group.", "danger")
            return redirect(url_for('dashboard'))

        print("All character IDs:", [c.id for c in Character.query.all()])
        print("Current character ID:", character.id)
        print("Creating crime with leader_id:", character.id)
        print("DB path:", os.path.abspath('users.db'))
        if character.crime_group:
            return redirect(url_for('crime_group'))

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

        character.crime_group_id = crime.id
        
        db.session.commit()
        print("DEBUG: character.id =", character.id)
        print("DEBUG: Character in DB?", db.session.get(Character, character.id) is not None)
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

@app.route('/crime_group')
@login_required
def crime_group():
    # Get the current user's active character
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()

    if character.in_jail and character.jail_until and character.jail_until > datetime.utcnow():
        remaining = character.jail_until - datetime.utcnow()
        mins, secs = divmod(int(remaining.total_seconds()), 60)
        flash(f"You are in jail for {mins}m {secs}s.", "danger")
        return redirect(url_for('dashboard'))
    
    if not character or not character.crime_group:
        flash("You're not part of any crime group yet.", 'info')
        return redirect(url_for('dashboard'))

    
        
    # Using the character's crime_group relationship
    crime = character.crime_group
    # Query all members in the group from the Character table using the foreign key
    members = Character.query.filter_by(crime_group_id=crime.id).all()
    
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
    if file and allowed_file(file.filename):
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
    all_crews = Crew.query.all()
    # For each crew, find the leader, left hand, and right hand
    crew_roles = {}
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
        if Godfather.query.first():
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
        new_crew = Crew(name=crew_name)
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
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    godfather = Godfather.query.filter_by(character_id=character.id).first()
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
    new_crew = Crew(name=req.crew_name)
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
    xp_min, xp_max = 50, 100
    if current_user.premium and current_user.premium_until and current_user.premium_until > now:
        money_min, money_max = int(money_min * 1.5), int(money_max * 1.5)
        xp_min, xp_max = int(xp_min * 1.5), int(xp_max * 1.5)
        cooldown = timedelta(seconds=35)

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

@app.route('/earn_status')
@login_required
def earn_status():
    # Use the same cooldown logic as in the /earn route
    character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
    if not character:
        return jsonify({'seconds_remaining': 0})

    now = datetime.utcnow()
    # Default cooldown
    cooldown = timedelta(seconds=60)
    # Premium cooldown
    if current_user.premium and current_user.premium_until and current_user.premium_until > now:
        cooldown = timedelta(seconds=30)

    if character.last_earned:
        elapsed = now - character.last_earned
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


@app.route('/profile/id/<int:char_id>')
def profile_by_id(char_id):
    character = Character.query.get_or_404(char_id)
    user = User.query.filter_by(id=character.master_id).first()
    crew = db.session.get(Crew, character.crew_id) if character.crew_id else None
    
    return render_template('profile.html', user=user, character=character,
    upload_image_form=UploadImageForm(),
    kill_form=KillForm(), crew=crew)
    

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
    dealers = DrugDealer.query.filter_by(city=character.city).all()
    inventory = CharacterDrugInventory.query.filter_by(character_id=character.id).all()

    # Create a BuyDrugForm for each dealer
    buy_forms = {dealer.id: BuyDrugForm(prefix=f'buy_{dealer.id}') for dealer in dealers}
    # Create a SellDrugForm for each inventory drug
    sell_forms = {inv.drug.id: SellDrugForm(prefix=f'sell_{inv.drug.id}') for inv in inventory}

    # Handle buy/sell POSTs
    for dealer in dealers:
        form = buy_forms[dealer.id]
        if form.validate_on_submit() and form.submit.data and form.quantity.data and f'buy_{dealer.id}-submit' in request.form:
            return buy_drug_form(dealer.id, form)

    for inv in inventory:
        form = sell_forms[inv.drug.id]
        if form.validate_on_submit() and form.submit.data and form.quantity.data and f'sell_{inv.drug.id}-submit' in request.form:
            return sell_drug_form(inv.drug.id, form)

    return render_template(
        'drug_dashboard.html',
        character=character,
        dealers=dealers,
        inventory=inventory,
        buy_forms=buy_forms,
        sell_forms=sell_forms
    )
@app.route('/public_messages')
@login_required
def public_messages():
    messages = ChatMessage.query.filter_by(channel='public')\
        .order_by(ChatMessage.timestamp.desc())\
        .limit(50).all()

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


# Create Flask app and configure it
@app.context_processor
def inject_upgrade_form():
    return dict(upgrade_form=UpgradeForm())

@app.context_processor
def inject_current_character():
    from flask_login import current_user
    if current_user.is_authenticated:
        character = Character.query.filter_by(master_id=current_user.id, is_alive=True).first()
        return dict(current_character=character)
    return dict(current_character=None)
# Create DB (run once, or integrate with a CLI or shell)
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

def randomize_all_drug_prices(min_price=50, max_price=10000, min_stock=5, max_stock=500):
    """Randomize prices and stock for all DrugDealers."""
    dealers = DrugDealer.query.all()
    for dealer in dealers:
        dealer.price = random.randint(min_price, max_price)
        dealer.stock = random.randint(min_stock, max_stock)
    db.session.commit()
def randomize_drug_prices(interval_minutes=random.randint(5, 10)):
    with app.app_context():
        while True:
            randomize_all_drug_prices(min_price=50, max_price=10000, min_stock=5, max_stock=5000)
            time.sleep(interval_minutes * 60)

# Start the background thread when the app starts
def start_price_randomizer():
    t = threading.Thread(target=randomize_drug_prices, args=(10,), daemon=True)  # 10 minutes interval
    t.start()

start_price_randomizer()


def get_online_users():
    cutoff = datetime.utcnow() - timedelta(seconds=1)
    # Real users online
    real_online = current_user.name.query.filter(current_user.last_seen >= cutoff).all()
    # NPCs: Characters with master_id=0 (or whatever you use)
    npcs = Character.query.filter_by(master_id=0, is_alive=True).all()
    # Optionally, create a fake User object for each NPC if your template expects User
    return real_online, npcs

@app.cli.command("randomize-drug-prices")
def randomize_drug_prices_command():
    """Randomize all drug dealer prices (manual trigger)."""
    randomize_all_drug_prices()
    print("Drug dealer prices randomized.")

@app.cli.command("init-db")
def init_db():
    db.create_all()
    print("Database tables created.")


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
