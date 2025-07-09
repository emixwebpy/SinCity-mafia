from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_required, current_user
from models.user import User
from models.character import Character
from models.forum import Forum, ForumTopic, ForumPost
from models.shop import ShopItem, UserInventory, Gun
from models.organized_crime import OrganizedCrime
from models.drug import Drug, DrugDealer, CharacterDrugInventory
from models.notification import Notification
from models.crew import Crew, CrewMember
from extensions import db, limiter  # Limiter should be instantiated in extensions.py
from datetime import datetime
import os
from datetime import timedelta
from models.loggers import admin_logger
from models.forms import (
    EditCharacterForm, EditForumForm, EditUserForm, AddShopItemForm, DeleteCrimeForm,
    AddDrugForm, EditShopItemForm, DeleteCrewForm, DeleteDealerForm, DeleteDrugForm, DeleteForm,
    AddDealerForm, ResetCrimeCooldownForm, DeleteShopItemForm
)
from models.constants import CITIES

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not getattr(current_user, 'is_admin', False):
            flash("Admin access required.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# --- Admin Dashboard ---

@admin_bp.route('/')
@limiter.limit("20 per minute")
@admin_required
def admin_dashboard():
    character = Character.query.filter_by(master_id=current_user.id).first()
    user_count = User.query.count()
    forum_count = Forum.query.count()
    topic_count = ForumTopic.query.count()
    jailed_count = Character.query.filter_by(in_jail=True).count()
    log_path = os.path.join(current_app.root_path, 'admin_actions.log')
    log_lines = []
    if os.path.exists(log_path):
        with open(log_path, 'r', encoding='utf-8') as f:
            log_lines = f.readlines()[-50:]
    return render_template('admin/dashboard.html',
                           user_count=user_count,
                           forum_count=forum_count,
                           topic_count=topic_count,
                           jailed_count=jailed_count,
                           admin_logs=log_lines,
                           character=character)

# --- Admin Users ---
@admin_bp.route('/users')
@limiter.limit("20 per minute")
@admin_required
def admin_users():
    character = Character.query.filter_by(master_id=current_user.id).first()
    users = User.query.order_by(User.id.desc()).all()
    return render_template('admin/users.html', users=users, character=character)

# --- Admin Forums ---
@admin_bp.route('/forums')
@limiter.limit("20 per minute")
@admin_required
def admin_forums():
    character = Character.query.filter_by(master_id=current_user.id).first()
    online_timeout = datetime.utcnow() - timedelta(minutes=5)
    online_users = User.query.filter(User.last_seen >= online_timeout).all()
    online_characters = []
    for u in online_users:
        char = Character.query.filter_by(master_id=u.id, is_alive=True).first()
        if char:
            online_characters.append(char)
    forums = Forum.query.order_by(Forum.id.desc()).all()
    delete_forms = {forum.id: DeleteForm(prefix=str(forum.id)) for forum in forums}
    forum_names = ', '.join([forum.title for forum in forums])
    admin_logger.info(f"Admin {current_user.username} viewed forums: {forum_names} at {datetime.utcnow()}")
    return render_template('admin/forums.html', forums=forums, delete_forms=delete_forms, character=character, online_characters=online_characters, online_users=online_users)

@admin_bp.route('/forums/<int:forum_id>/edit', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
@admin_required
def admin_edit_forum(forum_id):
    forum = Forum.query.get_or_404(forum_id)
    form = EditForumForm(obj=forum)
    if form.validate_on_submit():
        forum.title = form.title.data
        forum.description = form.description.data
        
        admin_logger.info(f"Admin {current_user.username} updated forum {forum.title} at {datetime.utcnow()}")
        db.session.commit()
        flash("Forum updated.", "success")
        return redirect(url_for('admin.admin_forums'))
    return render_template('admin/edit_forum.html', form=form, forum=forum)

@admin_bp.route('/forums/<int:forum_id>/delete', methods=['POST'])
@limiter.limit("20 per minute")
@admin_required
def admin_delete_forum(forum_id):
    forum = Forum.query.get_or_404(forum_id)
    db.session.delete(forum)
    admin_logger.info(f"Admin {current_user.username} deleted forum {forum.title} at {datetime.utcnow()}")
    db.session.commit()
    flash("Forum deleted.", "success")
    return redirect(url_for('admin.admin_forums'))

# --- Admin Jail ---
@admin_bp.route('/jail')
@limiter.limit("20 per minute")
@admin_required
def admin_jail():
    jailed = Character.query.filter_by(in_jail=True).all()
    return render_template('admin/jail.html', jailed=jailed)

# --- Admin Characters ---
@admin_bp.route('/characters')
@limiter.limit("20 per minute")
@admin_required
def admin_characters():
    character = Character.query.filter_by(master_id=current_user.id).first()
    characters = Character.query.order_by(Character.id.desc()).all()
    return render_template('admin/characters.html', characters=characters, character=character)

@admin_bp.route('/character/<int:char_id>/edit', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
@admin_required
def admin_edit_character(char_id):

    character = Character.query.get_or_404(char_id)
    form = EditCharacterForm(obj=character)
    if form.validate_on_submit():
        form.populate_obj(character)
        db.session.commit()
        admin_logger.info(f"Admin {current_user.username} updated character {character.name} at {datetime.utcnow()}")
        flash("Character updated.", "success")
        return redirect(url_for('admin.admin_characters'))
    return render_template('admin/edit_character.html', character=character, form=form)

@admin_bp.route('/character/<int:char_id>/delete', methods=['POST'])
@limiter.limit("20 per minute")
@admin_required
def admin_delete_character(char_id):
    character = Character.query.get_or_404(char_id)
    db.session.delete(character)
    admin_logger.info(f"Admin {current_user.username} deleted character {character.name} at {datetime.utcnow()}")
    db.session.commit()
    flash("Character deleted.", "success")
    return redirect(url_for('admin.admin_characters'))

# --- Admin Edit User ---
@admin_bp.route('/user/<int:user_id>/edit', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
@admin_required
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = EditUserForm(obj=user)
    if form.validate_on_submit():
        if current_user.id == user.id and not current_user.is_admin:
            admin_logger.warning(f"User {current_user.username} attempted to promote themselves to admin at {datetime.utcnow()}")
            flash("You cannot promote yourself to admin.", "danger")
            return redirect(url_for('admin.admin_users'))
        if current_user.id != user.id:
            is_admin = form.is_admin.data
            user.is_admin = bool(is_admin) if is_admin is not None else user.is_admin
        form.populate_obj(user)
        if form.password.data:
            user.set_password(form.password.data)
        db.session.commit()
        flash("User updated.", "success")
        return redirect(url_for('admin.admin_users'))
    return render_template('admin/edit_user.html', user=user, form=form)

# --- Admin Shop Management ---
@admin_bp.route('/shop')
@limiter.limit("20 per minute")
@admin_required
def admin_shop():
    character = Character.query.filter_by(master_id=current_user.id).first()
    online_timeout = datetime.utcnow() - timedelta(minutes=5)
    online_users = User.query.filter(User.last_seen >= online_timeout).all()
    online_characters = []
    for u in online_users:
        char = Character.query.filter_by(master_id=u.id, is_alive=True).first()
        if char:
            online_characters.append(char)
    items = ShopItem.query.order_by(ShopItem.id.desc()).all()
    delete_forms = {item.id: DeleteShopItemForm() for item in items}
    return render_template('admin/shop.html', items=items, character=character, online_characters=online_characters, online_users=online_users, delete_forms=delete_forms)

@admin_bp.route('/shop/add', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
@admin_required
def admin_add_shop_item():
    character = Character.query.filter_by(master_id=current_user.id).first()
    online_timeout = datetime.utcnow() - timedelta(minutes=5)
    online_users = User.query.filter(User.last_seen >= online_timeout).all()
    online_characters = []
    for u in online_users:
        char = Character.query.filter_by(master_id=u.id, is_alive=True).first()
        if char:
            online_characters.append(char)



    form = AddShopItemForm()
    if form.validate_on_submit():
        gun = None
        if form.is_gun.data:
            gun_name = form.gun_name.data.strip() or form.name.data.strip()
            gun = Gun.query.filter_by(name=gun_name).first()
            if gun:
                flash("A gun with this name already exists. Please choose a different name.", "danger")
                return redirect(url_for('admin.admin_add_shop_item'))
            gun = Gun(
                name=gun_name,
                damage=form.gun_damage.data or 0,
                accuracy=float(form.gun_accuracy.data or 0.7),
                rarity=form.gun_rarity.data or "Common",
                price=form.gun_price.data or form.price.data,
                image=form.gun_image.data or "",
                description=form.gun_description.data or ""
            )
            db.session.add(gun)
            db.session.commit()
        item = ShopItem(
            name=form.name.data.strip(),
            description=form.description.data.strip(),
            price=form.price.data,
            stock=form.stock.data,
            is_gun=form.is_gun.data,
            gun=gun
        )
        db.session.add(item)
        db.session.commit()


        
        admin_logger.info(f"Admin {current_user.username} added shop item {item.name} at {datetime.utcnow()}")
        flash("Shop item added!", "success")
        return redirect(url_for('admin.admin_shop'))
    return render_template('admin/add_shop_item.html', form=form, character=character, online_characters=online_characters, online_users=online_users)

@admin_bp.route('/shop/<int:item_id>/edit', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
@admin_required
def admin_edit_shop_item(item_id):
    item = ShopItem.query.get_or_404(item_id)
    gun = item.gun if item.is_gun else None
    form = EditShopItemForm(obj=item)
    if gun:
        form.gun_name.data = gun.name
        form.gun_damage.data = gun.damage
        form.gun_accuracy.data = str(gun.accuracy)
        form.gun_rarity.data = gun.rarity
        form.gun_price.data = gun.price
        form.gun_image.data = gun.image
        form.gun_description.data = gun.description
    if form.validate_on_submit():
        form.populate_obj(item)
        if item.is_gun:
            if not item.gun:
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

@admin_bp.route('/shop/<int:item_id>/delete', methods=['POST'])
@limiter.limit("20 per minute")
@admin_required
def admin_delete_shop_item(item_id):
    item = ShopItem.query.get_or_404(item_id)
    UserInventory.query.filter_by(item_id=item.id).delete()
    users_with_gun = User.query.filter_by(gun_id=item.id).all()
    for user in users_with_gun:
        user.gun_id = None
    characters_with_gun = Character.query.filter_by(gun_id=item.id).all()
    for char in characters_with_gun:
        char.gun_id = None
    db.session.delete(item)
    db.session.commit()
    flash("Shop item deleted.", "success")
    return redirect(url_for('admin.admin_shop'))

# --- Admin Organized Crimes ---
@admin_bp.route('/organized_crimes')
@limiter.limit("20 per minute")
@admin_required
def admin_organized_crimes():
    character = Character.query.filter_by(master_id=current_user.id).first()
    online_timeout = datetime.utcnow() - timedelta(minutes=5)
    online_users = User.query.filter(User.last_seen >= online_timeout).all()
    online_characters = []
    for u in online_users:
        char = Character.query.filter_by(master_id=u.id, is_alive=True).first()
        if char:
            online_characters.append(char)
    
    crimes = OrganizedCrime.query.order_by(OrganizedCrime.id.desc()).all()
    crime_forms = [(crime, DeleteCrimeForm(prefix=str(crime.id))) for crime in crimes]
    return render_template('admin/organized_crimes.html', crime_forms=crime_forms, crimes=crimes, character=character, online_characters=online_characters, online_users=online_users)

@admin_bp.route('/organized_crimes/<int:crime_id>/edit', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
@admin_required
def admin_edit_organized_crime(crime_id):
    crime = OrganizedCrime.query.get_or_404(crime_id)
    if request.method == 'POST':
        crime.name = request.form.get('name', crime.name)
        invite_code = request.form.get('invite_code', crime.invite_code)
        if invite_code and invite_code != crime.invite_code:
            if OrganizedCrime.query.filter_by(invite_code=invite_code).first():
                flash("Invite code already exists.", "danger")
                return redirect(url_for('admin.admin_edit_organized_crime', crime_id=crime.id))
            crime.invite_code = invite_code
        db.session.commit()
        flash("Organized crime updated.", "success")
        return redirect(url_for('admin.admin_organized_crimes'))
    return render_template('admin/edit_organized_crime.html', crime=crime)

@admin_bp.route('/organized_crimes/<int:crime_id>/delete', methods=['POST'])
@limiter.limit("20 per minute")
@admin_required
def admin_delete_organized_crime(crime_id):
    crime = OrganizedCrime.query.get_or_404(crime_id)
    for member in crime.members:
        member.crime_group_id = None
    db.session.delete(crime)
    db.session.commit()
    flash("Organized crime deleted.", "success")
    return redirect(url_for('admin.admin_organized_crimes'))

# --- Admin Search ---
@admin_bp.route('/search')
@limiter.limit("20 per minute")
@admin_required
def admin_search():
    character = Character.query.filter_by(master_id=current_user.id).first()
    online_timeout = datetime.utcnow() - timedelta(minutes=5)
    online_users = User.query.filter(User.last_seen >= online_timeout).all()
    online_characters = []
    for u in online_users:
        char = Character.query.filter_by(master_id=u.id, is_alive=True).first()
        if char:
            online_characters.append(char)
    q = request.args.get('q', '').strip()
    users = []
    characters = []
    if q:
        users = User.query.filter(User.username.ilike(f'%{q}%')).all()
        characters = Character.query.filter(Character.name.ilike(f'%{q}%')).all()
    return render_template('admin/search_results.html', q=q, users=users, characters=characters, character=character, online_characters=online_characters, online_users=online_users)

# --- Admin Topics ---
@admin_bp.route('/topics')
@limiter.limit("20 per minute")
@admin_required
def admin_topics():
    character = Character.query.filter_by(master_id=current_user.id).first()
    online_timeout = datetime.utcnow() - timedelta(minutes=5)
    online_users = User.query.filter(User.last_seen >= online_timeout).all()
    online_characters = []
    for u in online_users:
        char = Character.query.filter_by(master_id=u.id, is_alive=True).first()
        if char:
            online_characters.append(char)
    topics = ForumTopic.query.order_by(ForumTopic.created_at.desc()).all()
    user_ids = {t.author_id for t in topics}
    users_map = {u.id: u for u in User.query.filter(User.id.in_(user_ids)).all()}
    delete_form = DeleteForm()
    return render_template('admin/topics.html', topics=topics, users_map=users_map, delete_form=delete_form, character=character, online_characters=online_characters, online_users=online_users)

@admin_bp.route('/topics/<int:topic_id>/delete', methods=['POST'])
@limiter.limit("20 per minute")
@admin_required
def admin_delete_topic(topic_id):
    topic = ForumTopic.query.get_or_404(topic_id)
    ForumPost.query.filter_by(topic_id=topic.id).delete()
    db.session.delete(topic)
    db.session.commit()
    flash("Topic deleted.", "success")
    return redirect(url_for('admin.admin_topics'))

# --- Admin Drugs ---
@admin_bp.route('/drugs')
@limiter.limit("20 per minute")
@admin_required
def admin_drugs():
    character = Character.query.filter_by(master_id=current_user.id).first()
    online_timeout = datetime.utcnow() - timedelta(minutes=5)
    online_users = User.query.filter(User.last_seen >= online_timeout).all()
    online_characters = []
    for u in online_users:
        char = Character.query.filter_by(master_id=u.id, is_alive=True).first()
        if char:
            online_characters.append(char)
    drugs = Drug.query.order_by(Drug.id.desc()).all()
    return render_template('admin/drugs.html', drugs=drugs, character=character, online_characters=online_characters, online_users=online_users)

@admin_bp.route('/drugs/add', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
@admin_required
def admin_add_drug():
    form = AddDrugForm()
    if form.validate_on_submit():
        name = form.name.data.strip()
        drug_type = form.type.data or 'Other'
        if Drug.query.filter_by(name=name).first():
            flash("Drug already exists.", "danger")
            return redirect(url_for('admin.admin_add_drug'))
        db.session.add(Drug(name=name, type=drug_type))
        db.session.commit()
        flash("Drug added!", "success")
        return redirect(url_for('admin.admin_drugs'))
    return render_template('admin/add_drug.html', form=form)

# --- Admin Drug Dealers ---
@admin_bp.route('/dealers')
@limiter.limit("20 per minute")
@admin_required
def admin_dealers():
    dealers = DrugDealer.query.order_by(DrugDealer.city, DrugDealer.drug_id).all()
    return render_template('admin/dealers.html', dealers=dealers)

@admin_bp.route('/dealers/add', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
@admin_required
def admin_add_dealer():
    form = AddDealerForm()
    form.drug_id.choices = [(drug.id, drug.name) for drug in Drug.query.all()]
    if form.validate_on_submit():
        db.session.add(DrugDealer(
            city=form.city.data,
            drug_id=form.drug_id.data,
            price=form.price.data,
            stock=form.stock.data
        ))
        db.session.commit()
        flash("Dealer added!", "success")
        return redirect(url_for('admin.admin_drugs_dashboard'))
    return render_template('admin/drugs_dashboard.html',
        form=form,
        drugs=Drug.query.all(),
        cities=CITIES
    )

@admin_bp.route('/dealers/<int:dealer_id>/delete', methods=['POST'])
@limiter.limit("20 per minute")
@admin_required
def admin_delete_dealer(dealer_id):
    dealer = DrugDealer.query.get_or_404(dealer_id)
    db.session.delete(dealer)
    db.session.commit()
    flash("Dealer deleted.", "success")
    return redirect(url_for('admin.admin_drugs_dashboard'))

@admin_bp.route('/delete_drug/<int:drug_id>', methods=['POST'])
@limiter.limit("20 per minute")
@admin_required
def admin_delete_drug(drug_id):
    drug = Drug.query.get_or_404(drug_id)
    DrugDealer.query.filter_by(drug_id=drug.id).delete()
    CharacterDrugInventory.query.filter_by(drug_id=drug.id).delete()
    db.session.delete(drug)
    db.session.commit()
    flash("Drug deleted.", "success")
    return redirect(url_for('admin.admin_drugs_dashboard'))

@admin_bp.route('/drugs_dashboard', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
@admin_required
def admin_drugs_dashboard():
    character = Character.query.filter_by(master_id=current_user.id).first()
    online_timeout = datetime.utcnow() - timedelta(minutes=5)
    online_users = User.query.filter(User.last_seen >= online_timeout).all()
    online_characters = []
    for u in online_users:
        char = Character.query.filter_by(master_id=u.id, is_alive=True).first()
        if char:
            online_characters.append(char)
    drugs = Drug.query.order_by(Drug.id.desc()).all()
    dealers = DrugDealer.query.order_by(DrugDealer.city, DrugDealer.drug_id).all()
    delete_drug_forms = {drug.id: DeleteDrugForm(prefix=f"drug_{drug.id}") for drug in drugs}
    delete_dealer_forms = {dealer.id: DeleteDealerForm(prefix=f"dealer_{dealer.id}") for dealer in dealers}
    for drug in drugs:
        form = delete_drug_forms[drug.id]
        if form.validate_on_submit() and form.submit.data and f"drug_{drug.id}-submit" in request.form:
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
        delete_dealer_forms=delete_dealer_forms,
        character=character,
        online_characters=online_characters,
        online_users=online_users
    )

# --- Admin Reset Crime Cooldown ---
@admin_bp.route('/reset_crime_cooldown', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
@admin_required
def reset_crime_cooldown():
    character = Character.query.filter_by(master_id=current_user.id).first()
    online_timeout = datetime.utcnow() - timedelta(minutes=5)
    online_users = User.query.filter(User.last_seen >= online_timeout).all()
    online_characters = []
    for u in online_users:
        char = Character.query.filter_by(master_id=u.id, is_alive=True).first()
        if char:
            online_characters.append(char)
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
    return render_template('admin/reset_crime_cooldown.html', form=form, character=character, online_characters=online_characters, online_users=online_users)

# --- Admin Crews ---
@admin_bp.route('/crews')
@limiter.limit("20 per minute")
@admin_required
def admin_crews():
    character = Character.query.filter_by(master_id=current_user.id).first()
    online_timeout = datetime.utcnow() - timedelta(minutes=5)
    online_users = User.query.filter(User.last_seen >= online_timeout).all()
    online_characters = []
    for u in online_users:
        char = Character.query.filter_by(master_id=u.id, is_alive=True).first()
        if char:
            online_characters.append(char)
    crews = Crew.query.all()
    crew_forms = [(crew, DeleteCrewForm()) for crew in crews]
    return render_template('admin/crews.html', crew_forms=crew_forms, character=character, online_characters=online_characters, online_users=online_users)

@admin_bp.route('/crews/<int:crew_id>/delete', methods=['POST'])
@limiter.limit("20 per minute")
@admin_required
def admin_delete_crew(crew_id):
    crew = Crew.query.get_or_404(crew_id)
    for user in crew.members:
        user.crew_id = None
    CrewMember.query.filter_by(crew_id=crew.id).delete()
    db.session.delete(crew)
    db.session.commit()
    flash("Crew deleted.", "success")
    return redirect(url_for('admin.admin_crews'))

