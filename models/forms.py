from flask_wtf import FlaskForm, RecaptchaField
from flask_admin.form import SecureForm
from wtforms import (
    PasswordField, StringField, BooleanField, IntegerField, SubmitField,
    SelectField, FileField, RadioField, TextAreaField, HiddenField
)
from wtforms.fields import DateTimeField
from wtforms.validators import DataRequired, NumberRange, Optional, Length,ValidationError, Email, EqualTo, InputRequired
from models.constants import CITIES
from models.character import Character

class KillCharacterForm(FlaskForm):
    submit = SubmitField('Kill Current Character')
class UserSettingsForm(FlaskForm):
    email = StringField('New Email', validators=[Optional(), Email(), Length(max=120)])
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[Optional(), Length(min=6)])
    confirm_password = PasswordField('Confirm New Password', validators=[EqualTo('new_password', message='Passwords must match'), Optional()])
    submit = SubmitField('Update Settings')

class StealForm(FlaskForm):
    target_name = StringField('Target Character Name', validators=[DataRequired()])
    submit = SubmitField('Attempt Steal')

class RenameTerritoryForm(FlaskForm):
    custom_name = StringField('Custom Name', validators=[Length(max=64), Optional()])
    theme = StringField('Theme', validators=[Length(max=64), Optional()])
    submit = SubmitField('Update')

class ClaimTerritoryForm(FlaskForm):
    submit = SubmitField('Claim')

class StartTakeoverForm(FlaskForm):
    submit = SubmitField('Start Takeover')

class ResolveTakeoverForm(FlaskForm):
    submit = SubmitField('Resolve Takeover')

class CrewPayoutForm(FlaskForm):
    submit = SubmitField('Collect Crew Payout')

class HireBodyguardForm(FlaskForm):
    num = IntegerField('How many bodyguards do you want to hire?', validators=[DataRequired(), NumberRange(min=1, max=5)])
    submit = SubmitField('Hire')

class EditBioForm(FlaskForm):
    bio = TextAreaField('Bio', validators=[Length(max=1000)])
    submit = SubmitField('Save Bio')

class CreateForumForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description', validators=[DataRequired()])
    submit = SubmitField('Create Forum')
class SendBeerForm(FlaskForm):
    recipient_name = StringField('Recipient Name', validators=[DataRequired()])
    drink_type = SelectField(
        'Drink Type',
        choices=[
            ('beer', 'Beer'),
            ('whiskey', 'Whiskey'),
            ('wine', 'Wine'),
            ('vodka', 'Vodka'),
            ('rum', 'Rum'),
            ('gin', 'Gin')
        ],
        validators=[DataRequired()]
    )
    submit = SubmitField('Send Drink')
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
    def validate_character_name(self, field):
        if ' ' in field.data:
            raise ValidationError('Character name cannot contain spaces.')
        # Uniqueness check
        if Character.query.filter_by(name=field.data).first():
            raise ValidationError('This character name is already taken. Please choose another.')
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
class UpgradeCrimeForm(FlaskForm):
    submit = SubmitField('Upgrade Group')
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
    user_name = StringField('Username', validators=[DataRequired()])
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
class MinigameRollForm(FlaskForm):
    submit = SubmitField('Roll!')
class EditUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[Optional()])
    crew_id = IntegerField('Crew ID', validators=[Optional()])
    is_admin = BooleanField('Is Admin')
    premium = BooleanField('Premium')
    submit = SubmitField('Save Changes')
class LeaveCrewForm(FlaskForm):
    submit = SubmitField('Leave Crew')
class DeleteShopItemForm(FlaskForm):
    submit = SubmitField('Delete')
class AdminCommandForm(FlaskForm):
    command = StringField('Command', validators=[DataRequired()])
    submit = SubmitField('Execute')
class DepositForm(FlaskForm):
    amount = IntegerField('Amount', validators=[DataRequired(), NumberRange(min=1)])
    submit = SubmitField('Deposit')
class BuyStockForm(FlaskForm):
    shares = IntegerField('Shares', validators=[DataRequired(), NumberRange(min=1)])
    submit = SubmitField('Buy')

class SellStockForm(FlaskForm):
    shares = IntegerField('Shares', validators=[DataRequired(), NumberRange(min=1)])
    submit = SubmitField('Sell')

class RugStockForm(FlaskForm):
    submit = SubmitField('Rug')
class WithdrawForm(FlaskForm):
    amount = IntegerField('Amount', validators=[DataRequired(), NumberRange(min=1)])
    submit = SubmitField('Withdraw')

class TransferForm(FlaskForm):
    recipient = StringField('Recipient', validators=[DataRequired()])
    amount = IntegerField('Amount', validators=[DataRequired(), NumberRange(min=1)])
    submit = SubmitField('Transfer')

class GatherResourcesForm(FlaskForm):
    submit = SubmitField('Gather Random Amount')
class MinigameForm(FlaskForm):
    guess1 = IntegerField('Attempt 1', validators=[InputRequired(), NumberRange(min=1, max=10)])
    guess2 = IntegerField('Attempt 2', validators=[InputRequired(), NumberRange(min=1, max=10)])
    guess3 = IntegerField('Attempt 3', validators=[InputRequired(), NumberRange(min=1, max=10)])
    attempt = HiddenField()
    finished = HiddenField()
    submit = SubmitField('Submit Guess')
class ContributeResourcesForm(FlaskForm):
    resource_type = SelectField('Resource Type', choices=[('supplies', 'Supplies')], validators=[DataRequired()])
    amount = IntegerField('Amount', validators=[DataRequired(), NumberRange(min=1)])
    submit = SubmitField('Contribute Resources')

class GatherResourcesForm(FlaskForm):
    submit = SubmitField('Gather Resources')
class DummyRemoveForm(FlaskForm):
    pass
class DummyDisbandForm(FlaskForm):
    pass