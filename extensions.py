# extensions.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from flask_migrate import Migrate
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import stripe
limiter = Limiter(key_func=get_remote_address, storage_uri="redis://localhost:6379/0")
db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()
migrate = Migrate()
csrf = CSRFProtect()
stripe.api_key = "sk_test_51RjpHk3YQQu0IS1Okq5IIocVgqA9PKR6Ug8UQ2n6TSSM9eLPG1GWHZJWzmLoLn4W9TarndLs3MvYDmV4V86uMwyt00DdVFFCrI"