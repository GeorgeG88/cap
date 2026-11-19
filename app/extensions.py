"""Flask extensions, created here once and connected to the app in create_app().

They live in their own module so any other module can import them without
importing the whole application (which would cause circular imports).
"""

from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()               # database access (models, queries, sessions)
login_manager = LoginManager()  # remembers who is logged in via a signed session cookie
csrf = CSRFProtect()            # rejects form submissions that do not come from our own pages
