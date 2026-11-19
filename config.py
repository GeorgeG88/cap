"""Application configuration, read from environment variables / the .env file.

Values that differ between installations (secret key, host, port, Telegram
and SMTP credentials) live in the .env file next to this one. Everything
else has a sensible default here. Settings that the admin changes at run
time (rules, notification options) are stored in the database instead.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

# The project folder (where this file is).
BASE_DIR = Path(__file__).resolve().parent
# Copy the values from .env into the environment so os.getenv() can read them.
load_dotenv(BASE_DIR / ".env")

# Data that belongs to this installation: database and temporary uploads.
INSTANCE_DIR = BASE_DIR / "instance"


class Config:
    """Settings for normal use."""

    # Signs the session cookie. Generated randomly by "python manage.py init".
    SECRET_KEY = os.getenv("SECRET_KEY", "")

    # SQLite database file. Backslashes are replaced so Windows paths work in the URL.
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL", "sqlite:///" + str(INSTANCE_DIR / "analyzer.db").replace("\\", "/"))
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # timeout=30: wait up to 30 s if another thread is writing, instead of failing.
    # check_same_thread=False: allow the background threads to use connections too.
    SQLALCHEMY_ENGINE_OPTIONS = {"connect_args": {"timeout": 30, "check_same_thread": False}}

    UPLOAD_DIR = str(INSTANCE_DIR / "uploads")
    # Uploads larger than this are rejected (error 413) before they are saved.
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_UPLOAD_MB", "50")) * 1024 * 1024

    # Address the web server listens on. 127.0.0.1 = only this computer can connect.
    HOST = os.getenv("HOST", "127.0.0.1")
    PORT = int(os.getenv("PORT", "5000"))
    # Used to put a link to the alert in notification messages.
    BASE_URL = os.getenv("BASE_URL", "")

    # Cookie protection:
    #   HTTPONLY - JavaScript cannot read the session cookie
    #   SAMESITE - the cookie is not sent with requests started by other sites
    #   SECURE   - send only over HTTPS (turn on if the app is served over HTTPS)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "0") == "1"
    REMEMBER_COOKIE_HTTPONLY = True
    PERMANENT_SESSION_LIFETIME = 60 * 60 * 8     # 8 hours
    # CSRF tokens stay valid for the whole session (pages can stay open all day).
    WTF_CSRF_TIME_LIMIT = None

    # Login lockout: 5 wrong passwords -> locked for 10 minutes (see security.py).
    LOGIN_MAX_FAILURES = 5
    LOGIN_LOCKOUT_MINUTES = 10

    # Start the notifier and (if configured) live monitoring when the app starts.
    START_BACKGROUND_SERVICES = True


class TestConfig(Config):
    """Settings for the automated tests: a throwaway in-memory database,
    no CSRF tokens needed, no background services."""

    TESTING = True
    SECRET_KEY = "test-secret"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    # StaticPool makes every thread share the same in-memory database
    # (otherwise each connection would get its own empty one).
    SQLALCHEMY_ENGINE_OPTIONS = {"connect_args": {"check_same_thread": False},
                                 "poolclass": __import__("sqlalchemy.pool", fromlist=["StaticPool"]).StaticPool}
    WTF_CSRF_ENABLED = False
    START_BACKGROUND_SERVICES = False
