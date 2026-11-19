"""Shared test helpers (pytest loads this file automatically).

Fixtures are set-up functions that pytest passes to any test that names
them as a parameter:
  app             a fresh application with an empty in-memory database
  db_session      database access inside that app
  admin_client    a browser-like client already logged in as an admin
  analyst_client  the same, logged in as an analyst

Run all tests with:  pytest -q
"""
import os
import sys
from datetime import datetime, timedelta

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.parser import FirewallEvent  # noqa: E402

T0 = datetime(2026, 10, 19, 14, 0, 0)


# Build one parsed event directly. T0 + seconds sets its time; the other
# arguments default to an ordinary blocked TCP SYN from 10.0.0.5 to port 80.
def ev(seconds=0, src="10.0.0.5", dst="10.0.0.1", proto="TCP", spt=40000, dpt=80,
       action="DENY", flags=("SYN",), icmp_type=None):
    """Build a parsed event directly (no log text needed)."""
    return FirewallEvent(timestamp=T0 + timedelta(seconds=seconds), action=action,
                         ufw_action="BLOCK" if action == "DENY" else action, src_ip=src, dst_ip=dst,
                         proto=proto, src_port=spt, dst_port=dpt, flags=tuple(flags),
                         icmp_type=icmp_type)


@pytest.fixture
def app():
    from app import create_app
    from config import TestConfig
    application = create_app(TestConfig)
    yield application


@pytest.fixture
def db_session(app):
    from app.extensions import db
    with app.app_context():
        yield db.session


# Create a user directly in the database.
def make_user(app, username="admin", role="admin", password="CorrectHorse9"):
    from app.extensions import db
    from app.models import User
    with app.app_context():
        u = User(username=username, role=role)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()


@pytest.fixture
def admin_client(app):
    make_user(app)
    c = app.test_client()
    c.post("/login", data={"username": "admin", "password": "CorrectHorse9"})
    return c


@pytest.fixture
def analyst_client(app):
    make_user(app, "analyst", "analyst")
    c = app.test_client()
    c.post("/login", data={"username": "analyst", "password": "CorrectHorse9"})
    return c
