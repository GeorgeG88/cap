"""Firewall Log Analyzer and Alert System - Flask application factory.

``create_app()`` builds and configures the whole web application:
  1. load settings (from config.py / .env)
  2. connect the extensions: database, CSRF protection, login handling
  3. register the web pages (blueprints) and security headers
  4. create the database tables and default rules if they do not exist
  5. start the background services: notification sender and live monitor

The "factory" pattern (a function that returns a new app) lets the tests
create a fresh app with an in-memory database for every test.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime

from flask import Flask, render_template
from sqlalchemy import event as sa_event
from sqlalchemy.engine import Engine

from config import INSTANCE_DIR, Config
from .extensions import csrf, db, login_manager
from .security import LoginThrottle, apply_security_headers

# Severity -> CSS class used for the coloured badges in the pages.
SEVERITY_CLASS = {"low": "sev-low", "medium": "sev-medium", "high": "sev-high", "critical": "sev-critical"}


@sa_event.listens_for(Engine, "connect")
def _sqlite_pragmas(dbapi_conn, _record):
    """WAL mode lets the web UI read while the analysis threads write.

    Runs every time a new database connection is opened.
      journal_mode=WAL  readers do not block the writer and vice versa
      foreign_keys=ON   SQLite only enforces foreign keys when asked to
      synchronous=NORMAL  faster writes, still safe with WAL
    """
    try:
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.close()
    except Exception:
        pass


def ensure_columns() -> None:
    """Add columns introduced after a database was first created.

    SQLite has no automatic migrations and db.create_all() only creates missing
    tables, not missing columns. This adds any new column to an existing database
    so upgrading does not require wiping it. Safe to run on every startup.
    """
    from sqlalchemy import inspect, text
    insp = inspect(db.engine)
    if "alerts" not in insp.get_table_names():
        return
    existing = {c["name"] for c in insp.get_columns("alerts")}
    for name, ddl in [("incident_id", "ALTER TABLE alerts ADD COLUMN incident_id INTEGER")]:
        if name not in existing:
            db.session.execute(text(ddl))
            db.session.commit()


def seed_defaults() -> None:
    """Insert the built-in detection rules on first start.

    Rules that already exist are left alone, so thresholds edited on the
    Rules page are never overwritten.
    """
    from .core.authparser import DEFAULT_AUTH_RULE
    from .core.detection import DEFAULT_RULES
    from .models import Rule
    changed = False
    for r in DEFAULT_RULES + [DEFAULT_AUTH_RULE]:
        if db.session.get(Rule, r["rule_id"]) is None:
            db.session.add(Rule(rule_id=r["rule_id"], name=r["name"], description=r["description"],
                                threshold=r["threshold"], window_seconds=r["window_seconds"],
                                severity=r["severity"], params=r["params"], enabled=True))
            changed = True
    if changed:
        db.session.commit()


def create_app(config_object=Config) -> Flask:
    """Build the Flask application (see the module description for the steps)."""
    # The "instance" folder holds data that belongs to this installation:
    # the SQLite database and temporary uploads.
    app = Flask(__name__, instance_path=str(INSTANCE_DIR))
    app.config.from_object(config_object)
    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config["UPLOAD_DIR"], exist_ok=True)

    # The secret key signs the session cookie. Without it anyone could forge
    # a login, so the app refuses to start.
    if not app.config.get("SECRET_KEY"):
        raise RuntimeError("SECRET_KEY is not set. Run 'python manage.py init' to create the .env file.")

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    # Connect the extensions to this app.
    db.init_app(app)
    csrf.init_app(app)                 # every POST form must carry a valid CSRF token
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"          # where to send users who are not logged in
    login_manager.login_message_category = "info"
    # "strong" ends the session if the browser or IP address changes,
    # which makes a stolen session cookie much harder to use.
    login_manager.session_protection = "strong"

    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        """Called on every request to turn the id in the session cookie back into a user.
        Disabled users are treated as logged out immediately."""
        user = db.session.get(User, int(user_id))
        return user if user and user.active else None

    # Failed-login counter, shared by all requests (see security.py).
    app.extensions["login_throttle"] = LoginThrottle(app.config["LOGIN_MAX_FAILURES"],
                                                     app.config["LOGIN_LOCKOUT_MINUTES"] * 60)

    # All the pages (app/web/*.py).
    from .web import register_blueprints
    register_blueprints(app)

    # Add security headers to every response.
    app.after_request(apply_security_headers)

    # -- template helpers, used as {{ value|dt }} etc. in the HTML templates --
    @app.template_filter("dt")
    def fmt_dt(value, fmt="%Y-%m-%d %H:%M:%S"):
        """Format a date/time, or show "-" if there is none."""
        return value.strftime(fmt) if isinstance(value, datetime) else (value or "-")

    @app.template_filter("sevclass")
    def sev_class(value):
        """CSS class for a severity badge."""
        return SEVERITY_CLASS.get(value, "")

    @app.template_filter("num")
    def fmt_num(value):
        """Thousands separators: 12345 -> 12,345."""
        try:
            return f"{int(value):,}"
        except (TypeError, ValueError):
            return value

    @app.context_processor
    def inject_globals():
        """Values available in every template (the sidebar shows a dot while monitoring runs)."""
        from .core.monitor import RATE_LIMITED_LOG_LEVELS, ufw_logging_level
        monitor = app.extensions.get("monitor")
        level = ufw_logging_level()
        return {"monitor_running": bool(monitor and monitor.running), "now": datetime.now(),
                "ufw_logging_level": level,
                "ufw_logging_rate_limited": level in RATE_LIMITED_LOG_LEVELS}

    # Friendly error pages instead of the default ones.
    # (c=code fixes the value of code for each lambda.)
    for code in (403, 404, 413, 500):
        app.register_error_handler(
            code, lambda e, c=code: (render_template("error.html", code=c, error=e), c))

    # Create any missing tables and the default rules.
    with app.app_context():
        db.create_all()
        ensure_columns()
        seed_defaults()

    # background services: notification queue + live monitor
    from .core.monitor import LiveMonitor
    from .core.notifier import Notifier

    def record(alert_id, channel, status, attempts, error):
        """Called by the notifier thread after each delivery attempt, to save the result."""
        from .models import Notification
        with app.app_context():
            db.session.add(Notification(alert_id=alert_id, channel=channel, status=status,
                                        attempts=attempts, error=error))
            db.session.commit()

    # One notifier and one monitor for the whole application, stored on the
    # app so the web pages can reach them.
    notifier = Notifier(record=record, base_url=app.config.get("BASE_URL", ""))
    app.extensions["notifier"] = notifier
    app.extensions["monitor"] = LiveMonitor(app, notifier)

    # The tests switch this off so no background threads start.
    if app.config.get("START_BACKGROUND_SERVICES"):
        with app.app_context():
            from .models import AnalysisRun, get_setting
            # runs interrupted by a previous shutdown are marked as such
            # (otherwise they would show "running" forever).
            for run in AnalysisRun.query.filter(AnalysisRun.status.in_(["queued", "running"])).all():
                run.status = "stopped" if run.source == "live" else "failed"
                run.error = run.error or "Interrupted by application restart"
                run.finished_at = run.finished_at or datetime.now()
            db.session.commit()
            # Resume live monitoring automatically if the admin chose that option.
            if get_setting("monitor_autostart"):
                err = app.extensions["monitor"].start(get_setting("monitor_log_path"),
                                                      get_setting("monitor_from_start"), "system")
                if err:
                    app.logger.warning("Live monitor autostart failed: %s", err)
    return app
