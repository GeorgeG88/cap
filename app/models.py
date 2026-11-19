"""Database models (SQLite through SQLAlchemy).

Each class below is one database table. SQLAlchemy (an ORM, object
relational mapper) turns rows into Python objects, so the code works with
objects like ``alert.severity`` instead of writing SQL by hand.

Tables and what they hold
  users           accounts that can log in (admin or analyst)
  analysis_runs   one row per uploaded file or live monitoring session
  events          every stored firewall log entry (the biggest table)
  alerts          what the detection rules found
  notifications   delivery results of Telegram/email messages per alert
  rules           detection rule settings, edited on the Rules page
  allowlist       trusted addresses/networks
  settings        simple key/value settings from the Settings page
  audit_log       security-relevant actions (logins, config changes, triage)

How they relate
  analysis_runs 1 --- * events         (deleting a run deletes its events)
  analysis_runs 1 --- * alerts
  alerts        1 --- * notifications
"""

from __future__ import annotations

import json
from datetime import datetime

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db

ROLES = ("admin", "analyst")
# An alert moves through these states as the analyst works on it.
ALERT_STATUSES = ("new", "acknowledged", "resolved")


class JSONText(db.TypeDecorator):
    """Stores a dict/list as JSON text.

    SQLite has no dictionary type, so values such as the alert details are
    converted to JSON text when saved and back into a dict when loaded.
    """

    impl = db.Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        # Python -> database. default=str handles values like datetimes.
        return json.dumps(value, default=str) if value is not None else None

    def process_result_value(self, value, dialect):
        # Database -> Python. An empty value becomes an empty dict.
        return json.loads(value) if value else {}


class User(UserMixin, db.Model):
    """A person who can log in. UserMixin adds what Flask-Login needs."""

    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    # Only a salted hash of the password is stored, never the password itself.
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(16), nullable=False, default="analyst")
    active = db.Column(db.Boolean, nullable=False, default=True)   # False = account disabled
    created_at = db.Column(db.DateTime, default=datetime.now)
    last_login = db.Column(db.DateTime)

    def set_password(self, password: str) -> None:
        # Werkzeug's default is scrypt: slow on purpose, with a random salt,
        # so stolen hashes are expensive to crack.
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    @property
    def is_active(self) -> bool:  # used by Flask-Login
        return bool(self.active)


class AnalysisRun(db.Model):
    """One analysis: an uploaded file or a live monitoring session.

    The counters are updated while the analysis runs, so the run page can
    show progress, and they document how much of the log was usable.
    """

    __tablename__ = "analysis_runs"
    id = db.Column(db.Integer, primary_key=True)
    source = db.Column(db.String(16), nullable=False)          # upload | live
    filename = db.Column(db.String(255))                       # uploaded file name or log path
    status = db.Column(db.String(16), nullable=False, default="queued")  # queued|running|done|failed|stopped
    notify = db.Column(db.Boolean, default=False)              # send Telegram/email for this run?
    started_at = db.Column(db.DateTime, default=datetime.now)
    finished_at = db.Column(db.DateTime)
    lines_total = db.Column(db.Integer, default=0)
    lines_parsed = db.Column(db.Integer, default=0)
    lines_not_ufw = db.Column(db.Integer, default=0)
    lines_malformed = db.Column(db.Integer, default=0)
    events_noise = db.Column(db.Integer, default=0)
    events_allowlisted = db.Column(db.Integer, default=0)
    events_stored = db.Column(db.Integer, default=0)
    alerts_created = db.Column(db.Integer, default=0)
    first_event = db.Column(db.DateTime)                       # time span covered by the log
    last_event = db.Column(db.DateTime)
    error = db.Column(db.Text)                                 # why the run failed, if it did
    created_by = db.Column(db.String(64))

    @property
    def duration_seconds(self):
        """How long the analysis took (None while it is still running)."""
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None


class Event(db.Model):
    """One firewall log entry. Columns match FirewallEvent in core/parser.py.

    index=True columns get a database index, which makes the filters on the
    Events page and the dashboard statistics fast on large tables.
    """

    __tablename__ = "events"
    id = db.Column(db.Integer, primary_key=True)
    run_id = db.Column(db.Integer, db.ForeignKey("analysis_runs.id", ondelete="CASCADE"), index=True)
    timestamp = db.Column(db.DateTime, nullable=False, index=True)
    action = db.Column(db.String(8), nullable=False, index=True)    # ALLOW | DENY | AUDIT
    ufw_action = db.Column(db.String(24))
    src_ip = db.Column(db.String(45), nullable=False, index=True)   # 45 chars fits any IPv6 address
    dst_ip = db.Column(db.String(45), nullable=False, index=True)
    proto = db.Column(db.String(10), index=True)
    src_port = db.Column(db.Integer)
    dst_port = db.Column(db.Integer, index=True)
    iface_in = db.Column(db.String(32))
    iface_out = db.Column(db.String(32))
    direction = db.Column(db.String(8))
    length = db.Column(db.Integer)
    ttl = db.Column(db.Integer)
    flags = db.Column(db.String(40))                                # e.g. "SYN" or "ACK PSH"
    icmp_type = db.Column(db.Integer)
    hostname = db.Column(db.String(64))
    allowlisted = db.Column(db.Boolean, default=False)              # stored but excluded from detection
    raw = db.Column(db.Text)                                        # original log line (shortened)


class Alert(db.Model):
    """Something a detection rule found, plus the analyst's triage state."""

    __tablename__ = "alerts"
    id = db.Column(db.Integer, primary_key=True)
    # SET NULL: deleting a run keeps nothing pointing at a missing run.
    run_id = db.Column(db.Integer, db.ForeignKey("analysis_runs.id", ondelete="SET NULL"), index=True)
    rule_id = db.Column(db.String(32), nullable=False, index=True)
    rule_name = db.Column(db.String(64), nullable=False)
    severity = db.Column(db.String(10), nullable=False, index=True)
    src_ip = db.Column(db.String(45), nullable=False, index=True)   # "*" for the global traffic spike rule
    first_seen = db.Column(db.DateTime, nullable=False, index=True)
    last_seen = db.Column(db.DateTime, nullable=False)
    event_count = db.Column(db.Integer, default=0)                  # distinct items (ports, attempts...)
    threshold = db.Column(db.Integer)                               # rule settings at the time of the alert
    window_seconds = db.Column(db.Integer)
    occurrences = db.Column(db.Integer, default=1)   # merged detection episodes
    details = db.Column(JSONText)                                   # rule-specific evidence
    status = db.Column(db.String(16), nullable=False, default="new", index=True)
    status_changed_by = db.Column(db.String(64))
    status_changed_at = db.Column(db.DateTime)
    notes = db.Column(db.Text)                                      # analyst notes, one per line
    notified_at = db.Column(db.DateTime)                            # used for the notification cooldown
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    # alert.notifications lists the delivery attempts for this alert.
    # lazy="dynamic" returns a query, so it can be sorted when displayed.
    notifications = db.relationship("Notification", backref="alert", lazy="dynamic",
                                    cascade="all, delete-orphan")


class Notification(db.Model):
    """The outcome of sending one alert through one channel."""

    __tablename__ = "notifications"
    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.Integer, db.ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    channel = db.Column(db.String(16), nullable=False)       # telegram | email
    status = db.Column(db.String(16), nullable=False)        # sent | failed
    attempts = db.Column(db.Integer, default=1)
    error = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now)


class Rule(db.Model):
    """Settings of one detection rule. The logic itself lives in core/detection.py."""

    __tablename__ = "rules"
    rule_id = db.Column(db.String(32), primary_key=True)    # e.g. "port_scan"
    name = db.Column(db.String(64), nullable=False)
    description = db.Column(db.Text)
    enabled = db.Column(db.Boolean, default=True)
    threshold = db.Column(db.Integer, nullable=False)
    window_seconds = db.Column(db.Integer, nullable=False)
    severity = db.Column(db.String(10), nullable=False)
    params = db.Column(JSONText)                            # extras, e.g. {"auth_ports": [22, 3389]}
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    updated_by = db.Column(db.String(64))

    def to_config_dict(self) -> dict:
        """The form the detection engine expects (see RuleConfig.from_dict)."""
        return {"rule_id": self.rule_id, "name": self.name, "threshold": self.threshold,
                "window_seconds": self.window_seconds, "severity": self.severity,
                "enabled": self.enabled, "params": self.params or {}}


class AllowlistEntry(db.Model):
    """A trusted address or network, e.g. 192.168.56.1 or 10.0.0.0/8."""

    __tablename__ = "allowlist"
    id = db.Column(db.Integer, primary_key=True)
    cidr = db.Column(db.String(64), nullable=False, unique=True)
    note = db.Column(db.String(255))
    created_by = db.Column(db.String(64))
    created_at = db.Column(db.DateTime, default=datetime.now)


class Setting(db.Model):
    """One setting as a key/value pair; values are stored as text.
    Use get_setting() / set_setting() below rather than this class directly."""

    __tablename__ = "settings"
    key = db.Column(db.String(64), primary_key=True)
    value = db.Column(db.Text)


class AuditLog(db.Model):
    """Who did what, and from which IP address (shown on the Audit log page)."""

    __tablename__ = "audit_log"
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.now, index=True)
    username = db.Column(db.String(64))
    ip = db.Column(db.String(45))
    action = db.Column(db.String(64), nullable=False)      # e.g. "login_failed", "rule_updated"
    detail = db.Column(db.Text)


# --------------------------------------------------------------------------
# settings helpers
# --------------------------------------------------------------------------
# Every setting with its default value. The type of the default (bool, int
# or str) decides how the stored text is converted back when it is read.
DEFAULT_SETTINGS = {
    "telegram_enabled": False,
    "email_enabled": False,
    "notify_min_severity": "high",
    "notify_cooldown_minutes": 15,
    "alert_merge_minutes": 10,
    "drop_broadcast": True,
    "drop_multicast": True,
    "noise_ports": "67,68,137,138,1900,5353,5355",
    "monitor_log_path": "/var/log/ufw.log",
    "monitor_from_start": False,
    "monitor_autostart": False,
    "ollama_url": "http://localhost:11434",
    "ollama_model": "",
}


def _coerce(default, raw: str):
    """Convert stored text back to the type of the default value."""
    if isinstance(default, bool):    # must be checked before int: in Python, bool is a kind of int
        return raw in ("1", "true", "True", "on", "yes")
    if isinstance(default, int):
        try:
            return int(raw)
        except (TypeError, ValueError):
            return default
    return raw


def get_setting(key: str):
    """Read a setting, falling back to its default if it was never saved."""
    default = DEFAULT_SETTINGS.get(key)
    row = db.session.get(Setting, key)
    if row is None or row.value is None:
        return default
    return _coerce(default, row.value)


def set_setting(key: str, value) -> None:
    """Save a setting (the caller commits). Booleans are stored as "1"/"0"."""
    if isinstance(value, bool):
        value = "1" if value else "0"
    row = db.session.get(Setting, key)
    if row is None:
        row = Setting(key=key)
        db.session.add(row)
    row.value = str(value)


def all_settings() -> dict:
    """Every setting in one dictionary (used when an analysis starts)."""
    return {k: get_setting(k) for k in DEFAULT_SETTINGS}


def audit(action: str, detail: str = "", username: str | None = None, ip: str | None = None) -> None:
    """Record a security-relevant action. Caller commits.

    Inside a web request the user name and IP address are filled in
    automatically. Background threads (no request) pass them explicitly.
    """
    try:
        from flask import request
        from flask_login import current_user
        if username is None and current_user and getattr(current_user, "is_authenticated", False):
            username = current_user.username
        if ip is None:
            ip = request.remote_addr
    except RuntimeError:  # outside a request
        pass
    db.session.add(AuditLog(username=username, ip=ip, action=action, detail=detail[:2000]))
