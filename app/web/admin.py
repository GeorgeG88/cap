"""Configuration pages: rules and allowlist, settings, users and the audit log.

Analysts may view the Rules page (read-only). Everything that changes the
configuration requires the admin role, and every change is written to the
audit log. All form input is validated on the server before it is saved,
even if the HTML form already limits it, because form limits in the
browser can be bypassed.
"""

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from ..core.detection import SEVERITIES
from ..core.filters import is_valid_network
from ..core.notifier import EmailChannel, TelegramChannel, send_test
from ..core.summarizer import SummaryError, list_models
from ..extensions import db
from ..models import (ROLES, AllowlistEntry, AuditLog, Rule, User, all_settings, audit,
                      set_setting)
from ..security import admin_required
from .auth import password_problem

bp = Blueprint("admin", __name__)


def _int_in(value, lo, hi):
    """The value as a whole number if it is between lo and hi, otherwise None."""
    try:
        v = int(value)
    except (TypeError, ValueError):
        return None
    return v if lo <= v <= hi else None


# --------------------------------------------------------------------------
# rules and allowlist
# --------------------------------------------------------------------------
@bp.route("/rules")
@login_required
def rules():
    """Rule cards and the allowlist (the template disables the inputs for analysts)."""
    return render_template("rules.html", rules=Rule.query.order_by(Rule.name).all(),
                           allowlist=AllowlistEntry.query.order_by(AllowlistEntry.cidr).all(),
                           severities=SEVERITIES, monitor_running=current_app.extensions["monitor"].running)


@bp.route("/rules/<rule_id>", methods=["POST"])
@admin_required
def rule_update(rule_id):
    """Save one rule's settings after checking every value."""
    rule = db.session.get(Rule, rule_id) or abort(404)
    threshold = _int_in(request.form.get("threshold"), 1, 100_000)
    window = _int_in(request.form.get("window_seconds"), 1, 86_400)   # up to one day
    severity = request.form.get("severity")
    if threshold is None or window is None or severity not in SEVERITIES:
        flash("Threshold must be 1-100000, window 1-86400 seconds, and severity valid.", "danger")
        return redirect(url_for("admin.rules"))

    # Rule-specific extra settings.
    params = dict(rule.params or {})
    if rule.rule_id == "brute_force":
        # "22, 3389, 21" -> [21, 22, 3389]; any invalid port rejects the whole list.
        ports = [_int_in(p.strip(), 1, 65535) for p in request.form.get("auth_ports", "").split(",") if p.strip()]
        if not ports or None in ports:
            flash("Authentication ports must be a comma-separated list of port numbers.", "danger")
            return redirect(url_for("admin.rules"))
        params["auth_ports"] = sorted(set(ports))
    if rule.rule_id == "traffic_spike":
        baseline = _int_in(request.form.get("baseline_minutes"), 3, 120)
        try:
            multiplier = float(request.form.get("multiplier", ""))
        except ValueError:
            multiplier = None
        if baseline is None or multiplier is None or not 1.0 <= multiplier <= 100:
            flash("Baseline must be 3-120 minutes and multiplier 1-100.", "danger")
            return redirect(url_for("admin.rules"))
        params.update(baseline_minutes=baseline, multiplier=multiplier)

    # The audit entry records the old and new values, so tuning decisions
    # can be traced later (useful for the evaluation as well).
    before = rule.to_config_dict()
    rule.threshold, rule.window_seconds, rule.severity = threshold, window, severity
    rule.enabled = bool(request.form.get("enabled"))   # unticked checkboxes send nothing
    rule.params = params
    rule.updated_by = current_user.username
    audit("rule_updated", f"{rule.rule_id}: {before} -> {rule.to_config_dict()}")
    db.session.commit()
    msg = f"Rule '{rule.name}' saved."
    if current_app.extensions["monitor"].running:
        # The live monitor loaded its rules when it started.
        msg += " Restart live monitoring to apply it there."
    flash(msg, "success")
    # The #rule-... part scrolls the page back to the rule that was edited.
    return redirect(url_for("admin.rules") + f"#rule-{rule.rule_id}")


@bp.route("/allowlist", methods=["POST"])
@admin_required
def allowlist_add():
    """Add a trusted address or network."""
    cidr = request.form.get("cidr", "").strip()
    note = request.form.get("note", "").strip()[:255]
    if not is_valid_network(cidr):
        flash(f"'{cidr}' is not a valid IP address or network (e.g. 192.168.56.1 or 10.0.0.0/8).", "danger")
    elif AllowlistEntry.query.filter_by(cidr=cidr).first():
        flash(f"{cidr} is already on the allowlist.", "warning")
    else:
        db.session.add(AllowlistEntry(cidr=cidr, note=note, created_by=current_user.username))
        audit("allowlist_add", cidr)
        db.session.commit()
        flash(f"{cidr} added to the allowlist.", "success")
    return redirect(url_for("admin.rules") + "#allowlist")


@bp.route("/allowlist/<int:entry_id>/delete", methods=["POST"])
@admin_required
def allowlist_delete(entry_id):
    entry = db.session.get(AllowlistEntry, entry_id) or abort(404)
    audit("allowlist_remove", entry.cidr)
    db.session.delete(entry)
    db.session.commit()
    flash(f"{entry.cidr} removed from the allowlist.", "success")
    return redirect(url_for("admin.rules") + "#allowlist")


# --------------------------------------------------------------------------
# settings
# --------------------------------------------------------------------------
@bp.route("/settings", methods=["GET", "POST"])
@admin_required
def settings():
    """The Settings page has four separate forms. A hidden "section" field
    says which one was submitted, so only that group of settings is saved."""
    if request.method == "POST":
        section = request.form.get("section")
        if section == "notifications":
            sev = request.form.get("notify_min_severity")
            cooldown = _int_in(request.form.get("notify_cooldown_minutes"), 0, 1440)
            if sev not in SEVERITIES or cooldown is None:
                flash("Invalid severity or cooldown (0-1440 minutes).", "danger")
                return redirect(url_for("admin.settings"))
            set_setting("telegram_enabled", bool(request.form.get("telegram_enabled")))
            set_setting("email_enabled", bool(request.form.get("email_enabled")))
            set_setting("notify_min_severity", sev)
            set_setting("notify_cooldown_minutes", cooldown)
        elif section == "alerts":
            merge = _int_in(request.form.get("alert_merge_minutes"), 0, 1440)
            if merge is None:
                flash("Merge window must be 0-1440 minutes.", "danger")
                return redirect(url_for("admin.settings"))
            set_setting("alert_merge_minutes", merge)
        elif section == "noise":
            ports = [p.strip() for p in request.form.get("noise_ports", "").split(",") if p.strip()]
            if any(_int_in(p, 1, 65535) is None for p in ports):
                flash("Noise ports must be a comma-separated list of port numbers.", "danger")
                return redirect(url_for("admin.settings"))
            set_setting("noise_ports", ",".join(ports))
            set_setting("drop_broadcast", bool(request.form.get("drop_broadcast")))
            set_setting("drop_multicast", bool(request.form.get("drop_multicast")))
        elif section == "auth":
            apath = request.form.get("auth_log_path", "").strip()
            if not apath:
                flash("Auth log path is required.", "danger")
                return redirect(url_for("admin.settings"))
            set_setting("auth_monitor_enabled", bool(request.form.get("auth_monitor_enabled")))
            set_setting("auth_log_path", apath)
        elif section == "ollama":
            url = request.form.get("ollama_url", "").strip()
            if not url.startswith(("http://", "https://")):
                flash("Ollama URL must start with http:// or https://", "danger")
                return redirect(url_for("admin.settings"))
            set_setting("ollama_url", url.rstrip("/"))
            set_setting("ollama_model", request.form.get("ollama_model", "").strip()[:100])
        else:
            abort(400)
        audit("settings_updated", section)
        db.session.commit()
        flash("Settings saved.", "success")
        return redirect(url_for("admin.settings") + f"#{section}")

    # GET: show current values, whether .env has the credentials for each
    # channel, and which Ollama models are installed (if Ollama is running).
    s = all_settings()
    ollama_models, ollama_error = [], None
    try:
        ollama_models = list_models(s["ollama_url"])
    except SummaryError as exc:
        ollama_error = str(exc)
    return render_template("settings.html", s=s, severities=SEVERITIES,
                           telegram_configured=TelegramChannel().is_configured(),
                           email_configured=EmailChannel().is_configured(),
                           ollama_models=ollama_models, ollama_error=ollama_error)


@bp.route("/settings/test/<channel>", methods=["POST"])
@admin_required
def settings_test(channel):
    """Send a test message right now and show whether it worked."""
    if channel not in ("telegram", "email"):
        abort(404)
    error = send_test(channel)
    audit("notification_test", f"{channel}: {'ok' if not error else error}")
    db.session.commit()
    if error:
        flash(f"Test via {channel} failed: {error}", "danger")
    else:
        flash(f"Test notification sent via {channel}.", "success")
    return redirect(url_for("admin.settings") + "#notifications")


# --------------------------------------------------------------------------
# users
# --------------------------------------------------------------------------
@bp.route("/users", methods=["GET", "POST"])
@admin_required
def users():
    """List users; POST creates a new one."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role")
        # Usernames: letters, digits, "." and "_" only.
        if not username or len(username) > 64 or not username.replace("_", "").replace(".", "").isalnum():
            flash("Username must be 1-64 letters, digits, '.' or '_'.", "danger")
        elif role not in ROLES:
            flash("Invalid role.", "danger")
        elif User.query.filter_by(username=username).first():
            flash("That username already exists.", "danger")
        elif problem := password_problem(password):
            flash(problem, "danger")
        else:
            user = User(username=username, role=role)
            user.set_password(password)
            db.session.add(user)
            audit("user_created", f"{username} ({role})")
            db.session.commit()
            flash(f"User {username} created.", "success")
        return redirect(url_for("admin.users"))
    return render_template("users.html", users=User.query.order_by(User.username).all(), roles=ROLES)


@bp.route("/users/<int:user_id>", methods=["POST"])
@admin_required
def user_update(user_id):
    """Change a role, enable/disable, reset the password, or delete a user."""
    user = db.session.get(User, user_id) or abort(404)
    action = request.form.get("action")
    # An admin cannot lock themselves out by accident.
    if user.id == current_user.id and action in ("role", "disable", "delete"):
        flash("You cannot change your own role, disable or delete your own account.", "warning")
        return redirect(url_for("admin.users"))
    if action == "role":
        role = request.form.get("role")
        if role in ROLES:
            user.role = role
            audit("user_role", f"{user.username} -> {role}")
    elif action == "disable":
        # The same button toggles: disable an active user, enable a disabled one.
        user.active = not user.active
        audit("user_active", f"{user.username} active={user.active}")
    elif action == "password":
        password = request.form.get("password", "")
        if problem := password_problem(password):
            flash(problem, "danger")
            return redirect(url_for("admin.users"))
        user.set_password(password)
        audit("user_password_reset", user.username)
    elif action == "delete":
        audit("user_deleted", user.username)
        db.session.delete(user)
    else:
        abort(400)
    # Safety net: undo the change if it would leave no active admin at all.
    if User.query.filter_by(role="admin", active=True).count() == 0:
        db.session.rollback()
        flash("At least one active admin account must remain.", "danger")
        return redirect(url_for("admin.users"))
    db.session.commit()
    flash("User updated.", "success")
    return redirect(url_for("admin.users"))


@bp.route("/audit")
@admin_required
def audit_log():
    """The audit trail, newest first, 50 per page."""
    page = request.args.get("page", 1, type=int)
    pagination = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(page=page, per_page=50,
                                                                             error_out=False)
    return render_template("audit.html", pagination=pagination)
