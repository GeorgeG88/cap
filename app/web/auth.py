"""Login, logout and the user's own account page.

Security measures in this file:
  * passwords are checked against a hash (see models.User)
  * repeated failures lock the username+IP pair (see security.LoginThrottle)
  * the same message is shown for an unknown user and a wrong password,
    so the login page cannot be used to find out which usernames exist
  * every login, failure and logout is written to the audit log
  * after login the user is only redirected to pages on this site
"""

from datetime import datetime
from urllib.parse import urlparse

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from ..extensions import db
from ..models import User, audit

# A Blueprint is a group of related pages that is registered on the app.
bp = Blueprint("auth", __name__)

MIN_PASSWORD = 10


def password_problem(password: str) -> str | None:
    """Return what is wrong with a new password, or None if it is acceptable.

    Rules: at least 10 characters, and not only letters or only digits.
    Also used by manage.py and the Users page.
    """
    if len(password) < MIN_PASSWORD:
        return f"Password must be at least {MIN_PASSWORD} characters."
    if password.isalpha() or password.isdigit():
        return "Password must mix letters with digits or symbols."
    return None


def _safe_next(target: str | None) -> str:
    """Only allow relative redirects (prevents open redirects after login).

    The login URL can carry ?next=/alerts/5 so the user returns to the page
    they wanted. Without this check, an attacker could send someone a link
    such as /login?next=https://evil.example and use our login page to
    forward the victim to a fake site. Only paths on this site are accepted.
    """
    if target:
        parsed = urlparse(target)
        # "//evil.example" is also rejected: browsers treat it as another site.
        if not parsed.scheme and not parsed.netloc and target.startswith("/") and not target.startswith("//"):
            return target
    return url_for("dashboard.index")


@bp.route("/login", methods=["GET", "POST"])
def login():
    """GET shows the form; POST checks the username and password."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))
    throttle = current_app.extensions["login_throttle"]
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip = request.remote_addr

        # Locked out? Refuse without even checking the password.
        # 429 is the HTTP status for "too many requests".
        remaining = throttle.locked_for(username, ip)
        if remaining:
            flash(f"Too many failed attempts. Try again in {remaining // 60 + 1} minute(s).", "danger")
            return render_template("login.html"), 429

        user = User.query.filter_by(username=username).first()
        if user and user.active and user.check_password(password):
            # Success: clear the failure counter, start the session, record it.
            throttle.success(username, ip)
            login_user(user)
            user.last_login = datetime.now()
            audit("login", "successful login", username=user.username)
            db.session.commit()
            return redirect(_safe_next(request.args.get("next")))

        # Failure: count it and record it. The username is shortened because
        # it is attacker-controlled input.
        locked = throttle.fail(username, ip)
        audit("login_failed", f"failed login for '{username[:64]}'" + (" - locked out" if locked else ""),
              username=username[:64] or None)
        db.session.commit()
        flash("Invalid username or password.", "danger")
    return render_template("login.html")


# Logout is POST only (a button in a form with a CSRF token), so another
# website cannot log the user out with a simple link or image.
@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    audit("logout")
    db.session.commit()
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


@bp.route("/account", methods=["GET", "POST"])
@login_required
def account():
    """Change your own password. The current password is required, so someone
    using an unattended logged-in browser cannot take over the account."""
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        if not current_user.check_password(current):
            flash("Current password is incorrect.", "danger")
        elif new != confirm:
            flash("New passwords do not match.", "danger")
        elif problem := password_problem(new):
            flash(problem, "danger")
        else:
            current_user.set_password(new)
            audit("password_changed")
            db.session.commit()
            flash("Password updated.", "success")
            return redirect(url_for("auth.account"))
    return render_template("account.html")
