"""Access control helpers, login throttling and HTTP security headers.

Since this is a security tool, the tool itself must not be an easy target.
This module holds three of its defences:
  admin_required     only admins can open configuration pages
  LoginThrottle      slows down password guessing against the login page
  security headers   tell the browser to block common web attacks
"""

from __future__ import annotations

import threading
import time
from functools import wraps

from flask import abort, current_app
from flask_login import current_user


def admin_required(view):
    """Decorator for pages that only admins may use.

    Not logged in -> sent to the login page. Logged in as analyst -> 403 error.
    Usage:  @admin_required  above a view function.
    """
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return current_app.login_manager.unauthorized()
        if not current_user.is_admin:
            abort(403)
        return view(*args, **kwargs)
    return wrapper


class LoginThrottle:
    """Locks a username+IP pair after repeated failed logins (in memory).

    After ``max_failures`` wrong passwords for the same username from the
    same IP within ``lockout_seconds``, further attempts are refused for
    ``lockout_seconds``, even with the right password. Using the pair
    (username, IP) means an attacker cannot lock the real admin out from a
    different machine.

    Data is kept in memory only, so a restart clears all lockouts.
    """

    def __init__(self, max_failures: int = 5, lockout_seconds: int = 600):
        self.max_failures = max_failures
        self.lockout_seconds = lockout_seconds
        # (username, ip) -> (failure count, time of first failure, locked until or 0)
        self._failures: dict = {}
        # The web server handles requests in several threads at once.
        self._lock = threading.Lock()

    def _key(self, username: str, ip: str) -> tuple:
        # Lower-case so "Admin" and "admin" share one counter.
        return ((username or "").lower(), ip or "")

    def locked_for(self, username: str, ip: str) -> int:
        """Seconds remaining in a lockout, or 0."""
        with self._lock:
            entry = self._failures.get(self._key(username, ip))
            if not entry:
                return 0
            count, first, locked_until = entry
            remaining = int(locked_until - time.time()) if locked_until else 0
            # Lockout has expired: forget the old failures.
            if remaining <= 0 and locked_until:
                del self._failures[self._key(username, ip)]
                return 0
            return max(remaining, 0)

    def fail(self, username: str, ip: str) -> bool:
        """Record a failure. Returns True if this failure triggered a lockout."""
        now = time.time()
        key = self._key(username, ip)
        with self._lock:
            count, first, locked_until = self._failures.get(key, (0, now, 0))
            # Failures older than the lockout period no longer count.
            if now - first > self.lockout_seconds:
                count, first = 0, now
            count += 1
            if count >= self.max_failures:
                self._failures[key] = (count, first, now + self.lockout_seconds)
                return True
            self._failures[key] = (count, first, 0)
            return False

    def success(self, username: str, ip: str) -> None:
        """A correct login clears the counter."""
        with self._lock:
            self._failures.pop(self._key(username, ip), None)


# Content-Security-Policy: the browser may only load scripts, styles and
# other resources from this application itself. Inline <script> blocks and
# style="" attributes are refused, so even if attacker-controlled log text
# got into a page as HTML, the browser would not run it. That is also why
# the templates contain no inline JavaScript and no inline styles.
CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
       "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")


def apply_security_headers(response):
    """Add security headers to every HTTP response.

      X-Content-Type-Options: nosniff   browser must trust the declared file type
      X-Frame-Options: DENY             page cannot be embedded in another site (clickjacking)
      Referrer-Policy: same-origin      URLs are not leaked to other sites
      Permissions-Policy                camera, microphone and location are disabled
      Cache-Control: no-store           pages with security data are not cached on disk
    setdefault() keeps any header a view has already set itself.
    """
    response.headers.setdefault("Content-Security-Policy", CSP)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if response.mimetype == "text/html":
        response.headers.setdefault("Cache-Control", "no-store")
    return response
