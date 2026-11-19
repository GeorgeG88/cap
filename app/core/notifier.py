"""Notification channels (Telegram, email) and the background delivery queue.

Design rules:
* Every channel implements the same ``send(subject, text)`` interface, so
  adding Slack or Discord later is one new class.
* Delivery happens on a background worker with retries, so a slow or failing
  channel never blocks parsing or detection.
* Secrets (bot token, SMTP password) come from environment variables / the
  .env file, never from the database or the source code.

Flow of one notification
  AlertManager decides an alert should be sent
    -> Notifier.enqueue(alert, ["telegram", "email"])   (returns immediately)
    -> worker thread picks it up from the queue
    -> deliver(): format the message, try each channel, retry on failure
    -> record(): the result (sent/failed) is saved and shown on the alert page
"""

from __future__ import annotations

import logging
import os
import queue
import smtplib
import ssl
import threading
import time
from email.message import EmailMessage

import requests

log = logging.getLogger(__name__)

# Coloured circles at the start of the message, so severity is visible at a glance on a phone.
SEVERITY_ICON = {"low": "🔵", "medium": "🟡", "high": "🟠", "critical": "🔴"}


class NotificationError(Exception):
    """Raised by a channel when a message could not be delivered."""
    pass


class Channel:
    """Interface every notification channel follows."""

    name = "base"

    def is_configured(self) -> bool:
        """True if the required settings are present in .env."""
        raise NotImplementedError

    def send(self, subject: str, text: str) -> None:
        """Deliver one message, or raise NotificationError."""
        raise NotImplementedError


class TelegramChannel(Channel):
    """Sends messages through a Telegram bot using the Bot API over HTTPS."""

    name = "telegram"
    API = "https://api.telegram.org/bot{token}/sendMessage"

    def __init__(self, token: str | None = None, chat_id: str | None = None, timeout: int = 10):
        # The token identifies the bot; the chat id says which chat (you) receives the message.
        self.token = token if token is not None else os.getenv("TELEGRAM_BOT_TOKEN", "")
        self.chat_id = chat_id if chat_id is not None else os.getenv("TELEGRAM_CHAT_ID", "")
        self.timeout = timeout

    def is_configured(self) -> bool:
        return bool(self.token and self.chat_id)

    def send(self, subject: str, text: str) -> None:
        if not self.is_configured():
            raise NotificationError("TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID missing in .env")
        try:
            # A timeout makes sure a network problem cannot hang the worker forever.
            resp = requests.post(self.API.format(token=self.token),
                                 json={"chat_id": self.chat_id, "text": f"{subject}\n\n{text}",
                                       "disable_web_page_preview": True},
                                 timeout=self.timeout)
        except requests.RequestException as exc:
            # Only the error type is reported, because the full message would
            # contain the URL, and the URL contains the secret bot token.
            raise NotificationError(f"Telegram request failed: {exc.__class__.__name__}") from exc
        if resp.status_code != 200:
            # Telegram explains errors in a "description" field (e.g. "chat not found").
            try:
                desc = resp.json().get("description", "")
            except ValueError:
                desc = resp.text[:200]
            raise NotificationError(f"Telegram API error {resp.status_code}: {desc}")


class EmailChannel(Channel):
    """Sends email through an SMTP server (for example Gmail with an app password)."""

    name = "email"

    def __init__(self, timeout: int = 15):
        self.host = os.getenv("SMTP_HOST", "")
        self.port = int(os.getenv("SMTP_PORT", "587") or 587)
        self.user = os.getenv("SMTP_USER", "")
        self.password = os.getenv("SMTP_PASSWORD", "")
        self.sender = os.getenv("SMTP_FROM", "") or self.user
        # ALERT_EMAIL_TO may list several addresses separated by commas.
        self.recipients = [r.strip() for r in os.getenv("ALERT_EMAIL_TO", "").split(",") if r.strip()]
        # Port 465 uses encryption from the first byte (SMTPS). Other ports,
        # normally 587, start unencrypted and switch with STARTTLS.
        self.use_ssl = self.port == 465
        self.timeout = timeout

    def is_configured(self) -> bool:
        return bool(self.host and self.sender and self.recipients)

    def send(self, subject: str, text: str) -> None:
        if not self.is_configured():
            raise NotificationError("SMTP_HOST, SMTP_FROM/SMTP_USER or ALERT_EMAIL_TO missing in .env")
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self.sender
        msg["To"] = ", ".join(self.recipients)
        msg.set_content(text)
        # The default context verifies the server's certificate, so the
        # password is never sent to an impostor server.
        ctx = ssl.create_default_context()
        try:
            if self.use_ssl:
                with smtplib.SMTP_SSL(self.host, self.port, timeout=self.timeout, context=ctx) as s:
                    if self.user:
                        s.login(self.user, self.password)
                    s.send_message(msg)
            else:
                with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as s:
                    s.starttls(context=ctx)    # encrypt before logging in
                    if self.user:
                        s.login(self.user, self.password)
                    s.send_message(msg)
        except (smtplib.SMTPException, OSError) as exc:
            raise NotificationError(f"SMTP error: {exc}") from exc


def build_channel(name: str) -> Channel:
    """Create a channel object by name. A new channel type only needs a line here."""
    if name == "telegram":
        return TelegramChannel()
    if name == "email":
        return EmailChannel()
    raise ValueError(name)


def format_alert(alert: dict, base_url: str = "") -> tuple:
    """Build (subject, text) for an alert dict.

    The same text is used for Telegram and email. Example subject:
    "🟠 [HIGH] Port scan from 192.168.56.20"
    """
    sev = alert["severity"]
    icon = SEVERITY_ICON.get(sev, "")
    escalated = " (escalated)" if alert.get("escalated") else ""
    subject = f"{icon} [{sev.upper()}] {alert['rule_name']}{escalated} from {alert['src_ip']}"
    details = alert.get("details") or {}
    lines = [
        details.get("summary", ""),
        f"Source: {alert['src_ip']}",
        f"First seen: {alert['first_seen']}",
        f"Last seen: {alert['last_seen']}",
        f"Rule: {alert['rule_name']} (threshold {alert.get('threshold')} in {alert.get('window_seconds')}s)",
    ]
    # Optional lines, only for rules that collect this information.
    if details.get("scan_type"):
        lines.append(f"Type: {details['scan_type']}")
    if details.get("services"):
        lines.append("Services: " + ", ".join(details["services"]))
    if details.get("targets"):
        lines.append("Targets: " + ", ".join(details["targets"][:5]))
    lines.append(f"Alert #{alert['id']} - Firewall Log Analyzer")
    # A direct link to the alert page, if BASE_URL is set in .env.
    if base_url:
        lines.append(f"{base_url.rstrip('/')}/alerts/{alert['id']}")
    return subject, "\n".join(l for l in lines if l)   # skip empty lines


class Notifier:
    """Background delivery queue with retries.

    ``record`` is a callback ``record(alert_id, channel, status, attempts, error)``
    used to persist delivery results (the web app writes them to the DB).

    ``channel_factory`` builds channel objects; tests replace it with a fake
    channel so no real messages are sent.
    """

    # Seconds to wait before the 2nd and 3rd attempt (3 attempts in total).
    RETRY_DELAYS = (2, 5)

    def __init__(self, record=None, channel_factory=build_channel, base_url: str = ""):
        self.record = record
        self.channel_factory = channel_factory
        self.base_url = base_url
        # A thread-safe queue: analysis threads put work in, the worker takes it out.
        self.queue: queue.Queue = queue.Queue()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def _ensure_worker(self):
        """Start the worker thread the first time it is needed (or again if it stopped)."""
        with self._lock:
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._run, name="notifier", daemon=True)
                self._thread.start()

    def enqueue(self, alert: dict, channels: list) -> None:
        """Hand an alert over for delivery. Returns immediately."""
        if not channels:
            return
        self._ensure_worker()
        self.queue.put((alert, list(channels)))

    def _run(self):
        """Worker loop: wait for an item, deliver it, repeat forever."""
        while True:
            alert, channels = self.queue.get()   # blocks until something arrives
            try:
                self.deliver(alert, channels)
            except Exception:  # never let the worker die
                log.exception("notification delivery crashed")
            finally:
                self.queue.task_done()

    def deliver(self, alert: dict, channels: list, delays=None) -> list:
        """Deliver synchronously; returns list of (channel, status, error)."""
        delays = self.RETRY_DELAYS if delays is None else delays
        subject, text = format_alert(alert, self.base_url)
        results = []
        for name in channels:
            channel = self.channel_factory(name)
            attempts, error, status = 0, None, "failed"
            # Try once, then once more after each delay.
            for attempt in range(len(delays) + 1):
                attempts = attempt + 1
                try:
                    channel.send(subject, text)
                    status, error = "sent", None
                    break
                except NotificationError as exc:
                    error = str(exc)
                    if "missing" in error:  # configuration problem: retrying won't help
                        break
                    if attempt < len(delays):
                        time.sleep(delays[attempt])
            results.append((name, status, error))
            if status != "sent":
                log.warning("notification via %s failed: %s", name, error)
            # Save the outcome so the alert page can show "sent" or "failed".
            if self.record:
                try:
                    self.record(alert["id"], name, status, attempts, error)
                except Exception:
                    log.exception("could not record notification result")
        return results

    def wait_idle(self, timeout: float = 10.0) -> None:
        """Used by tests: wait until the queue is empty."""
        end = time.time() + timeout
        while self.queue.unfinished_tasks and time.time() < end:
            time.sleep(0.05)


def send_test(channel_name: str) -> str | None:
    """Send a test message; returns an error string or None on success.

    Used by the "Send test" buttons on the Settings page. It runs directly
    (not through the queue) so the result can be shown to the admin at once.
    """
    try:
        build_channel(channel_name).send(
            "✅ Firewall Log Analyzer test notification",
            "If you can read this, alert notifications for this channel are working.")
        return None
    except NotificationError as exc:
        return str(exc)
