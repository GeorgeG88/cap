"""Alert generation: turns detection updates into stored alerts.

Responsibilities
* **Deduplication / merging** - updates for the same detection episode
  update one alert; a new episode from the same source for the same rule is
  merged into the still-open alert if it starts within the merge window.
* **Severity escalation** - when the observed count reaches twice the rule
  threshold, the alert is raised one severity level (and notified again).
* **Notification policy** - only alerts at or above the minimum severity are
  sent, and the same rule+source is notified at most once per cooldown.

Decision steps for each Detection (see AlertManager.apply)
1. Has this exact episode already produced an alert in this analysis?
   -> update that alert.
2. Otherwise, is there an open (not resolved) alert for the same rule and
   source that ended no longer than the merge window ago?
   -> merge into it and increase its "occurrences" counter.
3. Otherwise -> create a new alert and consider notifying.
In every case the severity is raised if the count reached twice the threshold.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Iterable

from ..extensions import db
from ..models import Alert
from .detection import SEVERITIES, Detection

# Severity name -> position (low=0 ... critical=3), so severities can be compared.
SEV_INDEX = {s: i for i, s in enumerate(SEVERITIES)}


def escalate(severity: str) -> str:
    """One level higher (medium -> high, high -> critical). Critical stays critical."""
    return SEVERITIES[min(SEV_INDEX.get(severity, 1) + 1, len(SEVERITIES) - 1)]


def alert_to_dict(alert: Alert, escalated: bool = False) -> dict:
    """Copy the fields a notification needs into a plain dictionary.

    The notifier runs in another thread, and database objects should not be
    shared between threads, so it receives this copy instead.
    """
    return {
        "id": alert.id, "rule_id": alert.rule_id, "rule_name": alert.rule_name,
        "severity": alert.severity, "src_ip": alert.src_ip,
        "first_seen": alert.first_seen.strftime("%Y-%m-%d %H:%M:%S"),
        "last_seen": alert.last_seen.strftime("%Y-%m-%d %H:%M:%S"),
        "event_count": alert.event_count, "threshold": alert.threshold,
        "window_seconds": alert.window_seconds, "details": alert.details or {},
        "escalated": escalated,
    }


class AlertManager:
    """Creates and updates alerts for one analysis run."""

    def __init__(self, run_id: int | None, settings: dict, notifier=None, notify: bool = False):
        self.run_id = run_id
        self.settings = settings        # values from the Settings page
        self.notifier = notifier        # background sender (Telegram / email)
        self.notify = notify            # False for uploads unless the user asked for notifications
        self.alert_ids: dict = {}            # detection episode key -> alert id
        self.created = 0
        self.updated = 0
        # Notifications waiting to be sent. They are only sent after the
        # database commit, so a message never refers to an alert that was
        # not saved.
        self._outbox: list = []

    # -- notification policy ---------------------------------------------
    def channels(self) -> list:
        """The notification channels switched on in Settings."""
        out = []
        if self.settings.get("telegram_enabled"):
            out.append("telegram")
        if self.settings.get("email_enabled"):
            out.append("email")
        return out

    def _maybe_notify(self, alert: Alert, escalated: bool) -> None:
        """Queue a notification if the policy allows it. Checks, in order:
        notifications wanted for this run, at least one channel on, severity
        high enough, and (unless escalated) not inside the cooldown period."""
        if not (self.notify and self.notifier):
            return
        channels = self.channels()
        if not channels:
            return
        min_sev = self.settings.get("notify_min_severity", "high")
        if SEV_INDEX.get(alert.severity, 0) < SEV_INDEX.get(min_sev, 2):
            return
        now = datetime.now()
        if not escalated:
            # Cooldown: find when this rule last notified about this source
            # (across all alerts, including resolved ones). If that was less
            # than the cooldown ago, stay quiet. This prevents a long or
            # repeated attack from sending a message every few minutes.
            cooldown = timedelta(minutes=int(self.settings.get("notify_cooldown_minutes", 15)))
            last = (db.session.query(db.func.max(Alert.notified_at))
                    .filter(Alert.rule_id == alert.rule_id, Alert.src_ip == alert.src_ip).scalar())
            if last and now - last < cooldown:
                return
        alert.notified_at = now
        self._outbox.append((alert, escalated, channels))

    def _incident_for(self, d: Detection) -> int | None:
        """Reuse the incident of a recent alert from the same source (any rule),
        so one attack that trips several rules becomes one incident. Returns None
        to start a new incident (the caller then uses the new alert's own id)."""
        window = timedelta(minutes=int(self.settings.get("incident_window_minutes", 5)))
        prior = (Alert.query
                 .filter(Alert.src_ip == d.src_ip, Alert.incident_id.isnot(None),
                         Alert.last_seen >= d.first_seen - window)
                 .order_by(Alert.last_seen.desc()).first())
        return prior.incident_id if prior else None

    # -- main entry point --------------------------------------------------
    def apply(self, detections: Iterable[Detection]) -> None:
        """Create or update alerts for a batch of detections (see the steps at the top)."""
        merge = timedelta(minutes=int(self.settings.get("alert_merge_minutes", 10)))
        for d in detections:
            # Severity this detection deserves: one level up at 2x the threshold.
            target_sev = escalate(d.severity) if d.count >= 2 * max(d.threshold, 1) else d.severity

            # Step 1: an alert already exists for this exact episode.
            alert = None
            alert_id = self.alert_ids.get(d.key)
            if alert_id is not None:
                alert = db.session.get(Alert, alert_id)

            # Step 2: look for an open alert to merge into.
            if alert is None:
                alert = (Alert.query
                         .filter(Alert.rule_id == d.rule_id, Alert.src_ip == d.src_ip,
                                 Alert.status != "resolved",
                                 Alert.last_seen >= d.first_seen - merge)
                         .order_by(Alert.last_seen.desc()).first())
                if alert is not None:
                    alert.occurrences = (alert.occurrences or 1) + 1
                    db.session.flush()
                    self.alert_ids[d.key] = alert.id

            # Step 3: nothing to update or merge into, so create a new alert.
            if alert is None:
                alert = Alert(
                    run_id=self.run_id, rule_id=d.rule_id, rule_name=d.rule_name,
                    severity=target_sev, src_ip=d.src_ip, first_seen=d.first_seen,
                    last_seen=d.last_seen, event_count=d.count, threshold=d.threshold,
                    window_seconds=d.window_seconds, details=d.details, status="new", occurrences=1,
                )
                db.session.add(alert)
                db.session.flush()    # assigns the alert its id
                alert.incident_id = self._incident_for(d) or alert.id
                self.alert_ids[d.key] = alert.id
                self.created += 1
                self._maybe_notify(alert, escalated=False)
                continue

            # update existing alert
            # Widen the time span, keep the highest count, show the newest evidence.
            self.updated += 1
            alert.first_seen = min(alert.first_seen, d.first_seen)
            alert.last_seen = max(alert.last_seen, d.last_seen)
            alert.event_count = max(alert.event_count or 0, d.count)
            alert.details = d.details
            alert.updated_at = datetime.now()
            # Escalation only ever raises the severity, never lowers it.
            if SEV_INDEX[target_sev] > SEV_INDEX.get(alert.severity, 0):
                alert.severity = target_sev
                self._maybe_notify(alert, escalated=True)

    def commit_and_dispatch(self) -> None:
        """Commit and hand queued notifications to the background notifier."""
        db.session.commit()
        outbox, self._outbox = self._outbox, []
        for alert, escalated, channels in outbox:
            self.notifier.enqueue(alert_to_dict(alert, escalated), channels)
