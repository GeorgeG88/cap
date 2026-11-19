"""Tests for alert creation and notifications (app/core/alerting.py, notifier.py).

A fake notifier and fake channels are used, so no real Telegram or email
messages are sent while testing.
"""
from datetime import timedelta

from app.core.alerting import AlertManager
from app.core.detection import Detection
from app.core.notifier import NotificationError, Notifier
from app.models import Alert
from conftest import T0


# Build a Detection as the detection engine would produce it.
def det(count=25, episode=1, src="10.0.0.5", start=0, end=30, rule="port_scan", severity="high"):
    return Detection(rule_id=rule, rule_name="Port scan", severity=severity, src_ip=src,
                     first_seen=T0 + timedelta(seconds=start), last_seen=T0 + timedelta(seconds=end),
                     count=count, threshold=20, window_seconds=60, episode=episode,
                     details={"summary": f"{count} ports"})


# Stands in for the real notifier and just records what would have been sent.
class FakeNotifier:
    def __init__(self):
        self.sent = []

    def enqueue(self, alert, channels):
        self.sent.append((alert, channels))


SETTINGS = {"telegram_enabled": True, "email_enabled": False, "notify_min_severity": "high",
            "notify_cooldown_minutes": 15, "alert_merge_minutes": 10}


# Two updates of the same episode must give one alert with the newer count.
def test_updates_to_same_episode_update_one_alert(db_session):
    m = AlertManager(None, SETTINGS)
    m.apply([det(25)])
    m.apply([det(30, end=40)])
    m.commit_and_dispatch()
    alerts = Alert.query.all()
    assert len(alerts) == 1 and alerts[0].event_count == 30 and m.created == 1


# A second episode soon after the first is merged into the open alert.
def test_new_episode_merges_into_open_alert(db_session):
    m = AlertManager(None, SETTINGS)
    m.apply([det(25, episode=1)])
    m.apply([det(22, episode=2, start=200, end=230)])
    m.commit_and_dispatch()
    a = Alert.query.one()
    assert a.occurrences == 2


# Once an analyst resolves an alert, new activity creates a new alert.
def test_resolved_alert_is_not_reused(db_session):
    m = AlertManager(None, SETTINGS)
    m.apply([det(25, episode=1)])
    m.commit_and_dispatch()
    Alert.query.one().status = "resolved"
    db_session.commit()
    m.apply([det(25, episode=2, start=200, end=230)])
    m.commit_and_dispatch()
    assert Alert.query.count() == 2


# Reaching 2x the threshold raises high -> critical and sends a second message.
def test_escalation_at_double_threshold_notifies_again(db_session):
    fake = FakeNotifier()
    m = AlertManager(None, SETTINGS, notifier=fake, notify=True)
    m.apply([det(25)])
    m.commit_and_dispatch()
    m.apply([det(45, end=50)])
    m.commit_and_dispatch()
    assert Alert.query.one().severity == "critical"
    assert len(fake.sent) == 2 and fake.sent[1][0]["escalated"] is True


# Medium alerts are not sent (minimum is high), and a repeat within the
# cooldown period is not sent either. Only one message is expected.
def test_cooldown_and_min_severity(db_session):
    fake = FakeNotifier()
    m = AlertManager(None, SETTINGS, notifier=fake, notify=True)
    m.apply([det(25, src="10.0.0.7", rule="denied_burst", severity="medium")])  # below min severity
    m.apply([det(25, src="10.0.0.8")])
    m.commit_and_dispatch()
    Alert.query.filter_by(src_ip="10.0.0.8").one().status = "resolved"
    db_session.commit()
    m.apply([det(25, src="10.0.0.8", episode=9, start=900, end=930)])  # new alert, but in cooldown
    m.commit_and_dispatch()
    assert [a["src_ip"] for a, _ in fake.sent] == ["10.0.0.8"]


# Uploads have notifications off unless the user ticks the box.
def test_alerts_from_same_source_share_one_incident(db_session):
    m = AlertManager(None, SETTINGS)
    # One attack trips two rules from the same source: one incident, two alerts.
    m.apply([det(25, rule="port_scan"), det(25, rule="denied_burst", severity="medium")])
    m.commit_and_dispatch()
    alerts = Alert.query.all()
    assert len(alerts) == 2
    assert len({a.incident_id for a in alerts}) == 1
    # A different source is a different incident.
    m.apply([det(25, src="10.9.9.9", episode=5, start=1, end=30)])
    m.commit_and_dispatch()
    by_src = {a.src_ip: a.incident_id for a in Alert.query.all()}
    assert by_src["10.0.0.5"] != by_src["10.9.9.9"]


def test_upload_without_notify_sends_nothing(db_session):
    fake = FakeNotifier()
    m = AlertManager(None, SETTINGS, notifier=fake, notify=False)
    m.apply([det(25)])
    m.commit_and_dispatch()
    assert fake.sent == []


# -- notifier -----------------------------------------------------------------
# A channel that fails a set number of times before succeeding.
class FlakyChannel:
    def __init__(self, fail_times):
        self.fail_times = fail_times
        self.calls = 0

    def send(self, subject, text):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise NotificationError("temporary failure")


# One failure, then success on the second attempt.
def test_notifier_retries_then_succeeds():
    ch = FlakyChannel(fail_times=1)
    records = []
    n = Notifier(record=lambda *a: records.append(a), channel_factory=lambda name: ch)
    alert = {"id": 1, "rule_name": "Port scan", "severity": "high", "src_ip": "10.0.0.5",
             "first_seen": "x", "last_seen": "y", "details": {"summary": "s"}}
    result = n.deliver(alert, ["telegram"], delays=(0, 0))
    assert result == [("telegram", "sent", None)] and ch.calls == 2
    assert records[0][2] == "sent" and records[0][3] == 2


# Always failing: three attempts, then the failure is recorded.
def test_notifier_gives_up_and_records_failure():
    ch = FlakyChannel(fail_times=10)
    records = []
    n = Notifier(record=lambda *a: records.append(a), channel_factory=lambda name: ch)
    alert = {"id": 1, "rule_name": "R", "severity": "high", "src_ip": "x", "first_seen": "", "last_seen": ""}
    n.deliver(alert, ["email"], delays=(0, 0))
    assert records[0][2] == "failed" and ch.calls == 3
