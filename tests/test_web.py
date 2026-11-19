"""Tests for the web application, using Flask's test client (no real browser).

Covers access control, login lockout, security headers, the upload flow
end to end, escaping of hostile log content, live monitoring with log
rotation, and the report downloads.
"""
import io
import time

import pytest

from app.extensions import db
from app.models import Alert, AnalysisRun, AuditLog, Event


# One UFW log line for a blocked TCP SYN, in classic syslog format.
def blocked_line(sec, src, dpt, spt=50000):
    return (f"Oct 19 14:00:{sec:02d} fw kernel: [UFW BLOCK] IN=enp0s8 OUT= SRC={src} "
            f"DST=192.168.56.10 LEN=44 TOS=0x00 PREC=0x00 TTL=50 ID=1 PROTO=TCP SPT={spt} DPT={dpt} "
            f"WINDOW=1024 RES=0x00 SYN URGP=0")


# Uploads are analysed in a background thread; wait until the run has finished.
def wait_for_run(app, run_id, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        with app.app_context():
            run = db.session.get(AnalysisRun, run_id)
            if run.status in ("done", "failed"):
                return run
        time.sleep(0.05)
    raise AssertionError("analysis did not finish")


# Pages redirect to the login page when nobody is logged in.
def test_login_required(app):
    c = app.test_client()
    r = c.get("/")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


# After 5 wrong passwords even the right password is refused (HTTP 429),
# and all 5 failures are in the audit log.
def test_failed_logins_lock_out_and_are_audited(app):
    from conftest import make_user
    make_user(app)
    c = app.test_client()
    for _ in range(5):
        c.post("/login", data={"username": "admin", "password": "wrong"})
    r = c.post("/login", data={"username": "admin", "password": "CorrectHorse9"})
    assert r.status_code == 429
    with app.app_context():
        assert AuditLog.query.filter_by(action="login_failed").count() == 5


# ?next= pointing to another website is ignored after login.
def test_open_redirect_blocked(app):
    from conftest import make_user
    make_user(app)
    c = app.test_client()
    r = c.post("/login?next=https://evil.example/", data={"username": "admin", "password": "CorrectHorse9"})
    assert r.headers["Location"] == "/"


# Every page carries the Content-Security-Policy and anti-framing headers.
def test_security_headers(admin_client):
    r = admin_client.get("/")
    assert "script-src 'self'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Frame-Options"] == "DENY"


# Smoke test: every page loads without an error for an admin.
def test_all_pages_render(admin_client):
    for url in ("/", "/alerts/", "/events/", "/upload", "/runs", "/monitor", "/rules", "/settings",
                "/users", "/audit", "/reports/", "/account", "/api/stats"):
        assert admin_client.get(url).status_code == 200, url


# Analysts can view rules but cannot open admin pages or change anything.
def test_analyst_cannot_use_admin_pages(analyst_client):
    assert analyst_client.get("/rules").status_code == 200          # read-only view is fine
    for url in ("/settings", "/users", "/audit"):
        assert analyst_client.get(url).status_code == 403, url
    assert analyst_client.post("/rules/port_scan", data={"threshold": 1}).status_code == 403
    assert analyst_client.post("/monitor", data={"action": "start"}).status_code == 403


# Upload a small log with a scan, a hostile line and an unrelated line.
# Checks the counters, that an alert was created, and that the <script>
# text never appears unescaped in the page.
def test_upload_end_to_end_creates_alert_and_escapes_html(app, admin_client):
    lines = [blocked_line(i, "192.168.56.20", 1000 + i) for i in range(30)]
    lines.append("Oct 19 14:00:59 fw kernel: [UFW BLOCK] <script>alert(1)</script> SRC=1.1.1.1")  # malformed
    lines.append("Oct 19 14:00:59 fw CRON[1]: (root) CMD (true)")                                  # not UFW
    data = {"logfile": (io.BytesIO("\n".join(lines).encode()), "ufw.log")}
    r = admin_client.post("/upload", data=data, content_type="multipart/form-data")
    assert r.status_code == 302
    run_id = int(r.headers["Location"].rstrip("/").split("/")[-1])
    run = wait_for_run(app, run_id)
    assert run.status == "done"
    assert (run.lines_total, run.lines_parsed, run.lines_malformed, run.lines_not_ufw) == (32, 30, 1, 1)
    with app.app_context():
        assert Event.query.count() == 30
        alerts = {a.rule_id for a in Alert.query.all()}
    assert "port_scan" in alerts
    page = admin_client.get(f"/runs/{run_id}").get_data(as_text=True)
    assert "Port scan" in page and "<script>alert(1)</script>" not in page


# Traffic from an allowlisted network is stored but never alerts.
def test_allowlisted_source_raises_no_alert(app, admin_client):
    admin_client.post("/allowlist", data={"cidr": "192.168.56.0/24", "note": "lab"})
    lines = [blocked_line(i, "192.168.56.20", 1000 + i) for i in range(30)]
    r = admin_client.post("/upload", data={"logfile": (io.BytesIO("\n".join(lines).encode()), "a.log")},
                          content_type="multipart/form-data")
    run = wait_for_run(app, int(r.headers["Location"].split("/")[-1]))
    assert run.events_allowlisted == 30 and run.alerts_created == 0


# An invalid threshold is rejected; valid values are saved.
def test_rule_update_validation(admin_client, app):
    r = admin_client.post("/rules/port_scan", data={"threshold": "0", "window_seconds": "60", "severity": "high"})
    assert r.status_code == 302
    admin_client.post("/rules/port_scan", data={"threshold": "50", "window_seconds": "30",
                                                "severity": "critical", "enabled": "1"})
    from app.models import Rule
    with app.app_context():
        rule = db.session.get(Rule, "port_scan")
        assert (rule.threshold, rule.window_seconds, rule.severity) == (50, 30, "critical")


# Start live monitoring on a temporary file, append lines, then replace the
# file (as logrotate does) and check that both old and new lines are read once.
@pytest.fixture
def live_env(tmp_path):
    """An app backed by a file database (not the shared in-memory one), so the
    live-monitor threads each get their own SQLite connection, exactly as in
    production. Yields (app, logged-in admin client) and stops the monitor after."""
    from app import create_app
    from app.extensions import db
    from app.models import User
    from config import TestConfig

    class FileConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = "sqlite:///" + str(tmp_path / "live.db").replace("\\", "/")
        SQLALCHEMY_ENGINE_OPTIONS = {"connect_args": {"check_same_thread": False, "timeout": 30}}

    application = create_app(FileConfig)
    with application.app_context():
        u = User(username="admin", role="admin")
        u.set_password("CorrectHorse9")
        db.session.add(u)
        db.session.commit()
    client = application.test_client()
    client.post("/login", data={"username": "admin", "password": "CorrectHorse9"})
    try:
        yield application, client
    finally:
        try:
            application.extensions["monitor"].stop()
        except Exception:
            pass


def _set_auth_monitor(app, enabled, path=""):
    from app.extensions import db
    from app.models import set_setting
    with app.app_context():
        set_setting("auth_monitor_enabled", enabled)
        if path:
            set_setting("auth_log_path", path)
        db.session.commit()


def test_live_monitor_tails_new_lines_and_survives_rotation(live_env, tmp_path):
    app, client = live_env
    _set_auth_monitor(app, False)       # this test covers the firewall tail only
    log = tmp_path / "ufw.log"
    log.write_text(blocked_line(0, "10.1.1.1", 22) + "\n")          # existing line, skipped
    r = client.post("/monitor", data={"action": "start", "path": str(log)})
    assert r.status_code == 302
    monitor = app.extensions["monitor"]
    assert monitor.running

    def wait(cond, timeout=8):
        end = time.time() + timeout
        while time.time() < end:
            if cond():
                return True
            time.sleep(0.1)
        return False

    with open(log, "a") as fh:
        fh.write("\n".join(blocked_line(i, "10.2.2.2", 2000 + i) for i in range(25)) + "\n")
    assert wait(lambda: monitor.lines_read == 25), monitor.status()
    log.unlink()                                                       # simulate logrotate
    log.write_text(blocked_line(30, "10.3.3.3", 80) + "\n")
    assert wait(lambda: monitor.lines_read == 26)
    client.post("/monitor", data={"action": "stop"})
    assert not monitor.running
    with app.app_context():
        assert Event.query.count() == 26
        assert Alert.query.filter_by(rule_id="port_scan", src_ip="10.2.2.2").count() == 1


def _failed_ssh(i, ip="192.168.56.1"):
    return f"Nov 16 02:00:{i:02d} kali sshd[1]: Failed password for testuser from {ip} port {5000+i} ssh2"


def test_live_monitor_detects_ssh_bruteforce_from_auth_log(live_env, tmp_path):
    app, client = live_env
    ufw = tmp_path / "ufw.log"
    ufw.write_text(blocked_line(0, "10.1.1.1", 22) + "\n")
    auth = tmp_path / "auth.log"
    auth.write_text("Nov 16 01:59:00 kali sshd[1]: Server listening on 0.0.0.0 port 22.\n")
    _set_auth_monitor(app, True, str(auth))
    r = client.post("/monitor", data={"action": "start", "path": str(ufw)})
    assert r.status_code == 302
    monitor = app.extensions["monitor"]
    assert monitor.status()["auth_running"]

    def wait(cond, timeout=8):
        end = time.time() + timeout
        while time.time() < end:
            if cond():
                return True
            time.sleep(0.1)
        return False

    with open(auth, "a") as fh:                        # 8 failed logins, threshold is 5
        fh.write("\n".join(_failed_ssh(i) for i in range(1, 9)) + "\n")

    def has_alert():
        with app.app_context():
            return Alert.query.filter_by(rule_id="ssh_auth_bruteforce", src_ip="192.168.56.1").count() == 1
    assert wait(has_alert), monitor.status()
    client.post("/monitor", data={"action": "stop"})
    with app.app_context():
        assert Event.query.count() == 0                # auth events are NOT stored as firewall events


# The PDF download is a real PDF file and the CSV export works.
def test_reports_pdf_and_csv(admin_client):
    r = admin_client.get("/reports/pdf")
    assert r.status_code == 200 and r.data[:4] == b"%PDF"
    assert admin_client.get("/reports/alerts.csv").status_code == 200
