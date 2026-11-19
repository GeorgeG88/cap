"""Alert pages: the alert queue, one alert's details, and triage actions.

Triage workflow (like a SOC ticket queue):
  new -> acknowledged (someone is looking at it) -> resolved (dealt with)
An alert can be reopened (set back to new). Every change is audited.
"""

from datetime import datetime, timedelta

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from ..core.detection import SEVERITIES
from ..extensions import db
from ..models import ALERT_STATUSES, Alert, Event, Rule, audit

bp = Blueprint("alerts", __name__, url_prefix="/alerts")

PER_PAGE = 30


def filtered_alerts():
    """Build the alert query from the filter values in the URL.

    Unknown values are ignored rather than causing errors, and the filters
    use the ORM (never string-built SQL), so URL input cannot inject SQL.
    """
    q = Alert.query
    status = request.args.get("status", "open")
    if status == "open":
        q = q.filter(Alert.status.in_(["new", "acknowledged"]))   # default view: unresolved
    elif status in ALERT_STATUSES:
        q = q.filter(Alert.status == status)
    severity = request.args.get("severity", "")
    if severity in SEVERITIES:
        q = q.filter(Alert.severity == severity)
    rule = request.args.get("rule", "")
    if rule:
        q = q.filter(Alert.rule_id == rule)
    src = request.args.get("src", "").strip()
    if src:
        # Prefix match, so "192.168.56." finds the whole lab subnet.
        q = q.filter(Alert.src_ip.like(f"{src}%"))
    run = request.args.get("run", type=int)
    if run:
        q = q.filter(Alert.run_id == run)
    incident = request.args.get("incident", type=int)
    if incident:
        # Show one incident's alerts regardless of their status.
        q = Alert.query.filter(Alert.incident_id == incident)
    return q


@bp.route("/")
@login_required
def index():
    """The alert queue, most recent activity first."""
    page = request.args.get("page", 1, type=int)
    pagination = (filtered_alerts().order_by(Alert.last_seen.desc())
                  .paginate(page=page, per_page=PER_PAGE, error_out=False))
    rules = Rule.query.order_by(Rule.name).all()
    # Current filters, so the page links keep them.
    args = {k: v for k, v in request.args.items() if k != "page"}
    return render_template("alerts.html", pagination=pagination, rules=rules, severities=SEVERITIES,
                           statuses=ALERT_STATUSES, args=args)


@bp.route("/<int:alert_id>")
@login_required
def detail(alert_id):
    """One alert with its evidence, the events behind it, notes and notifications."""
    alert = db.session.get(Alert, alert_id) or abort(404)
    # Show the events from this source during the alert, plus one window
    # before and after, so the analyst sees what led up to it.
    window = timedelta(seconds=alert.window_seconds or 60)
    events_q = Event.query.filter(Event.timestamp >= alert.first_seen - window,
                                  Event.timestamp <= alert.last_seen + window)
    # "*" is the global traffic spike alert, which has no single source.
    if alert.src_ip != "*":
        events_q = events_q.filter(Event.src_ip == alert.src_ip)
    related_count = events_q.count()
    events = events_q.order_by(Event.timestamp).limit(100).all()
    # Other alerts from the same source help to see the bigger picture
    # (e.g. a port scan followed by a brute-force attempt).
    others = []
    if alert.src_ip != "*":
        others = (Alert.query.filter(Alert.src_ip == alert.src_ip, Alert.id != alert.id)
                  .order_by(Alert.last_seen.desc()).limit(10).all())
    return render_template("alert_detail.html", alert=alert, events=events, related_count=related_count,
                           others=others, notifications=alert.notifications.order_by("created_at").all())


@bp.route("/<int:alert_id>/status", methods=["POST"])
@login_required
def set_status(alert_id):
    """Change an alert's status and optionally add a note."""
    alert = db.session.get(Alert, alert_id) or abort(404)
    status = request.form.get("status")
    if status not in ALERT_STATUSES:
        abort(400)
    note = request.form.get("note", "").strip()
    old = alert.status
    alert.status = status
    alert.status_changed_by = current_user.username
    alert.status_changed_at = datetime.now()
    if note:
        # Notes are appended with time and author, never overwritten,
        # so the alert keeps a history of what was done.
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
        entry = f"[{stamp}] {current_user.username}: {note[:1000]}"
        alert.notes = (alert.notes + "\n" + entry) if alert.notes else entry
    audit("alert_status", f"alert #{alert.id}: {old} -> {status}")
    db.session.commit()
    flash(f"Alert #{alert.id} marked as {status}.", "success")
    # Go back to the page the request came from, but only if it is an alerts page.
    return redirect(request.form.get("back") if request.form.get("back", "").startswith("/alerts")
                    else url_for("alerts.detail", alert_id=alert.id))


@bp.route("/bulk", methods=["POST"])
@login_required
def bulk():
    """Acknowledge or resolve several selected alerts at once."""
    status = request.form.get("status")
    # Keep only values that are whole numbers (the checkbox values are alert ids).
    ids = [int(i) for i in request.form.getlist("ids") if i.isdigit()]
    if status not in ALERT_STATUSES or not ids:
        flash("Select at least one alert.", "warning")
        return redirect(url_for("alerts.index"))
    now = datetime.now()
    for alert in Alert.query.filter(Alert.id.in_(ids)).all():
        alert.status, alert.status_changed_by, alert.status_changed_at = status, current_user.username, now
    audit("alert_status_bulk", f"{len(ids)} alerts -> {status}")
    db.session.commit()
    flash(f"{len(ids)} alert(s) marked as {status}.", "success")
    return redirect(url_for("alerts.index"))
