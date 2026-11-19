"""Event explorer: search and export the stored firewall events."""

from datetime import datetime

from flask import Blueprint, Response, render_template, request
from flask_login import login_required

from ..core.reporting import events_csv
from ..models import AnalysisRun, Event

bp = Blueprint("events", __name__, url_prefix="/events")

PER_PAGE = 50
# Cap on rows in one CSV export, so a single click cannot exhaust memory.
EXPORT_LIMIT = 100_000


def _parse_dt(value: str):
    """Read a date/time from the filter form. The browser's date-time picker
    sends "2026-10-19T14:30"; plain dates are accepted too. Bad input -> None."""
    for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt)
        except (TypeError, ValueError):
            continue
    return None


def filtered_events():
    """Build the event query from the filters in the URL (used by the page and the CSV export)."""
    q = Event.query
    a = request.args
    # IP filters match the start of the address ("192.168.56." finds the whole subnet).
    if a.get("src"):
        q = q.filter(Event.src_ip.like(a["src"].strip() + "%"))
    if a.get("dst"):
        q = q.filter(Event.dst_ip.like(a["dst"].strip() + "%"))
    port = a.get("port", type=int)
    if port is not None:
        q = q.filter(Event.dst_port == port)
    if a.get("action") in ("ALLOW", "DENY", "AUDIT"):
        q = q.filter(Event.action == a["action"])
    if a.get("proto"):
        q = q.filter(Event.proto == a["proto"].upper())
    run = a.get("run", type=int)
    if run:
        q = q.filter(Event.run_id == run)
    start, end = _parse_dt(a.get("start", "")), _parse_dt(a.get("end", ""))
    if start:
        q = q.filter(Event.timestamp >= start)
    if end:
        q = q.filter(Event.timestamp <= end)
    return q


@bp.route("/")
@login_required
def index():
    """Newest events first, 50 per page."""
    page = request.args.get("page", 1, type=int)
    pagination = (filtered_events().order_by(Event.timestamp.desc(), Event.id.desc())
                  .paginate(page=page, per_page=PER_PAGE, error_out=False))
    runs = AnalysisRun.query.order_by(AnalysisRun.id.desc()).limit(30).all()
    args = {k: v for k, v in request.args.items() if k != "page"}
    return render_template("events.html", pagination=pagination, runs=runs, args=args)


@bp.route("/export.csv")
@login_required
def export():
    """Download the events matching the current filters as a CSV file."""
    rows = filtered_events().order_by(Event.timestamp).limit(EXPORT_LIMIT).all()
    return Response(events_csv(rows), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=events.csv"})
