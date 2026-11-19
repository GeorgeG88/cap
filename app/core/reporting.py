"""Reporting: aggregate statistics, CSV exports and PDF reports.

The same statistics feed three places: the dashboard charts (as JSON), the
Reports page and the PDF report. All of them work on a ``Scope``, which says
which part of the data to look at (a time range, an analysis run, or both).

All counting is done by the database with SQL (COUNT, SUM, GROUP BY) rather
than by loading every event into Python, so the dashboard stays fast even
with hundreds of thousands of stored events.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta

from fpdf import FPDF
from sqlalchemy import case, func

from ..extensions import db
from ..models import Alert, AnalysisRun, Event
from .detection import SEVERITIES

# Time ranges offered in the dashboard and report selectors ("all" means no time limit).
RANGES = {"1h": timedelta(hours=1), "24h": timedelta(hours=24), "7d": timedelta(days=7),
          "30d": timedelta(days=30)}


class Scope:
    """Time range and/or analysis run that a report or chart covers."""

    def __init__(self, range_key: str = "all", run_id: int | None = None,
                 start: datetime | None = None, end: datetime | None = None):
        # Unknown range values from the URL fall back to "all".
        self.range_key = range_key if (range_key in RANGES or range_key == "all") else "all"
        self.run_id = run_id
        self.start, self.end = start, end
        # "24h" means the 24 hours up to now.
        if self.range_key in RANGES and start is None:
            self.end = datetime.now()
            self.start = self.end - RANGES[self.range_key]

    @property
    def label(self) -> str:
        """Human-readable description, e.g. "run #3 (upload: ufw.log), 2026-10-19 14:00 to now"."""
        parts = []
        if self.run_id:
            run = db.session.get(AnalysisRun, self.run_id)
            if run:
                parts.append(f"run #{run.id} ({run.source}: {run.filename or '-'})")
        if self.start or self.end:
            s = self.start.strftime("%Y-%m-%d %H:%M") if self.start else "start"
            e = self.end.strftime("%Y-%m-%d %H:%M") if self.end else "now"
            parts.append(f"{s} to {e}")
        return ", ".join(parts) or "all recorded data"

    def events(self, q=None):
        """Restrict an event query to this scope (adds WHERE conditions)."""
        q = q if q is not None else Event.query
        if self.run_id:
            q = q.filter(Event.run_id == self.run_id)
        if self.start:
            q = q.filter(Event.timestamp >= self.start)
        if self.end:
            q = q.filter(Event.timestamp <= self.end)
        return q

    def alerts(self, q=None):
        """Restrict an alert query to this scope.

        An alert is included if any part of it overlaps the time range
        (it ended after the range started and began before the range ended).
        """
        q = q if q is not None else Alert.query
        if self.run_id:
            q = q.filter(Alert.run_id == self.run_id)
        if self.start:
            q = q.filter(Alert.last_seen >= self.start)
        if self.end:
            q = q.filter(Alert.first_seen <= self.end)
        return q


def _bucket_format(scope: Scope):
    """Choose the bar size for the "traffic over time" chart.

    Up to 3 hours of data -> one bar per minute, up to 4 days -> per hour,
    longer -> per day. This keeps the chart readable at any scale. Returns a
    SQLite strftime format (used to group timestamps) and the unit name.
    """
    q = scope.events(db.session.query(func.min(Event.timestamp), func.max(Event.timestamp)))
    lo, hi = q.one()
    if not lo or not hi:
        return "%Y-%m-%d %H:00", "hour"
    span = hi - lo
    if span <= timedelta(hours=3):
        return "%Y-%m-%d %H:%M", "minute"
    if span <= timedelta(days=4):
        return "%Y-%m-%d %H:00", "hour"
    return "%Y-%m-%d", "day"


def compute_stats(scope: Scope, top_n: int = 10) -> dict:
    """All the figures used by the dashboard, the Reports page and the PDF."""
    # SQL expressions that count DENY and ALLOW rows inside a query
    # (SUM of 1 for matching rows, 0 for the rest).
    deny = func.sum(case((Event.action == "DENY", 1), else_=0))
    allow = func.sum(case((Event.action == "ALLOW", 1), else_=0))
    total, allowed, denied = scope.events(
        db.session.query(func.count(Event.id), allow, deny)).one()
    total, allowed, denied = total or 0, allowed or 0, denied or 0

    unique_sources = scope.events(db.session.query(func.count(func.distinct(Event.src_ip)))).scalar() or 0

    # Timeline: group events into minute/hour/day buckets and count per action.
    fmt, unit = _bucket_format(scope)
    bucket = func.strftime(fmt, Event.timestamp)
    timeline_rows = (scope.events(db.session.query(bucket.label("b"), allow, deny,
                                                   func.count(Event.id)))
                     .group_by("b").order_by("b").all())
    timeline = {"unit": unit, "labels": [r[0] for r in timeline_rows],
                "allow": [int(r[1] or 0) for r in timeline_rows],
                "deny": [int(r[2] or 0) for r in timeline_rows],
                # "other" is everything that is neither ALLOW nor DENY (AUDIT lines).
                "other": [int((r[3] or 0) - (r[1] or 0) - (r[2] or 0)) for r in timeline_rows]}

    # Busiest source addresses and destination ports, with how many were denied.
    top_sources = [{"ip": ip, "count": c, "denied": int(d or 0)} for ip, c, d in
                   scope.events(db.session.query(Event.src_ip, func.count(Event.id).label("c"), deny))
                   .group_by(Event.src_ip).order_by(db.desc("c")).limit(top_n).all()]
    top_ports = [{"port": p, "count": c, "denied": int(d or 0)} for p, c, d in
                 scope.events(db.session.query(Event.dst_port, func.count(Event.id).label("c"), deny))
                 .filter(Event.dst_port.isnot(None))
                 .group_by(Event.dst_port).order_by(db.desc("c")).limit(top_n).all()]
    protocols = dict(scope.events(db.session.query(Event.proto, func.count(Event.id)))
                     .group_by(Event.proto).all())

    # Alert counts by severity, by rule and by status.
    alert_q = scope.alerts()
    by_sev = dict(scope.alerts(db.session.query(Alert.severity, func.count(Alert.id)))
                  .group_by(Alert.severity).all())
    by_rule = [{"rule": n, "count": c} for n, c in
               scope.alerts(db.session.query(Alert.rule_name, func.count(Alert.id).label("c")))
               .group_by(Alert.rule_name).order_by(db.desc("c")).all()]
    by_status = dict(scope.alerts(db.session.query(Alert.status, func.count(Alert.id)))
                     .group_by(Alert.status).all())

    return {
        "scope": scope.label,
        "events": {"total": total, "allowed": allowed, "denied": denied,
                   "other": total - allowed - denied,
                   "deny_ratio": round(denied / total * 100, 1) if total else 0.0,
                   "unique_sources": unique_sources},
        "alerts": {"total": alert_q.count(),
                   # "Open" means not yet resolved.
                   "open": by_status.get("new", 0) + by_status.get("acknowledged", 0),
                   # Every severity is listed, with 0 where there are none.
                   "by_severity": {s: by_sev.get(s, 0) for s in SEVERITIES},
                   "by_rule": by_rule, "by_status": by_status},
        "timeline": timeline,
        "top_sources": top_sources,
        "top_ports": top_ports,
        "protocols": protocols,
    }


# --------------------------------------------------------------------------
# CSV
# --------------------------------------------------------------------------
def _csv_safe(value):
    """Neutralise spreadsheet formula injection (values starting with = + - @).

    Log content comes from the network, so an attacker could make a field
    start with "=". Excel would treat that cell as a formula when the CSV is
    opened. A leading apostrophe makes the spreadsheet show it as plain text.
    """
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def alerts_csv(alerts) -> str:
    """Alerts as CSV text, one row per alert."""
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["id", "severity", "rule", "source_ip", "first_seen", "last_seen", "count",
                "occurrences", "status", "summary"])
    for a in alerts:
        w.writerow([_csv_safe(v) for v in [a.id, a.severity, a.rule_name, a.src_ip, a.first_seen,
                                           a.last_seen, a.event_count, a.occurrences, a.status,
                                           (a.details or {}).get("summary", "")]])
    return out.getvalue()


def events_csv(events) -> str:
    """Events as CSV text, one row per event (the raw line is not included)."""
    out = io.StringIO()
    w = csv.writer(out)
    cols = ["timestamp", "action", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "flags",
            "direction", "iface_in", "length", "ttl", "hostname"]
    w.writerow(cols)
    for e in events:
        w.writerow([_csv_safe(getattr(e, c)) for c in cols])
    return out.getvalue()


# --------------------------------------------------------------------------
# PDF
# --------------------------------------------------------------------------
# The PDF is drawn with fpdf2. Positions and sizes are in millimetres on an
# A4 page (210 x 297 mm) with 10 mm margins.

def _latin1(text) -> str:
    """The built-in PDF fonts only cover Latin-1 characters. Anything else
    (emoji, Greek, etc.) is replaced with "?" instead of causing an error."""
    return str(text if text is not None else "").encode("latin-1", "replace").decode("latin-1")


class _ReportPDF(FPDF):
    """FPDF with a header and footer that are repeated on every page."""

    def header(self):
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(110, 110, 110)
        self.cell(0, 6, "Firewall Log Analyzer and Alert System", align="L")
        self.cell(0, 6, datetime.now().strftime("%Y-%m-%d %H:%M"), align="R",
                  new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(220, 220, 220)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(140, 140, 140)
        # {nb} is replaced with the total page count when the PDF is finished.
        self.cell(0, 6, f"Page {self.page_no()}/{{nb}}", align="C")


# Text colours for each severity in the alert table (red/green/blue values).
SEV_RGB = {"low": (59, 130, 246), "medium": (217, 159, 39), "high": (234, 88, 12),
           "critical": (220, 38, 38)}


def _h2(pdf, text):
    """Section heading."""
    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(20, 20, 20)
    pdf.cell(0, 8, _latin1(text), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)


def _bar_chart(pdf, rows, label_key, value_key, color=(37, 99, 235), max_rows=10):
    """Draw a simple horizontal bar chart: label, bar, value on each line.

    The longest bar is 110 mm wide; the others are scaled to it.
    """
    rows = rows[:max_rows]
    if not rows:
        pdf.cell(0, 6, "No data.", new_x="LMARGIN", new_y="NEXT")
        return
    vmax = max(r[value_key] for r in rows) or 1
    pdf.set_font("Helvetica", "", 8.5)
    for r in rows:
        y = pdf.get_y()
        pdf.set_text_color(40, 40, 40)
        # Shorten long labels until they fit in the 45 mm label column.
        label = _latin1(str(r[label_key]))
        while pdf.get_string_width(label) > 44 and len(label) > 4:
            label = label[:-2] + "."
        pdf.cell(45, 6, label)
        width = 110 * r[value_key] / vmax
        pdf.set_fill_color(*color)
        pdf.rect(57, y + 1.2, max(width, 0.5), 3.6, style="F")   # at least a thin sliver
        pdf.set_xy(57 + 112, y)
        pdf.cell(25, 6, str(r[value_key]), align="R", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)


def build_pdf(stats: dict, alerts: list, scope_label: str, ai_summary: str | None = None,
              generated_by: str = "") -> bytes:
    """Create the PDF security report and return it as bytes.

    Page layout, top to bottom: title, summary tiles, alerts by severity,
    optional AI summary, three bar charts, and the table of alerts.
    """
    pdf = _ReportPDF(format="A4")
    pdf.alias_nb_pages()                     # enables the "{nb}" total page count
    pdf.set_auto_page_break(True, margin=15) # start a new page automatically when full
    pdf.add_page()

    # Title block.
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 10, "Network Security Report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(90, 90, 90)
    pdf.multi_cell(0, 5, _latin1(f"Scope: {scope_label}\nGenerated by: {generated_by or '-'}"))
    pdf.set_text_color(20, 20, 20)

    # Six summary tiles in a row (each 29.5 mm wide with a 2 mm gap).
    ev, al = stats["events"], stats["alerts"]
    _h2(pdf, "Summary")
    tiles = [("Events", ev["total"]), ("Allowed", ev["allowed"]), ("Denied", ev["denied"]),
             ("Deny ratio", f"{ev['deny_ratio']}%"), ("Sources", ev["unique_sources"]),
             ("Alerts", al["total"])]
    x0, y0 = pdf.get_x(), pdf.get_y()
    for i, (label, value) in enumerate(tiles):
        x = x0 + i * 31.5
        pdf.set_fill_color(245, 246, 248)
        pdf.rect(x, y0, 29.5, 16, style="F")
        pdf.set_xy(x + 2, y0 + 1.5)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(25, 4, label)
        pdf.set_xy(x + 2, y0 + 7)
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(20, 20, 20)
        pdf.cell(25, 6, _latin1(value))
    pdf.set_xy(x0, y0 + 20)
    pdf.set_font("Helvetica", "", 10)

    sev_line = ", ".join(f"{s}: {n}" for s, n in al["by_severity"].items())
    pdf.multi_cell(0, 5, _latin1(f"Alerts by severity - {sev_line}. Open alerts: {al['open']}."))

    # The AI summary is only included when the user explicitly asks for it,
    # and it is labelled so the reader knows it was machine-written.
    if ai_summary:
        _h2(pdf, "Analyst summary (AI-generated, verify before acting)")
        pdf.set_font("Helvetica", "", 9.5)
        pdf.multi_cell(0, 4.8, _latin1(ai_summary))
        pdf.set_font("Helvetica", "", 10)

    _h2(pdf, "Alerts by detection rule")
    _bar_chart(pdf, al["by_rule"], "rule", "count", color=(234, 88, 12))

    _h2(pdf, "Top source IPs (events)")
    _bar_chart(pdf, stats["top_sources"], "ip", "count")

    _h2(pdf, "Top destination ports (events)")
    _bar_chart(pdf, stats["top_ports"], "port", "count", color=(13, 148, 136))

    # Alert table. Limited to 300 rows to keep the PDF a sensible size;
    # the CSV export contains everything.
    _h2(pdf, f"Alerts ({len(alerts)})")
    if not alerts:
        pdf.cell(0, 6, "No alerts in this scope.", new_x="LMARGIN", new_y="NEXT")
    else:
        widths = (12, 18, 40, 32, 34, 16, 38)    # column widths in mm
        headers = ("ID", "Sev.", "Rule", "Source", "First seen", "Count", "Status")
        pdf.set_font("Helvetica", "B", 8.5)
        pdf.set_fill_color(235, 237, 240)
        for w_, h in zip(widths, headers):
            pdf.cell(w_, 6, h, fill=True)
        pdf.ln()
        pdf.set_font("Helvetica", "", 8.5)
        for a in alerts[:300]:
            pdf.cell(widths[0], 5.5, str(a.id))
            pdf.set_text_color(*SEV_RGB.get(a.severity, (0, 0, 0)))
            pdf.cell(widths[1], 5.5, a.severity)
            pdf.set_text_color(20, 20, 20)
            pdf.cell(widths[2], 5.5, _latin1(a.rule_name)[:26])
            pdf.cell(widths[3], 5.5, _latin1(a.src_ip)[:20])
            pdf.cell(widths[4], 5.5, a.first_seen.strftime("%Y-%m-%d %H:%M:%S"))
            pdf.cell(widths[5], 5.5, str(a.event_count))
            pdf.cell(widths[6], 5.5, a.status, new_x="LMARGIN", new_y="NEXT")
        if len(alerts) > 300:
            pdf.cell(0, 6, f"... {len(alerts) - 300} more alerts (see CSV export)",
                     new_x="LMARGIN", new_y="NEXT")
    return bytes(pdf.output())
