"""Dashboard page and the JSON statistics endpoint used by its charts.

The page itself is rendered on the server (numbers in the tiles, recent
alerts). The charts are drawn in the browser by static/js/dashboard.js,
which fetches /api/stats. While live monitoring runs, the script fetches
it again every 15 seconds so the charts stay current without a full reload.
"""

from flask import Blueprint, current_app, jsonify, render_template, request
from flask_login import login_required

from ..core.reporting import RANGES, Scope, compute_stats
from ..models import Alert, AnalysisRun

bp = Blueprint("dashboard", __name__)


def scope_from_request() -> Scope:
    """Read ?range=24h&run=3 from the URL (also used by the Reports page)."""
    run_id = request.args.get("run", type=int)
    return Scope(request.args.get("range", "all"), run_id=run_id)


@bp.route("/")
@login_required
def index():
    scope = scope_from_request()
    stats = compute_stats(scope)
    recent = scope.alerts().order_by(Alert.last_seen.desc()).limit(8).all()
    runs = AnalysisRun.query.order_by(AnalysisRun.id.desc()).limit(30).all()   # for the run selector
    monitor = current_app.extensions["monitor"].status()
    return render_template("dashboard.html", stats=stats, recent=recent, runs=runs,
                           ranges=["all"] + list(RANGES), scope=scope, monitor=monitor)


@bp.route("/api/stats")
@login_required
def api_stats():
    """The same statistics as JSON, for the charts. Requires login like every page."""
    stats = compute_stats(scope_from_request())
    return jsonify(stats)
