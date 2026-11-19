"""Reports page: PDF report, CSV export and the optional AI summary."""

import json
from datetime import datetime

from flask import Blueprint, Response, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from ..core.reporting import RANGES, Scope, alerts_csv, build_pdf, compute_stats
from ..core.summarizer import SummaryError, summarize
from ..extensions import db
from ..models import AnalysisRun, audit, get_setting, set_setting
from .dashboard import scope_from_request

bp = Blueprint("reports", __name__, url_prefix="/reports")


def _scope_args():
    """The current range/run selection, to keep it in links and redirects."""
    return {k: v for k, v in request.values.items() if k in ("range", "run") and v}


def scope_key(scope: Scope) -> str:
    """A short id for the selection, e.g. "24h|3". Used to show a saved AI
    summary only for the selection it was generated for."""
    return f"{scope.range_key}|{scope.run_id or ''}"


def load_summary(key: str):
    """The last AI summary, if it was made for the same selection. Only the
    most recent summary is kept (as a setting), which is enough for a report."""
    from ..models import Setting
    row = db.session.get(Setting, "last_ai_summary")
    if not row or not row.value:
        return None
    try:
        data = json.loads(row.value)
    except ValueError:
        return None
    return data if data.get("scope") == key else None


@bp.route("/")
@login_required
def index():
    scope = scope_from_request()
    stats = compute_stats(scope)
    runs = AnalysisRun.query.order_by(AnalysisRun.id.desc()).limit(30).all()
    return render_template("reports.html", stats=stats, scope=scope, runs=runs,
                           ranges=["all"] + list(RANGES), args=_scope_args(),
                           summary=load_summary(scope_key(scope)), ollama_model=get_setting("ollama_model"))


@bp.route("/pdf")
@login_required
def pdf():
    """Build and download the PDF. "?ai=1" includes the saved AI summary."""
    scope = scope_from_request()
    stats = compute_stats(scope)
    alerts = scope.alerts().order_by(db.text("first_seen")).all()
    summary = load_summary(scope_key(scope)) if request.args.get("ai") else None
    data = build_pdf(stats, alerts, scope.label, ai_summary=summary["text"] if summary else None,
                     generated_by=current_user.username)
    audit("report_pdf", scope.label)
    db.session.commit()
    name = f"security-report-{datetime.now():%Y%m%d-%H%M}.pdf"
    # "attachment" makes the browser download the file instead of opening it.
    return Response(data, mimetype="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename={name}"})


@bp.route("/alerts.csv")
@login_required
def alerts_export():
    scope = scope_from_request()
    alerts = scope.alerts().order_by(db.text("first_seen")).all()
    return Response(alerts_csv(alerts), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=alerts.csv"})


@bp.route("/summary", methods=["POST"])
@login_required
def ai_summary():
    """Ask the local Ollama model for a summary of the current selection and save it.

    This request waits for the model, which can take up to a couple of
    minutes on modest hardware.
    """
    scope = Scope(request.form.get("range", "all"), run_id=request.form.get("run", type=int))
    stats = compute_stats(scope)
    alerts = scope.alerts().order_by(db.text("first_seen")).all()
    model = get_setting("ollama_model")
    try:
        text = summarize(get_setting("ollama_url"), model, stats, alerts)
    except SummaryError as exc:
        flash(str(exc), "danger")
    else:
        # Saved together with who made it, when, and with which model, so the
        # report page can show where the text came from.
        set_setting("last_ai_summary", json.dumps({
            "scope": scope_key(scope), "label": scope.label, "text": text, "model": model,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "generated_by": current_user.username}))
        audit("ai_summary", f"{model}: {scope.label}")
        db.session.commit()
        flash("AI summary generated. Review it before including it in a report.", "success")
    return redirect(url_for("reports.index", **_scope_args()))
