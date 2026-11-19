"""Pages for running analyses: file upload, the list of runs, and live monitoring."""

import os
import threading
import uuid

from flask import (Blueprint, abort, current_app, flash, redirect, render_template, request,
                   url_for)
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

from ..core.pipeline import analyze_file
from ..extensions import db
from ..models import Alert, AnalysisRun, Event, audit, get_setting, set_setting
from ..security import admin_required

bp = Blueprint("analysis", __name__)


@bp.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    """Upload a log file and start analysing it in the background.

    Steps: save the file under a random name -> create an AnalysisRun record
    -> start a background thread -> send the user to the run page, which
    refreshes itself until the analysis is finished.
    """
    if request.method == "POST":
        f = request.files.get("logfile")
        if not f or not f.filename:
            flash("Choose a log file to upload.", "warning")
            return redirect(url_for("analysis.upload"))
        # The original name is cleaned (no "../" tricks) and only used for
        # display. The file itself is saved under a random name, so an
        # uploaded name can never overwrite another file.
        name = secure_filename(f.filename) or "upload.log"
        stored = os.path.join(current_app.config["UPLOAD_DIR"], f"{uuid.uuid4().hex}.log")
        f.save(stored)
        run = AnalysisRun(source="upload", filename=name, status="queued",
                          notify=bool(request.form.get("notify")), created_by=current_user.username)
        db.session.add(run)
        db.session.flush()    # gives the run its id before the audit entry is written
        audit("upload", f"{name} ({os.path.getsize(stored)} bytes), run #{run.id}")
        db.session.commit()
        # A large file can take a while; doing the work in a thread means the
        # browser gets an answer immediately.
        thread = threading.Thread(target=analyze_file, name=f"analysis-{run.id}",
                                  args=(current_app._get_current_object(), run.id, stored,
                                        current_app.extensions["notifier"]), daemon=True)
        thread.start()
        flash(f"Analysis of {name} started.", "info")
        return redirect(url_for("analysis.run_detail", run_id=run.id))
    return render_template("upload.html", max_mb=current_app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024))


@bp.route("/runs")
@login_required
def runs():
    """All analysis runs, newest first, 25 per page."""
    page = request.args.get("page", 1, type=int)
    pagination = AnalysisRun.query.order_by(AnalysisRun.id.desc()).paginate(page=page, per_page=25,
                                                                            error_out=False)
    return render_template("runs.html", pagination=pagination)


@bp.route("/runs/<int:run_id>")
@login_required
def run_detail(run_id):
    """Statistics and alerts of one run."""
    run = db.session.get(AnalysisRun, run_id) or abort(404)
    alerts = Alert.query.filter_by(run_id=run.id).order_by(Alert.first_seen).all()
    return render_template("run_detail.html", run=run, alerts=alerts)


@bp.route("/runs/<int:run_id>/delete", methods=["POST"])
@admin_required
def run_delete(run_id):
    """Delete a run together with its events and alerts (admin only)."""
    run = db.session.get(AnalysisRun, run_id) or abort(404)
    if run.status in ("queued", "running"):
        flash("A run cannot be deleted while it is in progress.", "warning")
        return redirect(url_for("analysis.run_detail", run_id=run.id))
    # Bulk deletes are much faster than deleting rows one by one.
    Event.query.filter_by(run_id=run.id).delete(synchronize_session=False)
    Alert.query.filter_by(run_id=run.id).delete(synchronize_session=False)
    audit("run_deleted", f"run #{run.id} ({run.filename})")
    db.session.delete(run)
    db.session.commit()
    flash(f"Run #{run_id} and its events and alerts were deleted.", "success")
    return redirect(url_for("analysis.runs"))


@bp.route("/monitor", methods=["GET", "POST"])
@login_required
def monitor():
    """Live monitor page. Everyone can view the status; only admins can start or stop it."""
    mon = current_app.extensions["monitor"]
    if request.method == "POST":
        if not current_user.is_admin:
            abort(403)
        action = request.form.get("action")
        if action == "start":
            # Remember the chosen options for next time (and for autostart).
            path = request.form.get("path", "").strip() or get_setting("monitor_log_path")
            from_start = bool(request.form.get("from_start"))
            set_setting("monitor_log_path", path)
            set_setting("monitor_from_start", from_start)
            set_setting("monitor_autostart", bool(request.form.get("autostart")))
            db.session.commit()
            err = mon.start(path, from_start, current_user.username)
            if err:
                flash(err, "danger")
            else:
                audit("monitor_started", path)
                db.session.commit()
                flash(f"Live monitoring of {path} started.", "success")
        elif action == "stop":
            mon.stop()
            flash("Live monitoring stopped.", "info")
        # Redirect after POST, so refreshing the page does not repeat the action.
        return redirect(url_for("analysis.monitor"))
    status = mon.status()
    run = db.session.get(AnalysisRun, status["run_id"]) if status["run_id"] else None
    recent = []
    if run:
        recent = Alert.query.filter_by(run_id=run.id).order_by(Alert.last_seen.desc()).limit(10).all()
    return render_template("monitor.html", status=status, run=run, recent=recent,
                           path=get_setting("monitor_log_path"),
                           from_start=get_setting("monitor_from_start"),
                           autostart=get_setting("monitor_autostart"))
