"""Web layer: one Flask Blueprint (group of pages) per area of the interface.

  auth.py       login, logout, own account
  dashboard.py  dashboard and /api/stats for its charts
  alerts.py     alert queue, alert details, triage
  events.py     event explorer and CSV export
  analysis.py   file upload, analysis runs, live monitor
  admin.py      rules, allowlist, settings, users, audit log
  reports.py    PDF/CSV reports and the AI summary

The pages only handle web input and output. The actual work is done by
the modules in app/core.
"""


def register_blueprints(app):
    """Attach every group of pages to the application."""
    from .admin import bp as admin_bp
    from .alerts import bp as alerts_bp
    from .analysis import bp as analysis_bp
    from .auth import bp as auth_bp
    from .dashboard import bp as dashboard_bp
    from .events import bp as events_bp
    from .reports import bp as reports_bp

    for bp in (auth_bp, dashboard_bp, alerts_bp, events_bp, analysis_bp, admin_bp, reports_bp):
        app.register_blueprint(bp)
