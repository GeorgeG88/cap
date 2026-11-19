"""Analysis pipeline: parser -> filter -> storage -> detection -> alerting.

Used for both uploaded files (batch) and the live monitor (incremental).

This module connects the other core modules into one process:

    raw lines
      -> UFWParser         turns text into FirewallEvent objects
      -> EventFilter       noise is dropped; allowlisted events are kept but not analysed
      -> buffer of rows    written to the events table in batches
      -> DetectionEngine   sliding-window rules produce Detection updates
      -> AlertManager      turns detections into alerts and queues notifications

Writing to the database one row at a time would be slow, so events and
detections are collected in memory and written together every BATCH_SIZE
events (and at the end). For live monitoring the monitor calls flush()
after every read, so alerts appear within about a second.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Iterable

from ..extensions import db
from ..models import AllowlistEntry, AnalysisRun, Event, Rule, all_settings
from .alerting import AlertManager
from .authparser import DEFAULT_AUTH_RULE, AuthBruteForceDetector, AuthLogParser
from .detection import DetectionEngine, default_rule_configs
from .filters import EventFilter, FilterConfig, parse_networks
from .parser import UFWParser

log = logging.getLogger(__name__)

# Number of events collected in memory before they are written to the database.
BATCH_SIZE = 2000


def load_rule_dicts() -> list:
    """Read the current rule settings from the database.

    Falls back to the built-in defaults if the rules table is empty.
    """
    rules = Rule.query.all()
    if not rules:
        return [r.__dict__ for r in default_rule_configs()]
    return [r.to_config_dict() for r in rules]


def load_filter_config(settings: dict) -> FilterConfig:
    """Build the filter settings from the Settings page values and the allowlist table."""
    # noise_ports is stored as text such as "67,68,137"; turn it into numbers.
    ports = []
    for p in str(settings.get("noise_ports", "")).split(","):
        p = p.strip()
        if p.isdigit():
            ports.append(int(p))
    return FilterConfig(
        allowlist=parse_networks(e.cidr for e in AllowlistEntry.query.all()),
        drop_broadcast=bool(settings.get("drop_broadcast", True)),
        drop_multicast=bool(settings.get("drop_multicast", True)),
        noise_ports=tuple(ports),
    )


class AnalysisPipeline:
    """One analysis from start to finish (one uploaded file, or one live session).

    Rules, filters and settings are read once when the pipeline is created.
    That is why rule changes reach live monitoring only after it is restarted.
    """

    def __init__(self, run: AnalysisRun, notifier=None, reference_time: datetime | None = None):
        settings = all_settings()
        self.run_id = run.id
        self.parser = UFWParser(reference_time=reference_time)
        self.filter = EventFilter(load_filter_config(settings))
        self.engine = DetectionEngine(load_rule_dicts())
        # Notifications are only sent if the run asks for them (live monitoring
        # always does; uploads only if the user ticked the box).
        self.alerts = AlertManager(run.id, settings, notifier=notifier, notify=bool(run.notify))
        self._events: list = []          # event rows waiting to be written
        self._detections: dict = {}      # latest Detection per episode, waiting to be applied
        self.events_stored = 0
        self.first_event = run.first_event
        self.last_event = run.last_event

    def feed(self, lines: Iterable[str]) -> None:
        """Process a batch of raw log lines."""
        for event in self.parser.parse_lines(lines):
            kind = self.filter.classify(event)
            if kind == "noise":
                continue   # dropped: not stored and not analysed

            # Prepare the database row. Allowlisted events are stored too,
            # with a flag, so the analyst can still see that traffic.
            row = event.to_dict()
            row["run_id"] = self.run_id
            row["allowlisted"] = kind == "allowlisted"
            self._events.append(row)

            # Track the time span covered by the log, shown on the run page.
            if self.first_event is None or event.timestamp < self.first_event:
                self.first_event = event.timestamp
            if self.last_event is None or event.timestamp > self.last_event:
                self.last_event = event.timestamp

            # Only non-allowlisted events reach the detection rules.
            if kind == "ok":
                for d in self.engine.process(event):
                    # A long scan produces an update for every packet. Keeping
                    # only the latest update per episode (same key) means the
                    # database is written once per episode per batch.
                    self._detections[d.key] = d

            if len(self._events) >= BATCH_SIZE:
                self.flush()

    def flush(self) -> None:
        """Write buffered events and alerts, update run statistics, commit."""
        if self._events:
            # One bulk INSERT for the whole batch.
            db.session.execute(db.insert(Event), self._events)
            self.events_stored += len(self._events)
            self._events = []
        if self._detections:
            self.alerts.apply(self._detections.values())
            self._detections = {}

        # Copy the counters to the run record so the run page shows progress.
        run = db.session.get(AnalysisRun, self.run_id)
        ps, fs = self.parser.stats, self.filter.stats
        run.lines_total = ps.total
        run.lines_parsed = ps.parsed
        run.lines_not_ufw = ps.not_ufw
        run.lines_malformed = ps.malformed
        run.events_noise = fs.noise
        run.events_allowlisted = fs.allowlisted
        run.events_stored = self.events_stored
        run.alerts_created = self.alerts.created
        run.first_event = self.first_event
        run.last_event = self.last_event

        # Commit everything, then hand any notifications to the background sender.
        self.alerts.commit_and_dispatch()

    def finish(self, status: str = "done") -> None:
        """End of input: collect pending detections, write everything, mark the run finished."""
        for d in self.engine.flush():
            self._detections[d.key] = d
        self.flush()
        run = db.session.get(AnalysisRun, self.run_id)
        run.status = status
        run.finished_at = datetime.now()
        db.session.commit()


def analyze_file(app, run_id: int, path: str, notifier=None) -> None:
    """Background job for an uploaded log file.

    Runs in its own thread so the web page returns immediately; the run
    page refreshes itself until the status changes to "done" or "failed".
    """
    # A background thread has no web request, so it needs its own app
    # context to use the database.
    with app.app_context():
        run = db.session.get(AnalysisRun, run_id)
        run.status = "running"
        db.session.commit()
        pipeline = AnalysisPipeline(run, notifier=notifier)
        try:
            # errors="replace" turns invalid bytes into "?" instead of failing.
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                pipeline.feed(fh)    # the file is read line by line, not loaded all at once
            pipeline.finish("done")
        except Exception as exc:  # report the failure on the run page
            log.exception("analysis of %s failed", path)
            db.session.rollback()
            run = db.session.get(AnalysisRun, run_id)
            run.status = "failed"
            run.error = f"{exc.__class__.__name__}: {exc}"
            run.finished_at = datetime.now()
            db.session.commit()
        finally:
            try:
                os.remove(path)  # events are stored in the database; drop the temp file
            except OSError:
                pass


def load_auth_rule() -> dict:
    """The SSH auth brute-force rule settings from the database, or the defaults."""
    rule = db.session.get(Rule, DEFAULT_AUTH_RULE["rule_id"])
    return rule.to_config_dict() if rule else dict(DEFAULT_AUTH_RULE)


class AuthPipeline:
    """Live analysis of sshd's auth log. Produces SSH brute-force alerts only;
    it does not write rows to the events table (auth events are not firewall
    events). Exposes the same feed()/flush()/finish() interface as
    AnalysisPipeline, so the live monitor can tail its file the same way.
    """

    def __init__(self, run: AnalysisRun, notifier=None, reference_time: datetime | None = None):
        settings = all_settings()
        self.run_id = run.id
        self.parser = AuthLogParser(reference_time=reference_time)
        cfg = load_auth_rule()
        self.enabled = bool(cfg.get("enabled", True))
        self.detector = AuthBruteForceDetector(int(cfg["threshold"]), int(cfg["window_seconds"]),
                                               cfg.get("severity", "high"))
        self.alerts = AlertManager(run.id, settings, notifier=notifier, notify=bool(run.notify))
        self._detections: dict = {}
        self.first_event = run.first_event
        self.last_event = run.last_event

    def feed(self, lines: Iterable[str]) -> None:
        for ev in self.parser.parse_lines(lines):
            if self.first_event is None or ev.timestamp < self.first_event:
                self.first_event = ev.timestamp
            if self.last_event is None or ev.timestamp > self.last_event:
                self.last_event = ev.timestamp
            if not self.enabled:
                continue
            d = self.detector.process(ev)
            if d is not None:
                self._detections[d.key] = d

    def flush(self) -> None:
        if self._detections:
            self.alerts.apply(self._detections.values())
            self._detections = {}
        run = db.session.get(AnalysisRun, self.run_id)
        s = self.parser.stats
        run.lines_total = s.total
        run.lines_parsed = s.parsed
        run.events_stored = 0   # auth events are not stored as firewall events
        run.alerts_created = self.alerts.created
        run.first_event = self.first_event
        run.last_event = self.last_event
        self.alerts.commit_and_dispatch()

    def finish(self, status: str = "done") -> None:
        self.flush()
        run = db.session.get(AnalysisRun, self.run_id)
        run.status = status
        run.finished_at = datetime.now()
        db.session.commit()
