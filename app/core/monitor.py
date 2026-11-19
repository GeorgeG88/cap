"""Live monitoring: tails the UFW log file and analyses new lines as they arrive.

Handles partially written lines and log rotation (logrotate replacing
ufw.log with a fresh file) without re-reading old data or crashing.

How it works
------------
A background thread keeps the log file open and repeatedly reads whatever
has been added to the end of it, much like the Linux command "tail -f".
New complete lines go through the same AnalysisPipeline that uploaded files
use, so live and batch analysis behave identically. When nothing new has
arrived, the thread checks whether the file was rotated and then sleeps for
POLL_SECONDS before trying again.
"""

from __future__ import annotations

import logging
import os
import threading
from datetime import datetime

from ..extensions import db
from ..models import AnalysisRun, audit
from .pipeline import AnalysisPipeline

log = logging.getLogger(__name__)

# How long to wait before checking the file again when there is no new data.
POLL_SECONDS = 1.0
# Maximum bytes read in one go (1 MB). Larger backlogs are read in several steps.
READ_CHUNK = 1024 * 1024


class LiveMonitor:
    """Starts, stops and reports on the background monitoring thread.

    There is one LiveMonitor per application, so only one live session
    can run at a time.
    """

    def __init__(self, app, notifier=None):
        self.app = app
        self.notifier = notifier
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()       # set() tells the thread to finish
        self._lock = threading.Lock()        # prevents two simultaneous starts
        # Status values shown on the Live monitor page:
        self.path: str | None = None
        self.run_id: int | None = None
        self.started_at: datetime | None = None
        self.lines_read = 0
        self.last_activity: datetime | None = None
        self.error: str | None = None
        self.rotations = 0

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def status(self) -> dict:
        return {"running": self.running, "path": self.path, "run_id": self.run_id,
                "started_at": self.started_at, "lines_read": self.lines_read,
                "last_activity": self.last_activity, "error": self.error, "rotations": self.rotations}

    def start(self, path: str, from_start: bool = False, username: str | None = None) -> str | None:
        """Start monitoring. Returns an error message or None."""
        with self._lock:
            # Check the obvious problems first so the user gets a clear message.
            if self.running:
                return "Live monitoring is already running."
            if not os.path.isfile(path):
                return f"Log file not found: {path}"
            if not os.access(path, os.R_OK):
                return (f"No permission to read {path}. On Ubuntu add the app user to the 'adm' "
                        "group (sudo usermod -aG adm $USER) and log in again.")

            # Each live session is recorded as an analysis run, with
            # notifications switched on.
            run = AnalysisRun(source="live", filename=path, status="running", notify=True,
                              created_by=username)
            db.session.add(run)
            db.session.commit()
            self.path, self.run_id = path, run.id
            self.started_at, self.lines_read, self.error, self.rotations = datetime.now(), 0, None, 0
            self.last_activity = None
            self._stop.clear()
            # remember the position now, so lines written while the thread starts are not missed
            # Normally reading starts at the current end of the file (only new
            # events). "from_start" reads the existing contents first.
            offset = 0 if from_start else os.path.getsize(path)
            # daemon=True: the thread does not keep the program alive on shutdown.
            self._thread = threading.Thread(target=self._run, args=(run.id, path, offset),
                                            name="live-monitor", daemon=True)
            self._thread.start()
            return None

    def stop(self, timeout: float = 10.0) -> None:
        """Ask the thread to finish and wait (up to ``timeout`` seconds) for it."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)

    # ------------------------------------------------------------------
    def _run(self, run_id: int, path: str, offset: int) -> None:
        """Body of the background thread."""
        # The thread needs its own app context to use the database.
        with self.app.app_context():
            run = db.session.get(AnalysisRun, run_id)
            pipeline = AnalysisPipeline(run, notifier=self.notifier)
            status = "stopped"
            try:
                self._tail(path, offset, pipeline)   # runs until stop() is called
            except Exception as exc:
                # Record the error so it is visible on the Live monitor page.
                log.exception("live monitor crashed")
                self.error = f"{exc.__class__.__name__}: {exc}"
                status = "failed"
            try:
                # Save whatever is still buffered and close the run.
                pipeline.finish(status)
                if status == "failed":
                    run = db.session.get(AnalysisRun, run_id)
                    run.error = self.error
                audit("monitor_stopped", f"{path} ({status}, {self.lines_read} lines)", username="system")
                db.session.commit()
            except Exception:
                log.exception("could not finalize live run")
                db.session.rollback()

    def _tail(self, path: str, offset: int, pipeline: AnalysisPipeline) -> None:
        """Follow the file and feed complete new lines to the pipeline."""
        # Binary mode lets us split on newline bytes ourselves and handle
        # half-written lines and odd characters safely.
        fh = open(path, "rb")
        try:
            # The inode number identifies the actual file on disk. If logrotate
            # renames ufw.log and creates a new one, the path stays the same
            # but the inode changes.
            inode = os.fstat(fh.fileno()).st_ino
            if offset > os.fstat(fh.fileno()).st_size:  # rotated in the meantime
                offset = 0
            fh.seek(offset)
            # Bytes read so far that do not yet end with a newline.
            buffer = b""
            while not self._stop.is_set():
                chunk = fh.read(READ_CHUNK)
                if chunk:
                    buffer += chunk
                    # Split into lines. The last piece may be a line that the
                    # kernel is still writing, so it stays in the buffer until
                    # its newline arrives.
                    *complete, buffer = buffer.split(b"\n")
                    if complete:
                        lines = [c.decode("utf-8", errors="replace") for c in complete]
                        pipeline.feed(lines)
                        pipeline.flush()          # write now, so alerts appear immediately
                        self.lines_read += len(lines)
                        self.last_activity = datetime.now()
                    continue   # there may be more data; read again without waiting

                # no new data: check for rotation / truncation
                try:
                    st = os.stat(path)
                except FileNotFoundError:
                    st = None  # file is being rotated; try again shortly
                # Rotation: a different file now has the name (inode changed),
                # or the file is smaller than our read position (it was
                # emptied). Either way, reopen it and read from the start.
                if st is not None and (st.st_ino != inode or st.st_size < fh.tell()):
                    fh.close()
                    fh = open(path, "rb")
                    inode = os.fstat(fh.fileno()).st_ino
                    buffer = b""
                    self.rotations += 1
                    log.info("log rotation detected for %s", path)
                    continue

                # Nothing to do: sleep, but wake up at once if stop() is called.
                self._stop.wait(POLL_SECONDS)
        finally:
            fh.close()
