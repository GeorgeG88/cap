"""SSH authentication log parsing and brute-force detection.

This is the second log source. UFW logs *connections*; sshd logs *login
outcomes* in /var/log/auth.log. Together they cover each other's blind spot:
the firewall rate-limits the logging of allowed connections (so a brute-force
against the open SSH service can slip past the connection-rate rules), but
sshd records every failed password regardless of connection rate or firewall
logging level.

The detector here counts failed logins per source IP in a sliding window and
raises a "SSH authentication brute-force" alert when the count crosses a
threshold. It produces the same ``Detection`` objects as the firewall rules,
so the existing alerting, notification and reporting code handles them
unchanged.

Recognised sshd messages (OpenSSH on Debian/Ubuntu/Kali):
  Failed password for [invalid user ]<user> from <ip> port <n> ssh2
  Invalid user <user> from <ip>
  Accepted password|publickey for <user> from <ip> port <n>   (success, for context)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable, Iterator, Optional

from .detection import Detection, WindowCounter
from .parser import ISO_RE, SYSLOG_RE, MONTHS

# sshd message bodies (everything after "sshd[pid]: ").
FAILED_RE = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+")
INVALID_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")
ACCEPTED_RE = re.compile(r"Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>\S+) port \d+")
# Only sshd lines are of interest; this keeps PAM/cron/su noise out cheaply.
SSHD_RE = re.compile(r"\bsshd\[\d+\]:\s*(?P<body>.*)$")


@dataclass
class AuthEvent:
    timestamp: datetime
    src_ip: str
    user: str
    outcome: str          # "failed" | "invalid" | "accepted"
    raw: str = ""


@dataclass
class AuthStats:
    total: int = 0        # non-empty lines read
    parsed: int = 0       # sshd auth outcomes recognised
    failed: int = 0       # failed + invalid
    accepted: int = 0

    def as_dict(self) -> dict:
        return {"total": self.total, "parsed": self.parsed,
                "failed": self.failed, "accepted": self.accepted}


class AuthLogParser:
    """Turns auth.log lines into AuthEvent records. Non-sshd and unrecognised
    lines are skipped (and counted), never fatal."""

    def __init__(self, reference_time: Optional[datetime] = None):
        self.reference_time = reference_time
        self.stats = AuthStats()

    def _timestamp(self, line: str):
        """Return (timestamp, body) or (None, None) if neither format matches.

        Reuses the firewall parser's timestamp regexes so both log types read
        dates the same way."""
        m = SYSLOG_RE.match(line)
        if m:
            ref = self.reference_time or datetime.now()
            month = MONTHS.get(m["mon"])
            if month is None:
                return None, None
            h, mi, s = (int(x) for x in m["time"].split(":"))
            ts = datetime(ref.year, month, int(m["day"]), h, mi, s)
            if ts > ref + timedelta(days=1):      # year rollover (Dec log read in Jan)
                ts = ts.replace(year=ref.year - 1)
            return ts, m["rest"]
        m = ISO_RE.match(line)
        if m:
            value = m["iso"].replace(" ", "T", 1)
            if value.endswith("Z"):
                value = value[:-1] + "+00:00"
            mm = re.search(r"([+-]\d{2})(\d{2})$", value)
            if mm and ":" not in value[-6:]:
                value = value[: mm.start()] + f"{mm.group(1)}:{mm.group(2)}"
            try:
                ts = datetime.fromisoformat(value)
            except ValueError:
                return None, None
            if ts.tzinfo is not None:
                ts = ts.astimezone().replace(tzinfo=None)
            return ts, m["rest"]
        return None, None

    def parse_line(self, line: str) -> Optional[AuthEvent]:
        line = line.rstrip("\r\n")
        ts, rest = self._timestamp(line)
        if ts is None:
            return None
        sshd = SSHD_RE.search(rest)
        if not sshd:
            return None
        body = sshd["body"]
        m = FAILED_RE.search(body)
        if m:
            return AuthEvent(ts, m["ip"], m["user"], "failed", line)
        m = INVALID_RE.search(body)
        if m:
            return AuthEvent(ts, m["ip"], m["user"], "invalid", line)
        m = ACCEPTED_RE.search(body)
        if m:
            return AuthEvent(ts, m["ip"], m["user"], "accepted", line)
        return None

    def parse_lines(self, lines: Iterable[str]) -> Iterator[AuthEvent]:
        for line in lines:
            if not line.strip():
                continue
            self.stats.total += 1
            ev = self.parse_line(line)
            if ev is None:
                continue
            self.stats.parsed += 1
            if ev.outcome == "accepted":
                self.stats.accepted += 1
            else:
                self.stats.failed += 1
            yield ev


# Default settings for the SSH auth brute-force rule (kept here, not in the
# firewall DEFAULT_RULES, because it reads a different log source).
DEFAULT_AUTH_RULE = {
    "rule_id": "ssh_auth_bruteforce",
    "name": "SSH authentication brute-force",
    "description": "Many failed SSH logins from one source within the time window, read from "
                   "sshd's auth log (/var/log/auth.log). Catches password guessing even when the "
                   "firewall's connection logging is rate-limited.",
    "threshold": 5, "window_seconds": 120, "severity": "high", "params": {},
}


@dataclass
class _AuthEpisode:
    number: int
    first_seen: datetime
    last_seen: datetime
    count: int
    users: set = field(default_factory=set)


class AuthBruteForceDetector:
    """Counts failed SSH logins per source IP in a sliding window and raises a
    Detection when the count reaches the threshold. Mirrors the behaviour of the
    firewall rules (one episode per source, extended while activity continues)."""

    def __init__(self, threshold: int = 5, window_seconds: int = 120, severity: str = "high"):
        self.threshold = threshold
        self.window = timedelta(seconds=max(1, window_seconds))
        self.window_seconds = window_seconds
        self.severity = severity
        self.counters: dict = {}     # src_ip -> WindowCounter of attempt tokens
        self.episodes: dict = {}     # src_ip -> _AuthEpisode
        self._episode_seq = 0
        self._seq = 0

    def process(self, ev: AuthEvent) -> Optional[Detection]:
        # Only failed/invalid logins count; a success is context, not an attempt.
        if ev.outcome == "accepted":
            return None
        src = ev.src_ip
        counter = self.counters.get(src)
        if counter is None:
            counter = self.counters[src] = WindowCounter(self.window)
        # Each attempt must be a distinct item, so the window counts attempts
        # (not distinct usernames). A per-source sequence number guarantees that.
        self._seq += 1
        counter.add(ev.timestamp, (self._seq,))

        ep = self.episodes.get(src)
        active = ep is not None and ev.timestamp - ep.last_seen <= self.window
        if active:
            ep.count += 1
            ep.users.add(ev.user)
            if counter.distinct >= self.threshold:
                ep.last_seen = max(ep.last_seen, ev.timestamp)
            return self._detection(src, ep)

        if counter.distinct >= self.threshold:
            self._episode_seq += 1
            ep = _AuthEpisode(number=self._episode_seq, first_seen=counter.oldest or ev.timestamp,
                              last_seen=ev.timestamp, count=counter.distinct, users={ev.user})
            self.episodes[src] = ep
            return self._detection(src, ep)
        return None

    def _detection(self, src: str, ep: _AuthEpisode) -> Detection:
        users = sorted(ep.users)
        return Detection(
            rule_id="ssh_auth_bruteforce", rule_name="SSH authentication brute-force",
            severity=self.severity, src_ip=src, first_seen=ep.first_seen, last_seen=ep.last_seen,
            count=ep.count, threshold=self.threshold, window_seconds=self.window_seconds,
            episode=ep.number,
            details={"summary": f"{ep.count} failed SSH logins from {src}",
                     "usernames_tried": users[:20], "distinct_usernames": len(ep.users)},
        )

    def cleanup(self, now: datetime) -> None:
        stale = [s for s, c in self.counters.items() if c.newest and now - c.newest > self.window * 2]
        for s in stale:
            self.counters.pop(s, None)
            self.episodes.pop(s, None)
