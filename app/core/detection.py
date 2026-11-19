"""Rule-based behavioural detection engine.

Every rule keeps a sliding time window per source IP and counts *distinct*
items inside it (distinct ports, distinct connection attempts, distinct
hosts...). Counting distinct items rather than raw lines makes the rules
robust against duplicate log lines (UFW can log the same packet as both
BLOCK and AUDIT) and TCP SYN retransmissions, which reuse the same source
port.

When the distinct count reaches the rule's threshold an *episode* starts.
Further matching events extend the episode, and every change is reported as
a ``Detection`` update. The alerting module turns those updates into stored
alerts and decides whether to notify anyone.

The engine is pure Python with no database or web dependencies, so it can
be unit tested and used from the command line on its own.

Worked example (port scan rule, threshold 20, window 60 seconds)
----------------------------------------------------------------
Source 192.168.56.20 sends packets to ports 1, 2, 3 ... one per second.
For every packet the rule adds the destination port to that source's
window and throws away anything older than 60 seconds. After the 20th
different port the count reaches the threshold, an episode starts and a
Detection is returned. Each further port updates the same episode (the
count grows: 21, 22, ...). When the source goes quiet for longer than the
window, the episode ends; if it starts scanning again later, that is a new
episode.

How events flow through this file
---------------------------------
DetectionEngine.process(event)
  -> attempt_key(event)               is this a new connection attempt?
  -> rule.process(event, attempt)     for every enabled rule
       -> rule.item_for(...)          what does this rule count?
       -> WindowCounter.add(...)      sliding-window bookkeeping
       -> threshold check / episode   start or extend an episode
       -> Detection                   handed to the alerting module
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from .parser import FirewallEvent

# Severity levels from least to most serious. The position in this list is
# used to compare severities and to escalate an alert by one level.
SEVERITIES = ["low", "medium", "high", "critical"]

# Ports of services that ask for a username and password. Many new
# connections to these from one source suggests password guessing.
AUTH_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 110: "POP3", 143: "IMAP", 389: "LDAP",
    1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
}

# Default rule set, used to seed the database. Thresholds are deliberately
# conservative starting points; tune them on the Rules page using lab data.
# Each rule says: "alert when one source produces <threshold> distinct items
# within <window_seconds>". What an "item" is depends on the rule.
DEFAULT_RULES = [
    {
        "rule_id": "port_scan",
        "name": "Port scan",
        "description": "One source probes many distinct destination ports within the time window "
                       "(e.g. nmap -sS, -sT, -sU, -sF).",
        "threshold": 20, "window_seconds": 60, "severity": "high", "params": {},
    },
    {
        "rule_id": "brute_force",
        "name": "Brute-force attempt",
        "description": "One source opens many new connections to authentication services "
                       "(SSH, RDP, FTP, databases...) within the time window (e.g. hydra).",
        "threshold": 10, "window_seconds": 60, "severity": "high",
        "params": {"auth_ports": sorted(AUTH_SERVICES)},
    },
    {
        "rule_id": "denied_burst",
        "name": "Repeated denied connections",
        "description": "One source has many connection attempts blocked by the firewall within the time window.",
        "threshold": 30, "window_seconds": 60, "severity": "medium", "params": {},
    },
    {
        "rule_id": "high_rate",
        "name": "Unusual connection rate",
        "description": "One source makes an unusually high number of new connection attempts within the "
                       "time window (flooding or aggressive automated access).",
        "threshold": 100, "window_seconds": 60, "severity": "medium", "params": {},
    },
    {
        "rule_id": "host_sweep",
        "name": "Host sweep",
        "description": "One source contacts many distinct destination hosts within the time window. "
                       "Only visible when the firewall protects a network (gateway/forwarded traffic).",
        "threshold": 10, "window_seconds": 60, "severity": "medium", "params": {},
    },
    {
        "rule_id": "tcp_flag_anomaly",
        "name": "Abnormal TCP flags",
        "description": "Packets with TCP flag combinations that never occur in normal traffic "
                       "(NULL, FIN, Xmas, SYN+FIN, SYN+RST), typical of stealth scans.",
        "threshold": 3, "window_seconds": 60, "severity": "high", "params": {},
    },
    {
        "rule_id": "traffic_spike",
        "name": "Traffic spike",
        "description": "Total connection attempts in one minute exceed both the minimum (threshold) and "
                       "the multiplier times the average of the preceding baseline minutes.",
        "threshold": 200, "window_seconds": 60, "severity": "medium",
        "params": {"baseline_minutes": 10, "multiplier": 5.0},
    },
]


@dataclass
class RuleConfig:
    """The settings of one rule, as stored in the database and edited on the Rules page."""

    rule_id: str
    name: str
    threshold: int
    window_seconds: int
    severity: str = "medium"
    enabled: bool = True
    params: dict = field(default_factory=dict)   # rule-specific extras (e.g. auth_ports)

    @classmethod
    def from_dict(cls, d: dict) -> "RuleConfig":
        """Build a RuleConfig from a plain dictionary (database row or DEFAULT_RULES entry)."""
        return cls(
            rule_id=d["rule_id"], name=d.get("name", d["rule_id"]),
            threshold=int(d["threshold"]), window_seconds=int(d["window_seconds"]),
            severity=d.get("severity", "medium"), enabled=bool(d.get("enabled", True)),
            params=dict(d.get("params") or {}),
        )


@dataclass
class Detection:
    """A new or updated detection episode produced by a rule."""

    rule_id: str
    rule_name: str
    severity: str
    src_ip: str
    first_seen: datetime
    last_seen: datetime
    count: int                 # distinct items observed during the episode
    threshold: int
    window_seconds: int
    episode: int
    details: dict = field(default_factory=dict)   # evidence shown on the alert page

    @property
    def key(self) -> tuple:
        # Identifies one episode. Later updates of the same episode have the
        # same key, so the pipeline can keep only the newest one.
        return (self.rule_id, self.src_ip, self.episode)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def is_reply_like(event: FirewallEvent) -> bool:
    """UDP from a well-known port to an ephemeral port is almost always a reply.

    Example: a DNS answer comes from port 53 to a random high port on this
    machine. Without this check, many DNS replies would look like someone
    probing many different ports.
    """
    return (event.proto == "UDP" and event.src_port is not None and event.src_port < 1024
            and (event.dst_port or 0) >= 1024)


def attempt_key(event: FirewallEvent) -> Optional[tuple]:
    """Identify a *new connection attempt*, or return None.

    TCP packets carrying ACK belong to established flows and are ignored, as
    are bare RSTs. SYN packets and stealth probes (NULL/FIN/Xmas) count.
    The key includes the source port so duplicates/retransmissions collapse.

    Why this matters: when a computer opens a TCP connection, its first packet
    has only the SYN flag. Every later packet of that connection carries ACK.
    Counting only the first packet means one connection counts once, no matter
    how many packets it sends. If the same SYN appears twice in the log (a
    retransmission, or BLOCK and AUDIT lines for the same packet), it has the
    same source port, so it produces the same key and is counted once.
    """
    proto = event.proto
    if proto == "TCP":
        f = event.flag_set
        if "ACK" in f:
            return None          # part of an existing connection
        if "RST" in f and "SYN" not in f:
            return None          # a reset closes a connection, it does not open one
        return ("TCP", event.dst_ip, event.src_port, event.dst_port)
    if proto == "UDP":
        if is_reply_like(event):
            return None
        return ("UDP", event.dst_ip, event.src_port, event.dst_port)
    if proto in ("ICMP", "ICMPV6"):
        # Only requests count (ping, timestamp request); replies and error
        # messages are ignored. ICMP has no ports, so the timestamp is used
        # to tell separate requests apart.
        if event.icmp_type in (8, 13, 128):  # echo / timestamp request
            return (proto, event.dst_ip, event.icmp_type, event.timestamp)
        return None
    return None


def tcp_flag_pattern(event: FirewallEvent) -> Optional[str]:
    """Name the flag combination if it is one that normal software never sends.

    Scanning tools send these on purpose because some firewalls and hosts
    react to them differently than to a normal SYN:
      NULL     no flags at all            (nmap -sN)
      FIN      only FIN                   (nmap -sF)
      XMAS     FIN + PSH + URG            (nmap -sX)
      SYN+FIN  open and close at once     (impossible in a real connection)
      SYN+RST  open and reset at once     (impossible in a real connection)
    Returns None for normal combinations.
    """
    if event.proto != "TCP":
        return None
    f = event.flag_set
    core = f & {"SYN", "ACK", "FIN", "RST", "PSH", "URG"}   # ignore ECN flags (CWR, ECE)
    if not core:
        return "NULL"
    if {"FIN", "PSH", "URG"} <= core and "SYN" not in core:
        return "XMAS"
    if core == {"FIN"}:
        return "FIN"
    if {"SYN", "FIN"} <= core:
        return "SYN+FIN"
    if {"SYN", "RST"} <= core:
        return "SYN+RST"
    return None


class WindowCounter:
    """Distinct-item counter over a sliding time window.

    Keeps a queue of (time, item, event) in arrival order and a tally of how
    many times each item is in the queue. Adding an entry also removes the
    entries that have fallen out of the window from the front of the queue.
    ``distinct`` is then simply the number of different items in the tally.

    Example with a 60 s window: items added at 0 s (port 22), 10 s (port 80)
    and 70 s (port 443). At 70 s the entry from 0 s is older than 60 s, so it
    is removed and the distinct count is 2 (80 and 443).
    """

    # __slots__ saves memory: during live monitoring there is one counter per
    # source IP per rule, so there can be many of them.
    __slots__ = ("window", "items", "counts", "newest")

    def __init__(self, window: timedelta):
        self.window = window
        self.items: deque = deque()          # (timestamp, item, event), oldest first
        self.counts: Counter = Counter()     # item -> how many times it is in the window
        self.newest: Optional[datetime] = None

    def add(self, ts: datetime, item, event=None) -> None:
        self.items.append((ts, item, event))
        self.counts[item] += 1
        # The window ends at the newest time seen, so a slightly out-of-order
        # line cannot move the window backwards.
        if self.newest is None or ts > self.newest:
            self.newest = ts
        self.evict(self.newest)

    def evict(self, now: datetime) -> None:
        """Drop entries older than the window and update the tally."""
        limit = now - self.window
        while self.items and self.items[0][0] < limit:
            _, old, _ = self.items.popleft()
            self.counts[old] -= 1
            if self.counts[old] <= 0:
                del self.counts[old]    # no copies left, so it no longer counts as distinct

    @property
    def distinct(self) -> int:
        return len(self.counts)

    @property
    def oldest(self) -> Optional[datetime]:
        return self.items[0][0] if self.items else None


@dataclass
class Episode:
    """One continuous burst of suspicious activity from one source for one rule."""

    number: int            # running number, unique within the rule
    first_seen: datetime   # start of the window in which the threshold was reached
    last_seen: datetime    # last time the count was at or above the threshold
    items: set             # every distinct item seen during the episode
    extra: dict = field(default_factory=dict)   # rule-specific evidence (targets, flags...)


# Upper limit on items remembered per episode, so a scan of all 65,535 ports
# or a very long flood cannot use unlimited memory.
MAX_EPISODE_ITEMS = 100_000


class SlidingWindowRule:
    """Base class: counts distinct items per source within the window.

    Each concrete rule only has to say what it counts (item_for) and what
    evidence to collect (update_extra / build_details). The windowing,
    threshold check and episode handling below are shared by all of them.
    """

    def __init__(self, config: RuleConfig):
        self.config = config
        self.window = timedelta(seconds=max(1, config.window_seconds))
        self.counters: dict[str, WindowCounter] = {}   # one sliding window per source IP
        self.episodes: dict[str, Episode] = {}         # current episode per source IP
        self._episode_seq = 0

    # subclasses implement -------------------------------------------------
    def item_for(self, event: FirewallEvent, attempt: Optional[tuple]):
        """Return what this rule counts for the event, or None to ignore the event."""
        raise NotImplementedError

    def update_extra(self, extra: dict, event: FirewallEvent, item) -> None:
        """Collect rule-specific evidence for the alert details."""

    def build_details(self, episode: Episode) -> dict:
        """Turn the collected evidence into the details shown on the alert page."""
        return {}

    # shared logic ---------------------------------------------------------
    def process(self, event: FirewallEvent, attempt: Optional[tuple]) -> Optional[Detection]:
        """Feed one event to the rule. Returns a Detection if an episode started
        or was updated, otherwise None."""
        item = self.item_for(event, attempt)
        if item is None:
            return None   # this event is not relevant to this rule

        # Find (or create) the sliding window for this source and add the item.
        src = event.src_ip
        counter = self.counters.get(src)
        if counter is None:
            counter = self.counters[src] = WindowCounter(self.window)
        counter.add(event.timestamp, item, event)

        # Case 1: an episode for this source is still active (the source was
        # above the threshold less than one window ago). Extend it.
        ep = self.episodes.get(src)
        active = ep is not None and event.timestamp - ep.last_seen <= self.window
        if active:
            if len(ep.items) < MAX_EPISODE_ITEMS:
                ep.items.add(item)
            self.update_extra(ep.extra, event, item)
            # last_seen only moves forward while the source is still above
            # the threshold, so a slow trickle afterwards lets the episode end.
            if counter.distinct >= self.config.threshold:
                ep.last_seen = max(ep.last_seen, event.timestamp)
            return self._detection(src, ep)

        # Case 2: no active episode, but the threshold has just been reached.
        # Start a new episode that includes everything already in the window,
        # so the alert shows the activity that led up to the threshold too.
        if counter.distinct >= self.config.threshold:
            self._episode_seq += 1
            ep = Episode(number=self._episode_seq, first_seen=counter.oldest or event.timestamp,
                         last_seen=event.timestamp, items=set(counter.counts))
            for _, win_item, win_event in counter.items:  # evidence from the whole window
                self.update_extra(ep.extra, win_event, win_item)
            self.episodes[src] = ep
            return self._detection(src, ep)

        # Case 3: below the threshold and no active episode. Nothing to report.
        return None

    def _detection(self, src: str, ep: Episode) -> Detection:
        """Package the current state of an episode as a Detection."""
        cfg = self.config
        return Detection(
            rule_id=cfg.rule_id, rule_name=cfg.name, severity=cfg.severity, src_ip=src,
            first_seen=ep.first_seen, last_seen=ep.last_seen, count=len(ep.items),
            threshold=cfg.threshold, window_seconds=cfg.window_seconds, episode=ep.number,
            details=self.build_details(ep),
        )

    def cleanup(self, now: datetime) -> None:
        """Forget idle sources so memory stays bounded during live monitoring.

        A source that has sent nothing for two windows cannot affect any
        current count, so its window and episode can be thrown away.
        """
        stale = [s for s, c in self.counters.items() if c.newest and now - c.newest > self.window * 2]
        for s in stale:
            del self.counters[s]
        stale_ep = [s for s, e in self.episodes.items() if now - e.last_seen > self.window * 2]
        for s in stale_ep:
            del self.episodes[s]

    def flush(self) -> list:
        # Called at the end of a file. Window rules report as they go, so
        # there is nothing left over. (The traffic spike rule overrides this.)
        return []


def _sample(values, limit=40):
    """Return up to ``limit`` values in sorted order, for display on the alert page."""
    vals = sorted(v for v in values if v is not None)
    return vals[:limit]


# --------------------------------------------------------------------------
# the individual rules
# --------------------------------------------------------------------------
class PortScanRule(SlidingWindowRule):
    """Counts distinct destination ports. Many ports from one source = port scan."""

    def item_for(self, event, attempt):
        if attempt is None or event.dst_port is None:
            return None
        return event.dst_port

    def update_extra(self, extra, event, item):
        # Which machines were scanned (capped at 50 to keep the alert small).
        targets = extra.setdefault("targets", set())
        if len(targets) < 50:
            targets.add(event.dst_ip)
        # What kind of probe packets were used, to name the scan type.
        kinds = extra.setdefault("kinds", Counter())
        pattern = tcp_flag_pattern(event)
        if event.proto == "UDP":
            kinds["UDP"] += 1
        elif pattern:
            kinds[pattern] += 1          # e.g. "XMAS" for nmap -sX
        else:
            kinds["SYN"] += 1            # normal connection attempts (nmap -sS / -sT)
        # How many probes the firewall blocked or allowed.
        actions = extra.setdefault("actions", Counter())
        actions[event.action] += 1

    def build_details(self, ep):
        kinds = ep.extra.get("kinds", Counter())
        return {
            "summary": f"{len(ep.items)} distinct destination ports probed",
            "ports_sample": _sample(ep.items),
            "targets": sorted(ep.extra.get("targets", set())),
            # The most common probe type names the scan, e.g. "SYN scan".
            "scan_type": kinds.most_common(1)[0][0] + " scan" if kinds else "unknown",
            "actions": dict(ep.extra.get("actions", {})),
        }


class BruteForceRule(SlidingWindowRule):
    """Counts new TCP connections to authentication ports (SSH, RDP, FTP...).

    Password-guessing tools open a new connection for every few guesses, and
    each new connection uses a new source port, so each one counts once.
    """

    def __init__(self, config):
        super().__init__(config)
        # The list of ports can be changed on the Rules page.
        ports = config.params.get("auth_ports") or sorted(AUTH_SERVICES)
        self.auth_ports = {int(p) for p in ports}

    def item_for(self, event, attempt):
        if attempt is None or event.proto != "TCP" or event.dst_port not in self.auth_ports:
            return None
        # (target, source port, service port) identifies one connection attempt.
        return (event.dst_ip, event.src_port, event.dst_port)

    def update_extra(self, extra, event, item):
        services = extra.setdefault("services", Counter())
        services[f"{AUTH_SERVICES.get(event.dst_port, 'port')} ({event.dst_port})"] += 1
        targets = extra.setdefault("targets", set())
        if len(targets) < 50:
            targets.add(event.dst_ip)
        actions = extra.setdefault("actions", Counter())
        actions[event.action] += 1

    def build_details(self, ep):
        return {
            "summary": f"{len(ep.items)} connection attempts to authentication services",
            "services": dict(ep.extra.get("services", {})),
            "targets": sorted(ep.extra.get("targets", set())),
            "actions": dict(ep.extra.get("actions", {})),
        }


class DeniedBurstRule(SlidingWindowRule):
    """Counts connection attempts that the firewall blocked."""

    def item_for(self, event, attempt):
        if attempt is None or event.action != "DENY":
            return None
        return attempt

    def update_extra(self, extra, event, item):
        ports = extra.setdefault("ports", Counter())
        ports[event.dst_port] += 1

    def build_details(self, ep):
        ports = ep.extra.get("ports", Counter())
        return {
            "summary": f"{len(ep.items)} connection attempts blocked by the firewall",
            "top_ports": [[p, c] for p, c in ports.most_common(10)],
        }


class HighRateRule(SlidingWindowRule):
    """Counts all new connection attempts, allowed or blocked.

    Catches floods and aggressive automated access even when every
    connection goes to the same allowed port (which the port scan and
    denied-connection rules would not notice).
    """

    def item_for(self, event, attempt):
        return attempt

    def update_extra(self, extra, event, item):
        ports = extra.setdefault("ports", Counter())
        ports[event.dst_port] += 1
        # Remember the highest number of attempts seen in a single window.
        peak = extra.get("peak", 0)
        current = self.counters[event.src_ip].distinct
        if current > peak:
            extra["peak"] = current

    def build_details(self, ep):
        ports = ep.extra.get("ports", Counter())
        # Length of the episode in minutes (at least one second, to avoid
        # dividing by zero).
        minutes = max((ep.last_seen - ep.first_seen).total_seconds() / 60, 1 / 60)
        return {
            "summary": f"{len(ep.items)} new connection attempts "
                       f"(peak {ep.extra.get('peak', len(ep.items))} per {self.config.window_seconds}s)",
            "rate_per_minute": round(len(ep.items) / max(minutes, 1), 1),
            "top_ports": [[p, c] for p, c in ports.most_common(10)],
        }


class HostSweepRule(SlidingWindowRule):
    """Counts distinct destination hosts. One source contacting many machines
    in a short time is mapping the network.

    A firewall that protects a single machine only sees traffic for that
    machine, so this rule is only useful when the firewall is a gateway.
    """

    def item_for(self, event, attempt):
        if attempt is None:
            return None
        return event.dst_ip

    def build_details(self, ep):
        return {"summary": f"{len(ep.items)} distinct hosts contacted",
                "targets_sample": sorted(ep.items)[:40]}


class TcpFlagAnomalyRule(SlidingWindowRule):
    """Counts packets with abnormal TCP flag combinations (see tcp_flag_pattern).

    These never appear in normal traffic, so the threshold is low (3 by default).
    This is the one signature-style rule; the others are behavioural.
    """

    def item_for(self, event, attempt):
        pattern = tcp_flag_pattern(event)
        if pattern is None:
            return None
        return (event.dst_ip, event.src_port, event.dst_port, pattern)

    def update_extra(self, extra, event, item):
        patterns = extra.setdefault("patterns", Counter())
        patterns[item[3]] += 1    # item[3] is the pattern name

    def build_details(self, ep):
        return {"summary": f"{len(ep.items)} packets with abnormal TCP flag combinations",
                "patterns": dict(ep.extra.get("patterns", {}))}


class TrafficSpikeRule:
    """Global rule: compares each minute's attempts against a moving baseline.

    Unlike the other rules this one does not look at single sources. It
    counts all new connection attempts per clock minute and compares each
    finished minute with the average of the previous minutes (the baseline).
    A minute is a spike if it is both above the fixed minimum (threshold) and
    more than ``multiplier`` times the baseline. The fixed minimum stops a
    quiet network from alerting when, say, 2 connections jump to 12.

    Its alerts use "*" as the source, because many sources can contribute.
    The top contributing sources are listed in the alert details.
    """

    def __init__(self, config: RuleConfig):
        self.config = config
        self.baseline_minutes = int(config.params.get("baseline_minutes", 10))
        self.multiplier = float(config.params.get("multiplier", 5.0))
        self.bucket: Optional[datetime] = None        # the minute currently being counted
        self.bucket_items: set = set()                # distinct attempts in that minute
        self.bucket_sources: Counter = Counter()      # attempts per source in that minute
        # Counts of the previous minutes; maxlen drops the oldest automatically.
        self.history: deque = deque(maxlen=max(1, self.baseline_minutes))
        self._episode_seq = 0
        self._last_spike: Optional[datetime] = None

    def process(self, event: FirewallEvent, attempt: Optional[tuple]) -> Optional[Detection]:
        if attempt is None:
            return None
        # Round the time down to the minute, e.g. 14:02:37 -> 14:02:00.
        bucket = event.timestamp.replace(second=0, microsecond=0)
        result = None
        if self.bucket is None:
            self.bucket = bucket
        elif bucket > self.bucket:
            # A new minute has started, so the previous one is complete.
            result = self._finalize()
            # Minutes with no traffic at all still count towards the
            # baseline, as zeros.
            gap = int((bucket - self.bucket).total_seconds() // 60) - 1
            for _ in range(min(max(gap, 0), self.baseline_minutes)):
                self.history.append(0)
            self.bucket = bucket
        # Events from an earlier minute that arrive late are ignored.
        if bucket == self.bucket:
            self.bucket_items.add((event.src_ip,) + attempt)
            self.bucket_sources[event.src_ip] += 1
        return result

    def _finalize(self) -> Optional[Detection]:
        """Close the current minute: compare it with the baseline, then add it to the history."""
        count = len(self.bucket_items)
        detection = None
        # Need a few minutes of history before a baseline means anything.
        enough_history = len(self.history) >= min(3, self.baseline_minutes)
        if enough_history:
            baseline = sum(self.history) / len(self.history)
            # max(baseline, 1.0) avoids "5 times zero" being zero on a silent network.
            if count >= self.config.threshold and count >= self.multiplier * max(baseline, 1.0):
                start = self.bucket
                # Spikes in consecutive minutes belong to the same episode.
                if not self._last_spike or start - self._last_spike > timedelta(minutes=1):
                    self._episode_seq += 1
                self._last_spike = start
                cfg = self.config
                detection = Detection(
                    rule_id=cfg.rule_id, rule_name=cfg.name, severity=cfg.severity, src_ip="*",
                    first_seen=start, last_seen=start + timedelta(seconds=59), count=count,
                    threshold=cfg.threshold, window_seconds=60, episode=self._episode_seq,
                    details={
                        "summary": f"{count} connection attempts in one minute "
                                   f"(baseline {baseline:.1f}/min, x{count / max(baseline, 1.0):.1f})",
                        "baseline_per_minute": round(baseline, 1),
                        "top_sources": [[s, c] for s, c in self.bucket_sources.most_common(5)],
                    },
                )
        # The finished minute becomes part of the baseline (spike minutes
        # included, so a lasting change in traffic becomes the new normal).
        self.history.append(count)
        self.bucket_items = set()
        self.bucket_sources = Counter()
        return detection

    def cleanup(self, now: datetime) -> None:
        pass   # memory is already bounded by the history length

    def flush(self) -> list:
        # At the end of a file the last minute has not been closed by a later
        # event, so close it here.
        if self.bucket is None:
            return []
        d = self._finalize()
        self.bucket = None
        return [d] if d else []


# Maps the rule_id stored in the database to the class that implements it.
RULE_CLASSES = {
    "port_scan": PortScanRule,
    "brute_force": BruteForceRule,
    "denied_burst": DeniedBurstRule,
    "high_rate": HighRateRule,
    "host_sweep": HostSweepRule,
    "tcp_flag_anomaly": TcpFlagAnomalyRule,
    "traffic_spike": TrafficSpikeRule,
}


class DetectionEngine:
    """Runs every enabled rule over a stream of events.

    One engine is created per analysis (per uploaded file, or per live
    monitoring session), so the windows of different analyses never mix.
    """

    # How often (in events) idle sources are cleaned out of memory.
    CLEANUP_EVERY = 5000

    def __init__(self, rules: list):
        # Build one rule object per enabled rule. Unknown or disabled rules are skipped.
        self.rules = []
        for r in rules:
            cfg = r if isinstance(r, RuleConfig) else RuleConfig.from_dict(r)
            cls = RULE_CLASSES.get(cfg.rule_id)
            if cls is not None and cfg.enabled:
                self.rules.append(cls(cfg))
        self.rule_configs = {r.config.rule_id: r.config for r in self.rules}
        self.processed = 0

    def process(self, event: FirewallEvent) -> list:
        """Run one event through all rules and return any detections it caused."""
        # Work out once whether this is a new connection attempt; every rule uses the answer.
        attempt = attempt_key(event)
        out = []
        for rule in self.rules:
            d = rule.process(event, attempt)
            if d is not None:
                out.append(d)
        self.processed += 1
        if self.processed % self.CLEANUP_EVERY == 0:
            for rule in self.rules:
                rule.cleanup(event.timestamp)
        return out

    def flush(self) -> list:
        """Called when the input ends; returns detections that were still pending."""
        out = []
        for rule in self.rules:
            out.extend(rule.flush())
        return out


def default_rule_configs() -> list:
    """The built-in rules as RuleConfig objects (used by the command-line analyzer)."""
    return [RuleConfig.from_dict(r) for r in DEFAULT_RULES]
