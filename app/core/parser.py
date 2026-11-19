"""Log parsing module.

Converts raw UFW (Uncomplicated Firewall) log lines into normalized
``FirewallEvent`` records. This is the only module that knows the log
format, so supporting another firewall (pfSense, Windows Firewall) only
requires adding a new parser that produces the same ``FirewallEvent``.

Supported line formats
----------------------
Classic syslog (no year in the timestamp)::

    Oct 19 14:02:11 host kernel: [ 5123.456789] [UFW BLOCK] IN=enp0s8 OUT= ... SRC=... DST=... PROTO=TCP SPT=1 DPT=2 ... SYN URGP=0

ISO 8601 / RFC 3339 timestamps (rsyslog default on newer Ubuntu releases)::

    2026-10-19T14:02:11.123456+03:00 host kernel: [UFW BLOCK] IN=enp0s8 OUT= ...

How a line is read
------------------
1. Look for the "[UFW ...]" tag. No tag means the line is some other system
   message (cron, sshd, systemd) and it is skipped.
2. Read the timestamp and host name at the start of the line, trying the
   classic syslog format first and the ISO format second.
3. Everything after the tag is a list of KEY=value pairs (SRC=, DST=,
   PROTO=, SPT=, DPT=...). These are collected into a dictionary.
4. For TCP, the flags (SYN, ACK, FIN...) appear as bare words without "="
   and are picked out separately.
5. The values are packed into a FirewallEvent object, which is what the rest
   of the system works with.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable, Iterator, Optional

# Month abbreviations used by syslog, mapped to month numbers (Jan -> 1 ...).
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

# Regular expressions for the two timestamp styles. Each one captures the
# timestamp parts, the host name and the rest of the line.
#   SYSLOG_RE matches: "Oct 19 14:02:11 host ..."
#   ISO_RE matches:    "2026-10-19T14:02:11.123456+03:00 host ..."
SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<rest>.*)$")
ISO_RE = re.compile(
    r"^(?P<iso>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<host>\S+)\s+(?P<rest>.*)$")

# Finds the UFW tag, e.g. "[UFW BLOCK]" or "[UFW LIMIT BLOCK]", and captures the action words.
UFW_TAG_RE = re.compile(r"\[UFW (?P<action>[A-Z ]+?)\]")

# Finds every KEY=value pair in the line. The value may be empty (e.g. "OUT=").
KV_RE = re.compile(r"\b([A-Z]+)=(\S*)")

# All TCP flag names the kernel can print. Order does not matter for detection.
TCP_FLAGS = ("CWR", "ECE", "URG", "ACK", "PSH", "RST", "SYN", "FIN")

# UFW log prefix -> normalized action.
# The rest of the system only deals with three actions:
#   DENY  - the firewall dropped the packet
#   ALLOW - the packet matched an allow rule
#   AUDIT - logged for information only (UFW "high"/"full" logging levels)
ACTION_MAP = {
    "BLOCK": "DENY",
    "LIMIT BLOCK": "DENY",   # blocked by a "ufw limit" rate-limiting rule
    "ALLOW": "ALLOW",
    "AUDIT": "AUDIT",
    "AUDIT INVALID": "AUDIT",
}

MAX_RAW = 600  # characters of the raw line kept for the event explorer


@dataclass
class FirewallEvent:
    """A single normalized firewall log event.

    Every module after the parser (filtering, detection, storage, reports)
    works with this object and never looks at the original text again,
    except for showing the raw line to the analyst.
    """

    timestamp: datetime
    action: str                      # ALLOW | DENY | AUDIT
    ufw_action: str                  # original UFW tag, e.g. "LIMIT BLOCK"
    src_ip: str                      # who sent the packet
    dst_ip: str                      # who it was sent to
    proto: str                       # TCP | UDP | ICMP | ICMPv6 | other
    src_port: Optional[int] = None   # None for protocols without ports (ICMP)
    dst_port: Optional[int] = None
    iface_in: str = ""               # network interface the packet arrived on
    iface_out: str = ""              # network interface the packet left through
    direction: str = "in"            # in | out | forward
    length: Optional[int] = None     # packet length in bytes
    ttl: Optional[int] = None        # time-to-live (hop limit for IPv6)
    flags: tuple = field(default_factory=tuple)   # TCP flags, e.g. ("SYN",)
    icmp_type: Optional[int] = None  # e.g. 8 = echo request (ping)
    hostname: str = ""               # the machine that wrote the log line
    raw: str = ""                    # the original line, for display

    @property
    def flag_set(self) -> frozenset:
        # A set makes checks like "is ACK among the flags?" fast and simple.
        return frozenset(self.flags)

    def to_dict(self) -> dict:
        """Convert to a dictionary that matches the columns of the events table.

        Used for fast bulk inserts into the database. Flags become one string
        ("SYN ACK") and the raw line is shortened to MAX_RAW characters.
        """
        return {
            "timestamp": self.timestamp,
            "action": self.action,
            "ufw_action": self.ufw_action,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "proto": self.proto,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "iface_in": self.iface_in,
            "iface_out": self.iface_out,
            "direction": self.direction,
            "length": self.length,
            "ttl": self.ttl,
            "flags": " ".join(self.flags),
            "icmp_type": self.icmp_type,
            "hostname": self.hostname,
            "raw": self.raw[:MAX_RAW],
        }


class ParseError(ValueError):
    """Raised for a line that looks like a UFW entry but cannot be parsed."""


@dataclass
class ParseStats:
    """Counters shown on the analysis run page, so the analyst can see how
    much of the file was usable."""

    total: int = 0        # non-empty lines read
    parsed: int = 0       # firewall lines turned into events
    not_ufw: int = 0      # lines that are not firewall entries (ignored)
    malformed: int = 0    # UFW lines that could not be parsed

    def as_dict(self) -> dict:
        return {"total": self.total, "parsed": self.parsed,
                "not_ufw": self.not_ufw, "malformed": self.malformed}


def _to_int(value: Optional[str]) -> Optional[int]:
    """Turn a text value into a number, or None if it is missing or not a number.

    Log lines can be damaged or truncated, so a bad value must not crash the parser.
    """
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return None


class UFWParser:
    """Parser for UFW kernel log lines.

    ``reference_time`` is used to infer the year for classic syslog lines,
    which do not contain one. If the inferred date lies more than a day in
    the future, the previous year is assumed (e.g. a December log read in
    January).
    """

    def __init__(self, reference_time: Optional[datetime] = None):
        # reference_time is normally None, meaning "now". Tests pass a fixed
        # time so their results do not depend on when they are run.
        self.reference_time = reference_time
        self.stats = ParseStats()

    # -- timestamp helpers -------------------------------------------------
    def _syslog_time(self, mon: str, day: str, time_s: str) -> datetime:
        """Build a datetime from "Oct", "19", "14:02:11".

        Syslog lines have no year, so the current year is assumed. If that
        puts the event more than a day in the future, the line must be from
        last year (for example a December log analysed in January).
        """
        ref = self.reference_time or datetime.now()
        month = MONTHS.get(mon)
        if month is None:
            raise ParseError(f"unknown month {mon!r}")
        h, m, s = (int(x) for x in time_s.split(":"))
        ts = datetime(ref.year, month, int(day), h, m, s)
        if ts > ref + timedelta(days=1):
            ts = ts.replace(year=ref.year - 1)
        return ts

    @staticmethod
    def _iso_time(value: str) -> datetime:
        """Build a datetime from an ISO 8601 timestamp such as
        "2026-10-19T14:02:11.123456+03:00"."""
        value = value.replace(" ", "T", 1)
        # "Z" means UTC; older Python versions only understand "+00:00".
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        # Python < 3.11 cannot parse "+0300" style offsets
        m = re.search(r"([+-]\d{2})(\d{2})$", value)
        if m and ":" not in value[-6:]:
            value = value[: m.start()] + f"{m.group(1)}:{m.group(2)}"
        ts = datetime.fromisoformat(value)
        if ts.tzinfo is not None:
            # store as naive local time so all timestamps are comparable
            # (syslog timestamps carry no time zone, so everything is kept
            # in the machine's local time).
            ts = ts.astimezone().replace(tzinfo=None)
        return ts

    # -- main API ----------------------------------------------------------
    def parse_line(self, line: str) -> Optional[FirewallEvent]:
        """Parse one line. Returns ``None`` for non-UFW lines.

        Raises ``ParseError`` for UFW lines that cannot be parsed.
        """
        line = line.rstrip("\r\n")

        # Step 1: is this a firewall line at all?
        tag = UFW_TAG_RE.search(line)
        if not tag:
            return None

        # Step 2: read the timestamp. Try classic syslog, then ISO 8601.
        m = SYSLOG_RE.match(line)
        if m:
            try:
                ts = self._syslog_time(m["mon"], m["day"], m["time"])
            except (ValueError, ParseError) as exc:
                raise ParseError(f"bad syslog timestamp: {exc}") from exc
        else:
            m = ISO_RE.match(line)
            if not m:
                raise ParseError("no recognizable timestamp")
            try:
                ts = self._iso_time(m["iso"])
            except ValueError as exc:
                raise ParseError(f"bad ISO timestamp: {exc}") from exc
        hostname = m["host"]

        # Step 3: collect the KEY=value pairs that follow the UFW tag.
        body = line[tag.end():]
        kv: dict[str, str] = {}
        for key, value in KV_RE.findall(body):
            # UDP lines contain LEN twice: first the IP packet length, then
            # the UDP length. setdefault keeps the first one.
            kv.setdefault(key, value)  # keep first occurrence (IP LEN, not UDP LEN)

        # Without a source and destination address the line is useless.
        src, dst = kv.get("SRC"), kv.get("DST")
        if not src or not dst:
            raise ParseError("missing SRC or DST")

        # Map the UFW tag to ALLOW / DENY / AUDIT. Unknown tags fall back to
        # a best guess based on the words they contain.
        ufw_action = tag["action"].strip()
        action = ACTION_MAP.get(ufw_action, "AUDIT" if "AUDIT" in ufw_action else
                                "DENY" if "BLOCK" in ufw_action else "ALLOW")

        # Protocol name. The kernel prints IGMP as protocol number 2.
        proto = kv.get("PROTO", "other").upper()
        if proto in ("2", "IGMP"):
            proto = "IGMP"

        # Step 4: TCP flags.
        flags: tuple = ()
        if proto == "TCP":
            # flags are bare words between RES=0x.. and URGP=
            # e.g. "... WINDOW=1024 RES=0x00 SYN URGP=0". Only that part of
            # the line is searched, so words elsewhere cannot be mistaken
            # for flags.
            seg = body
            res = seg.find(" RES=")
            urgp = seg.find(" URGP=")
            if res != -1:
                seg = seg[res:urgp if urgp > res else None]
            words = set(seg.split())
            flags = tuple(f for f in TCP_FLAGS if f in words)

        # Direction of travel, from which interface fields are filled in:
        #   only IN=  -> packet arriving at this machine ("in")
        #   only OUT= -> packet leaving this machine ("out")
        #   both      -> packet routed through this machine ("forward")
        iface_in, iface_out = kv.get("IN", ""), kv.get("OUT", "")
        if iface_in and iface_out:
            direction = "forward"
        elif iface_out:
            direction = "out"
        else:
            direction = "in"

        # Step 5: build the event. Missing or invalid numbers become None.
        return FirewallEvent(
            timestamp=ts,
            action=action,
            ufw_action=ufw_action,
            src_ip=src,
            dst_ip=dst,
            proto=proto,
            src_port=_to_int(kv.get("SPT")),
            dst_port=_to_int(kv.get("DPT")),
            iface_in=iface_in,
            iface_out=iface_out,
            direction=direction,
            length=_to_int(kv.get("LEN")),
            ttl=_to_int(kv.get("TTL") or kv.get("HOPLIMIT")),  # IPv6 calls it HOPLIMIT
            flags=flags,
            icmp_type=_to_int(kv.get("TYPE")) if proto.startswith("ICMP") else None,
            hostname=hostname,
            raw=line,
        )

    def parse_lines(self, lines: Iterable[str]) -> Iterator[FirewallEvent]:
        """Parse many lines, updating ``self.stats``; never raises.

        This is a generator: it hands back one event at a time instead of
        building a list, so even a very large log file uses little memory.
        Bad lines are counted and skipped so one damaged line never stops
        the analysis of the whole file.
        """
        for line in lines:
            if not line.strip():
                continue  # blank lines are not counted at all
            self.stats.total += 1
            try:
                event = self.parse_line(line)
            except ParseError:
                self.stats.malformed += 1
                continue
            if event is None:
                self.stats.not_ufw += 1
                continue
            self.stats.parsed += 1
            yield event
