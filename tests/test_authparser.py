"""Tests for SSH auth-log parsing and brute-force detection (app/core/authparser.py)."""

from datetime import datetime

from app.core.authparser import AuthBruteForceDetector, AuthLogParser

REF = datetime(2026, 11, 16, 2, 0, 0)

FAILED = "Nov 16 02:00:01 kali sshd[1234]: Failed password for testuser from 192.168.56.1 port 50111 ssh2"
INVALID = "Nov 16 02:00:02 kali sshd[1234]: Invalid user admin from 192.168.56.1 port 50112"
FAILED_INVALID = "Nov 16 02:00:03 kali sshd[1234]: Failed password for invalid user root from 192.168.56.1 port 50113 ssh2"
ACCEPTED = "Nov 16 02:00:30 kali sshd[1250]: Accepted password for george from 192.168.56.20 port 50120 ssh2"
CRON = "Nov 16 02:00:04 kali CRON[9]: (root) CMD (true)"
ISO = "2026-11-16T02:00:05.123456+02:00 kali sshd[1234]: Failed password for bob from 10.0.0.9 port 2 ssh2"


def test_parse_failed_invalid_accepted():
    p = AuthLogParser(REF)
    assert p.parse_line(FAILED).outcome == "failed"
    assert p.parse_line(FAILED).src_ip == "192.168.56.1"
    assert p.parse_line(INVALID).outcome == "invalid"
    assert p.parse_line(FAILED_INVALID).user == "root"
    assert p.parse_line(ACCEPTED).outcome == "accepted"
    assert p.parse_line(ISO).src_ip == "10.0.0.9"


def test_non_sshd_lines_ignored():
    assert AuthLogParser(REF).parse_line(CRON) is None
    assert AuthLogParser(REF).parse_line("random text") is None


def test_stats_count_outcomes():
    p = AuthLogParser(REF)
    list(p.parse_lines([FAILED, INVALID, ACCEPTED, CRON, ""]))
    assert p.stats.as_dict() == {"total": 4, "parsed": 3, "failed": 2, "accepted": 1}


def _lines(n, ip="192.168.56.1", start=0):
    return [f"Nov 16 02:00:{start+i:02d} kali sshd[1]: Failed password for testuser from {ip} port {5000+i} ssh2"
            for i in range(n)]


def test_brute_force_fires_above_threshold():
    det = AuthBruteForceDetector(threshold=5, window_seconds=120)
    p = AuthLogParser(REF)
    out = []
    for ev in p.parse_lines(_lines(10)):
        d = det.process(ev)
        if d:
            out.append(d)
    assert out                      # at least one detection
    last = out[-1]
    assert last.rule_id == "ssh_auth_bruteforce" and last.src_ip == "192.168.56.1"
    assert last.count >= 5


def test_below_threshold_is_quiet():
    det = AuthBruteForceDetector(threshold=5, window_seconds=120)
    p = AuthLogParser(REF)
    assert [det.process(ev) for ev in p.parse_lines(_lines(4))] == [None, None, None, None]


def test_successful_logins_do_not_count():
    det = AuthBruteForceDetector(threshold=3, window_seconds=120)
    p = AuthLogParser(REF)
    accepted = [ACCEPTED.replace("02:00:30", f"02:00:0{i}") for i in range(5)]
    assert all(det.process(ev) is None for ev in p.parse_lines(accepted))
