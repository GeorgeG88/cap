"""Tests for the log parser (app/core/parser.py).

Checks both timestamp formats, field extraction, the year guess for
syslog lines, and that bad or unrelated lines are counted, not fatal.
"""
from datetime import datetime

import pytest

from app.core.parser import ParseError, UFWParser

REF = datetime(2026, 10, 19, 23, 0, 0)

SYSLOG = ("Oct 19 14:02:11 fw kernel: [ 5123.456789] [UFW BLOCK] IN=enp0s8 OUT= "
          "MAC=08:00:27:aa:bb:cc:08:00:27:dd:ee:ff:08:00 SRC=192.168.56.20 DST=192.168.56.10 LEN=44 "
          "TOS=0x00 PREC=0x00 TTL=52 ID=1234 PROTO=TCP SPT=54321 DPT=443 WINDOW=1024 RES=0x00 SYN URGP=0")
ISO = ("2026-10-19T14:02:11.123456+00:00 fw kernel: [UFW ALLOW] IN=enp0s8 OUT= SRC=192.168.56.30 "
       "DST=192.168.56.10 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=1 DF PROTO=TCP SPT=40000 DPT=80 "
       "WINDOW=64240 RES=0x00 SYN URGP=0")
UDP = ("Oct 19 14:02:12 fw kernel: [UFW AUDIT] IN=enp0s3 OUT= SRC=8.8.8.8 DST=10.0.2.15 LEN=100 "
       "TOS=0x00 PREC=0x00 TTL=117 ID=9 PROTO=UDP SPT=53 DPT=51000 LEN=80")


# A classic syslog line: every field is read correctly.
def test_syslog_line():
    e = UFWParser(REF).parse_line(SYSLOG)
    assert e.timestamp == datetime(2026, 10, 19, 14, 2, 11)
    assert (e.action, e.ufw_action) == ("DENY", "BLOCK")
    assert (e.src_ip, e.dst_ip, e.proto) == ("192.168.56.20", "192.168.56.10", "TCP")
    assert (e.src_port, e.dst_port) == (54321, 443)
    assert e.flags == ("SYN",)
    assert e.direction == "in" and e.iface_in == "enp0s8"
    assert e.ttl == 52 and e.length == 44


# ISO timestamps with a time zone are converted to local time without zone info.
def test_iso_line_converted_to_local_naive():
    e = UFWParser(REF).parse_line(ISO)
    assert e.action == "ALLOW" and e.dst_port == 80
    assert e.timestamp.tzinfo is None


# UDP lines contain LEN twice; the first (IP packet length) must be kept.
def test_udp_keeps_first_len():
    e = UFWParser(REF).parse_line(UDP)
    assert e.proto == "UDP" and e.length == 100 and e.flags == ()


# A "Dec 31" line read on 2 January belongs to the previous year.
def test_year_rollover():
    e = UFWParser(datetime(2027, 1, 2)).parse_line(SYSLOG.replace("Oct 19", "Dec 31"))
    assert e.timestamp.year == 2026


# Other system messages return None (skipped, not an error).
def test_non_ufw_line_is_ignored():
    assert UFWParser(REF).parse_line("Oct 19 14:00:00 fw CRON[1]: (root) CMD (true)") is None


# A UFW line without a source address cannot be used.
def test_malformed_ufw_line_raises():
    with pytest.raises(ParseError):
        UFWParser(REF).parse_line("Oct 19 14:00:00 fw kernel: [UFW BLOCK] IN=eth0 OUT= DST=1.2.3.4")


# Blank lines are not counted; good, unrelated and broken lines each have their own counter.
def test_parse_lines_counts_everything():
    p = UFWParser(REF)
    lines = [SYSLOG, ISO, "", "random text", "[UFW BLOCK] no timestamp SRC=1.1.1.1 DST=2.2.2.2"]
    events = list(p.parse_lines(lines))
    assert len(events) == 2
    assert p.stats.as_dict() == {"total": 4, "parsed": 2, "not_ufw": 1, "malformed": 1}
