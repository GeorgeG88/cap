"""Tests for the detection rules and filters (app/core/detection.py, filters.py).

Events are built directly with ev() from conftest.py, so each test states
exactly what traffic it feeds in. Every rule has a positive test (it fires)
and, where it matters, a negative test (it stays quiet).
"""
from app.core.detection import (DetectionEngine, RuleConfig, attempt_key, default_rule_configs,
                                tcp_flag_pattern)
from app.core.filters import EventFilter, FilterConfig, parse_networks
from conftest import ev


# A detection engine with only one rule enabled (optionally with changed settings).
def engine_with(rule_id, **overrides):
    cfgs = [c for c in default_rule_configs() if c.rule_id == rule_id]
    for k, v in overrides.items():
        setattr(cfgs[0], k, v)
    return DetectionEngine(cfgs)


# Feed events through the engine and return the final state of each episode.
def run(engine, events):
    out = {}
    for e in events:
        for d in engine.process(e):
            out[d.key] = d
    for d in engine.flush():
        out[d.key] = d
    return list(out.values())


# -- helpers ----------------------------------------------------------------
# Only new connection attempts count: SYN yes; ACK, bare RST and DNS replies no.
def test_attempt_key_ignores_established_and_replies():
    assert attempt_key(ev(flags=("SYN",))) is not None
    assert attempt_key(ev(flags=("ACK", "PSH"))) is None
    assert attempt_key(ev(flags=("RST",))) is None
    assert attempt_key(ev(proto="UDP", spt=53, dpt=51000, flags=())) is None
    assert attempt_key(ev(proto="UDP", spt=51000, dpt=161, flags=())) is not None


# Each abnormal TCP flag combination is recognised; a normal SYN is not.
def test_flag_patterns():
    assert tcp_flag_pattern(ev(flags=())) == "NULL"
    assert tcp_flag_pattern(ev(flags=("URG", "PSH", "FIN"))) == "XMAS"
    assert tcp_flag_pattern(ev(flags=("FIN",))) == "FIN"
    assert tcp_flag_pattern(ev(flags=("SYN", "FIN"))) == "SYN+FIN"
    assert tcp_flag_pattern(ev(flags=("SYN",))) is None


# -- rules ------------------------------------------------------------------
# 100 ports in 10 seconds: one episode that counts all 100 ports.
def test_port_scan_detected_once_per_episode():
    events = [ev(seconds=i * 0.1, dpt=1 + i) for i in range(100)]
    dets = run(engine_with("port_scan"), events)
    assert len(dets) == 1
    assert dets[0].count == 100 and dets[0].src_ip == "10.0.0.5"


# 19 ports is below the threshold of 20. 30 ports spread over 150 seconds
# never has 20 inside one 60-second window. Neither should alert.
def test_port_scan_below_threshold_or_spread_out():
    assert run(engine_with("port_scan"), [ev(seconds=i, dpt=i + 1) for i in range(19)]) == []
    # 30 ports, but one every 5 seconds: never 20 within 60 s
    assert run(engine_with("port_scan"), [ev(seconds=i * 5, dpt=i + 1) for i in range(30)]) == []


# The same SYN logged 50 times (same source port) is one attempt, not 50.
def test_duplicates_and_retransmissions_do_not_inflate_counts():
    # same packet repeated (e.g. BLOCK + AUDIT lines, SYN retransmits) counts once
    events = [ev(seconds=i * 0.01, spt=40000, dpt=22, action="ALLOW") for i in range(50)]
    assert run(engine_with("brute_force"), events) == []


# 15 new SSH connections in 30 seconds trigger the brute-force rule.
def test_brute_force_on_ssh():
    events = [ev(seconds=i * 2, spt=40000 + i, dpt=22, action="ALLOW") for i in range(15)]
    dets = run(engine_with("brute_force"), events)
    assert len(dets) == 1 and "SSH (22)" in dets[0].details["services"]


# Many connections to a web port (80) are not password guessing.
def test_brute_force_ignores_non_auth_ports():
    events = [ev(seconds=i, spt=40000 + i, dpt=80, action="ALLOW") for i in range(30)]
    assert run(engine_with("brute_force"), events) == []


# A port scan that touches several auth ports a few times each is not a brute
# force: the rule counts per destination port, so no single port reaches the
# threshold. Many connections to ONE port is a brute force and does fire.
def test_brute_force_counts_per_port_not_across_ports():
    ports = [21, 22, 23, 110, 143, 389, 1433, 3306, 3389, 5432, 5900]
    spread = [ev(seconds=i, spt=40000 + i, dpt=p, action="ALLOW") for i, p in enumerate(ports * 2)]
    assert run(engine_with("brute_force"), spread) == []
    focused = [ev(seconds=i, spt=50000 + i, dpt=22, action="ALLOW") for i in range(15)]
    dets = run(engine_with("brute_force"), focused)
    assert len(dets) == 1 and dets[0].count == 15 and dets[0].src_ip == "10.0.0.5"


# The same traffic alerts when blocked, but not when allowed.
def test_denied_burst_only_counts_denied():
    allowed = [ev(seconds=i, spt=40000 + i, dpt=445, action="ALLOW") for i in range(40)]
    assert run(engine_with("denied_burst"), allowed) == []
    denied = [ev(seconds=i, spt=40000 + i, dpt=445) for i in range(40)]
    assert len(run(engine_with("denied_burst"), denied)) == 1


# 150 new connections in 30 seconds to an allowed port.
def test_high_rate():
    events = [ev(seconds=i * 0.2, spt=30000 + i, dpt=80, action="ALLOW") for i in range(150)]
    dets = run(engine_with("high_rate"), events)
    assert len(dets) == 1 and dets[0].count == 150


# Pings to 14 different hosts within 14 seconds.
def test_host_sweep():
    events = [ev(seconds=i, dst=f"10.0.1.{i}", proto="ICMP", spt=None, dpt=None, flags=(), icmp_type=8)
              for i in range(1, 15)]
    assert len(run(engine_with("host_sweep"), events)) == 1


# Five Xmas-scan packets (FIN+PSH+URG).
def test_tcp_flag_anomaly():
    events = [ev(seconds=i, dpt=100 + i, flags=("FIN", "PSH", "URG")) for i in range(5)]
    dets = run(engine_with("tcp_flag_anomaly"), events)
    assert len(dets) == 1 and dets[0].details["patterns"] == {"XMAS": 5}


# Ten quiet minutes (5 attempts each) build the baseline, then one minute
# has 300 attempts: one spike, reported with source "*".
def test_traffic_spike_against_baseline():
    events = []
    for minute in range(10):                       # baseline: 5 attempts per minute
        for i in range(5):
            events.append(ev(seconds=minute * 60 + i * 10, src=f"10.0.2.{i}", spt=20000 + minute * 10 + i))
    for i in range(300):                           # minute 10: 300 attempts
        events.append(ev(seconds=600 + i * 0.15, src="10.0.3.1", spt=10000 + i))
    events.append(ev(seconds=700, src="10.0.2.1", spt=9999))  # closes minute 10
    dets = run(engine_with("traffic_spike"), events)
    assert len(dets) == 1 and dets[0].src_ip == "*" and dets[0].count == 300


# Two scans ten minutes apart are two separate episodes.
def test_new_episode_after_quiet_period():
    burst = [ev(seconds=i * 0.1, dpt=i + 1) for i in range(30)]
    later = [ev(seconds=600 + i * 0.1, dpt=i + 1) for i in range(30)]
    dets = run(engine_with("port_scan"), burst + later)
    assert len(dets) == 2


# A rule switched off on the Rules page is not loaded at all.
def test_disabled_rule_does_not_run():
    cfg = RuleConfig("port_scan", "Port scan", 20, 60, enabled=False)
    assert DetectionEngine([cfg]).rules == []


# -- filters ----------------------------------------------------------------
# Multicast and broadcast are noise; addresses inside allowlist entries are allowlisted.
def test_ufw_logging_level_reads_conf(tmp_path):
    from app.core.monitor import ufw_logging_level
    conf = tmp_path / "ufw.conf"
    conf.write_text("# comment\nENABLED=yes\nLOGLEVEL=high\n")
    assert ufw_logging_level(str(conf)) == "high"
    assert ufw_logging_level(str(tmp_path / "missing.conf")) is None


def test_noise_and_allowlist():
    f = EventFilter(FilterConfig(allowlist=parse_networks(["192.168.56.1", "10.9.0.0/16"])))
    assert f.classify(ev(dst="224.0.0.251", proto="UDP", dpt=5353)) == "noise"
    assert f.classify(ev(dst="255.255.255.255", proto="UDP", dpt=67)) == "noise"
    assert f.classify(ev(src="192.168.56.1")) == "allowlisted"
    assert f.classify(ev(src="10.9.4.4")) == "allowlisted"
    assert f.classify(ev(src="10.0.0.5")) == "ok"
