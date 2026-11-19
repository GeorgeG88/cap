# Firewall Log Analyzer and Alert System

A lightweight, rule-based intrusion detection system for UFW (Uncomplicated Firewall) logs. It parses firewall log files or follows them live. It detects reconnaissance and intrusion attempts with explainable sliding-window rules, raises alerts with Telegram and email notifications, and presents everything in a web dashboard with reports.

Built as a capstone project. It is aimed at small organisations, schools and university labs that need firewall monitoring without a full SIEM.

## Features

- **Log parsing** for UFW kernel log lines in classic syslog and ISO 8601 formats. It handles IPv4/IPv6, TCP flags and ICMP types, and counts malformed and non-firewall lines rather than failing on them.
- **Noise filtering** drops broadcast and multicast traffic, DHCP, mDNS, NetBIOS and SSDP. An **allowlist** of trusted hosts and networks keeps them out of detection.
- **Seven detection rules**: port scan, brute force against authentication services, repeated denied connections, unusual connection rate, host sweep, abnormal TCP flags (NULL/FIN/Xmas), and traffic spike against a moving baseline.
- **Alerting**: deduplication, merging of repeated episodes, automatic severity escalation, and a new → acknowledged → resolved workflow with analyst notes.
- **Notifications** by Telegram bot and email (SMTP). They are sent from a background queue with retries, with a minimum severity and a per-source cooldown to prevent alert fatigue.
- **Two input modes**: uploaded log files (batch) and **live monitoring** of `/var/log/ufw.log`. Live monitoring survives log rotation.
- **Web dashboard** with charts, alert queue, event explorer, run history, rule editor, settings, user management and audit log.
- **Reports**: a PDF security report and CSV exports of alerts and events. An optional plain-language summary can be written by a local Ollama model.
- **Security of the tool itself**: hashed passwords, admin/analyst roles, login lockout, CSRF protection, a strict Content-Security-Policy, output escaping, protection against CSV formula injection, an upload size limit, and an audit trail. Secrets are kept in `.env`.

## Architecture

```
 Uploaded file ─┐
                ├─> Log parser ─> Noise/allowlist filter ─> Detection engine ─> Alert generator ─> Notifier ─> Telegram / Email
 Live ufw.log ──┘                                    │                │
                                                     └──> SQLite <────┘ ──> Flask dashboard, reports (PDF/CSV), optional Ollama summary
```

| Layer | Modules |
|---|---|
| Presentation | `app/web/*` (Flask blueprints), `app/templates`, `app/static` |
| Application | `app/core/parser.py`, `filters.py`, `detection.py`, `alerting.py`, `notifier.py`, `pipeline.py`, `monitor.py`, `reporting.py`, `summarizer.py` |
| Data | `app/models.py` (SQLite through SQLAlchemy), `.env` for secrets |

Only `parser.py` knows the UFW log format. Adding pfSense or Windows Firewall support means writing a new parser that produces the same `FirewallEvent`; nothing else changes. Likewise, a new notification channel is a single class in `notifier.py`.

## Reading the code

Every file starts with a comment that explains what it is for, and the code has comments that explain how each step works and why it is done that way. A good reading order follows one log line through the system:

1. `app/core/parser.py` turns a text line into a `FirewallEvent`.
2. `app/core/filters.py` drops noise and marks allowlisted sources.
3. `app/core/detection.py` holds the sliding-window rules. It is the heart of the project, and the comment at its top walks through a worked example.
4. `app/core/alerting.py` turns detections into alerts and decides on notifications.
5. `app/core/notifier.py` sends Telegram and email messages in the background.
6. `app/core/pipeline.py` connects steps 1 to 4, and `app/core/monitor.py` feeds it from the live log.
7. `app/__init__.py` and `app/web/` contain the web application, and `app/models.py` the database tables.

## Quick start on Windows 11

Requirements: Python 3.10 or newer from [python.org](https://www.python.org/downloads/). Tick **"Add Python to PATH"** during installation.

1. Double-click **`setup.bat`**. It creates a virtual environment, installs dependencies, creates the database and asks you for the first admin username and password (at least 10 characters, mixing letters with digits or symbols).
2. Double-click **`start.bat`**. The dashboard opens at <http://127.0.0.1:5000>.

Or from a terminal in the project folder:

```bat
py -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python manage.py init
python run.py
```

On Windows you can analyse uploaded `ufw.log` files copied from the VM. Live monitoring needs to run on the Ubuntu machine where UFW writes the log.

## Lab setup (Ubuntu firewall VM)

The recommended lab uses VirtualBox with an Ubuntu Server VM as the protected host running UFW and this app, plus a second VM for generating test traffic. Put both VMs on a **Host-only** network so test traffic stays isolated. Give the Ubuntu VM a second **NAT** adapter so the app can reach Telegram and Gmail.

On the Ubuntu VM:

```bash
sudo apt update && sudo apt install -y ufw openssh-server git
sudo ufw default deny incoming
sudo ufw allow 22/tcp
sudo ufw enable
sudo ufw logging high        # IMPORTANT: see the note below
```

> **Why `logging high`?** At `low` and `medium`, UFW rate-limits its log output to about 3 entries per minute after a short burst. A scan of 1,000 ports would then leave only a dozen lines in the log, and no log analyser could see it. `high` logs blocked and new connections without rate limiting. `full` also works but is very noisy.

Copy the project to the VM (Git, a shared folder or `scp`), then:

```bash
cd firewall-log-analyzer
bash deploy/install_ubuntu.sh
```

The script installs dependencies and sets `ufw logging high`. It also adds your user to the `adm` group so the app can read `/var/log/ufw.log` without root, initialises the app and installs it as a hardened systemd service.

To open the dashboard from Windows, edit `.env` on the VM so that `HOST` is the VM's host-only IP (find it with `ip a`, e.g. `192.168.56.10`). Then allow the port from the lab network only and restart:

```bash
sudo ufw allow from 192.168.56.0/24 to any port 5000 proto tcp
sudo systemctl restart firewall-analyzer
```

Browse to `http://192.168.56.10:5000`. Under **Live monitor**, start monitoring `/var/log/ufw.log`. Tick "start automatically" if you want it to resume after reboots.

## Notifications

All credentials live in `.env`, never in the database or code. Enable each channel on the **Settings** page and use the **test** buttons there.

**Telegram**
1. In Telegram, open **@BotFather**, send `/newbot` and copy the token into `TELEGRAM_BOT_TOKEN`.
2. Send any message to your new bot.
3. Open `https://api.telegram.org/bot<TOKEN>/getUpdates` in a browser and copy the `"chat":{"id": ...}` number into `TELEGRAM_CHAT_ID`.

**Email (Gmail)**
1. Turn on 2-Step Verification for the Google account, then create an **App Password**.
2. Fill in `SMTP_USER`, `SMTP_PASSWORD` (the app password), `SMTP_FROM` and `ALERT_EMAIL_TO` in `.env`. The host `smtp.gmail.com` and port `587` are already set.

Restart the app after editing `.env`.

**Policy.** Only alerts at or above the minimum severity are sent (default *high*). The same rule and source is notified at most once per cooldown (default 15 minutes), and an escalation to a higher severity always notifies. Uploaded files have notifications off by default, because historical data should not page anyone.

## Detection rules

Every rule keeps a sliding time window **per source IP** and counts **distinct** items inside it. Counting distinct items rather than raw log lines makes the rules robust against duplicate log entries and TCP retransmissions. Only *new connection attempts* are counted: TCP packets without ACK, non-reply UDP, and ICMP echo requests. Established traffic is ignored. Thresholds are editable on the **Rules** page.

| Rule | Counts (per source, per window) | Default | Severity |
|---|---|---|---|
| Port scan | distinct destination ports | 20 in 60 s | high |
| Brute-force attempt | distinct connections to auth ports (SSH, RDP, FTP, Telnet, DBs, VNC...) | 10 in 60 s | high |
| Repeated denied connections | distinct blocked connection attempts | 30 in 60 s | medium |
| Unusual connection rate | distinct new connection attempts | 100 in 60 s | medium |
| Host sweep | distinct destination hosts (gateway deployments) | 10 in 60 s | medium |
| Abnormal TCP flags | packets with NULL / FIN / Xmas / SYN+FIN / SYN+RST flags | 3 in 60 s | high |
| Traffic spike (global) | attempts in one minute vs. the average of the previous 10 minutes | ≥ 200 and ≥ 5× baseline | medium |

When a source reaches **twice** a rule's threshold, its alert is escalated one severity level. Detections for the same rule and source that start within the merge window (default 10 minutes) of an open alert update that alert instead of creating a new one.

The thresholds are starting points. Tune them on real lab traffic and report the effect of the tuning in your evaluation.

## Using the dashboard

| Page | Purpose |
|---|---|
| Dashboard | KPIs, traffic over time, alerts by rule, top sources and ports; filter by time range or analysis run. Refreshes every 15 s while live monitoring runs. |
| Alerts | Alert queue with filters and bulk acknowledge/resolve. Each alert page shows its evidence, related events, notes, notifications and other alerts from the same source. |
| Events | Searchable explorer of all stored events with the raw log line, plus CSV export. |
| Upload log / Analysis runs | Batch analysis with per-run statistics: lines read, parsed, malformed, noise dropped, allowlisted, alerts. |
| Live monitor | Start/stop tailing of the UFW log (admin). |
| Reports | PDF report, alert/event CSV and the optional AI summary for any scope. |
| Rules & allowlist | View (analyst) or edit (admin) thresholds, windows, severities and trusted sources. |
| Settings, Users, Audit log | Admin only. |

## Command line

```bash
python manage.py init                          # create .env, database and first admin
python manage.py create-user alice --role analyst
python manage.py reset-password alice
python manage.py analyze path/to/ufw.log       # run detection without the web UI
```

## Testing

```bash
pytest -q
```

The suite has 41 tests. They cover the parser (both timestamp formats, year rollover, malformed lines), every detection rule (positive and negative cases, duplicate handling, episodes), filtering, alert merging, escalation, cooldown, notifier retries, and the web application. The web tests cover authentication, lockout, role enforcement, open-redirect protection, security headers, HTML escaping of hostile log content, upload end-to-end, allowlisting, live monitoring with log rotation, and PDF/CSV export.

For the evaluation in the paper, use real logs from the lab. Run controlled tests from the second VM against the Ubuntu host. For each test, record the start time, end time, source IP and expected rule. Generate ordinary traffic as well, such as SSH logins and web requests, so false positives can appear. Then compare the alerts the system raised against your test log to report detection rate, false positives and detection delay.

## Project structure

```
app/
  core/        parser, filters, detection, alerting, notifier, pipeline, monitor, reporting, summarizer
  web/         Flask blueprints: auth, dashboard, alerts, events, analysis, admin, reports
  templates/   Jinja2 pages
  static/      CSS, dashboard JS, Chart.js (bundled, works offline)
  models.py    database models and settings
  security.py  roles, login throttling, security headers
deploy/        Ubuntu install script and systemd unit
tests/         pytest suite
config.py, run.py, manage.py, setup.bat, start.bat
```

## Limitations

- It is an **IDS, not an IPS**: it detects and alerts but never blocks traffic.
- Detection is limited to what the firewall logs. Payload-based attacks (SQL injection, malware) are invisible in firewall logs, and a single host only sees traffic addressed to itself.
- Fixed thresholds need tuning per environment. Slow, distributed scans spread across many sources or long periods can stay under them.
- Classic syslog timestamps have no year, so the year is inferred.
- SQLite suits a single host and lab-scale volumes, not enterprise traffic.

## Potential enhancements

- Automatic response: temporarily block offending IPs through UFW rules (IPS mode) with an approval step.
- More parsers: pfSense/OPNsense, Windows Defender Firewall and iptables variants.
- Adaptive thresholds learned from each host's normal traffic, or anomaly detection with machine learning.
- GeoIP and threat-intelligence enrichment of source IPs.
- Additional channels (Slack, Discord, webhooks) and SIEM export (syslog/CEF).
- PostgreSQL backend and multi-sensor support for larger networks.
