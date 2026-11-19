"""Core processing modules: parsing, filtering, detection, alerting, notification, reporting.

Nothing in this package (except pipeline, alerting, monitor and reporting,
which store results) depends on the web framework, so the detection logic
can be tested and run from the command line on its own.

Order in which the modules are used for each log line:
  parser.py     text line  -> FirewallEvent
  filters.py    drop noise, mark allowlisted sources
  detection.py  sliding-window rules -> Detection
  alerting.py   Detection -> stored Alert, notification decision
  notifier.py   Telegram / email delivery in the background
  pipeline.py   connects all of the above (used for uploads)
  monitor.py    follows the live log file and feeds the pipeline
  reporting.py  statistics, CSV and PDF
  summarizer.py optional AI summary through a local Ollama model
"""
