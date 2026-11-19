"""Start the Firewall Log Analyzer web application.

Uses the Waitress production server (works on Windows and Linux).
Host and port come from the .env file (HOST, PORT).

Usage:  python run.py
"""

import sys

from app import create_app


def main():
    try:
        app = create_app()
    except RuntimeError as exc:
        # Most likely the .env file is missing; the message says what to do.
        print(f"Error: {exc}")
        sys.exit(1)
    host, port = app.config["HOST"], app.config["PORT"]
    print(f"Firewall Log Analyzer running on http://{host}:{port}  (Ctrl+C to stop)")
    try:
        # Waitress is a proper multi-threaded server; 8 threads means 8
        # requests can be handled at the same time.
        from waitress import serve
        serve(app, host=host, port=port, threads=8)
    except ImportError:
        # development fallback; reloader disabled so the live monitor runs only once
        # (the reloader would start the app twice, and with it two monitor threads).
        app.run(host=host, port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
