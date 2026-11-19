"""Management commands.

    python manage.py init                      create .env, database and the first admin
    python manage.py create-user NAME --role analyst
    python manage.py reset-password NAME
    python manage.py analyze path/to/ufw.log   run detection from the command line (no web UI)

These are for tasks that should not, or cannot, be done in the web
interface: creating the very first admin, recovering a forgotten password,
and quick command-line analysis.
"""

import argparse
import getpass
import secrets
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
ENV = BASE / ".env"
ENV_EXAMPLE = BASE / ".env.example"


def ensure_env() -> None:
    """Create .env from .env.example with a random SECRET_KEY, if it does not exist yet."""
    if ENV.exists():
        print(".env already exists - leaving it unchanged.")
        return
    template = ENV_EXAMPLE.read_text(encoding="utf-8") if ENV_EXAMPLE.exists() else "SECRET_KEY=\n"
    lines = []
    for line in template.splitlines():
        if line.startswith("SECRET_KEY="):
            # 32 random bytes from the operating system's secure random source.
            line = f"SECRET_KEY={secrets.token_hex(32)}"
        lines.append(line)
    ENV.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("Created .env with a random SECRET_KEY. Edit it to add Telegram/SMTP settings.")


def ask_password(username: str) -> str:
    """Ask for a password twice without showing it on screen, and check its strength."""
    from app.web.auth import password_problem
    while True:
        pw = getpass.getpass(f"Password for {username}: ")
        problem = password_problem(pw)
        if problem:
            print(problem)
            continue
        if pw != getpass.getpass("Repeat password: "):
            print("Passwords do not match.")
            continue
        return pw


def get_app():
    """Create the app without background services (these commands only touch the database)."""
    import importlib
    import config
    importlib.reload(config)  # pick up a freshly written .env
    from app import create_app
    cfg = config.Config
    cfg.START_BACKGROUND_SERVICES = False
    return create_app(cfg)


def create_user(username: str, role: str, password: str | None) -> None:
    """Add a user. Asks for the password interactively unless one is given."""
    from app.extensions import db
    from app.models import User
    from app.web.auth import password_problem
    app = get_app()
    with app.app_context():
        if User.query.filter_by(username=username).first():
            print(f"User '{username}' already exists.")
            sys.exit(1)
        if password is None:
            password = ask_password(username)
        elif problem := password_problem(password):
            print(problem)
            sys.exit(1)
        user = User(username=username, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        print(f"Created {role} '{username}'.")


def cmd_init(args):
    """First-time setup: .env file, database tables and the first admin account."""
    ensure_env()
    from app.extensions import db
    from app.models import User
    app = get_app()
    with app.app_context():
        db.create_all()
        print(f"Database ready: {app.config['SQLALCHEMY_DATABASE_URI']}")
        has_admin = User.query.filter_by(role="admin").count() > 0
    # Safe to run again: it never creates a second admin or overwrites .env.
    if has_admin:
        print("An admin account already exists.")
        return
    username = args.username or input("Admin username [admin]: ").strip() or "admin"
    create_user(username, "admin", args.password)
    print("\nDone. Start the app with:  python run.py")


def cmd_create_user(args):
    create_user(args.username, args.role, args.password)


def cmd_reset_password(args):
    """Set a new password; also re-enables the account (for a locked-out admin)."""
    from app.extensions import db
    from app.models import User
    app = get_app()
    with app.app_context():
        user = User.query.filter_by(username=args.username).first()
        if not user:
            print(f"No user '{args.username}'.")
            sys.exit(1)
        user.set_password(ask_password(user.username))
        user.active = True
        db.session.commit()
        print("Password updated.")


def cmd_analyze(args):
    """Command-line analysis using the default rules; nothing is stored.

    Runs the same parser, filter and detection engine as the web app and
    prints one line per detection episode. Useful for quick checks of a log
    file and for showing that the core works without the web interface.
    """
    from app.core.detection import DetectionEngine, default_rule_configs
    from app.core.filters import EventFilter
    from app.core.parser import UFWParser

    parser, flt = UFWParser(), EventFilter()
    engine = DetectionEngine(default_rule_configs())
    episodes = {}    # latest update per episode
    with open(args.logfile, "r", encoding="utf-8", errors="replace") as fh:
        for event in parser.parse_lines(fh):
            if flt.classify(event) != "ok":
                continue
            for d in engine.process(event):
                episodes[d.key] = d
    for d in engine.flush():
        episodes[d.key] = d

    s = parser.stats
    print(f"Lines: {s.total}  parsed: {s.parsed}  not firewall: {s.not_ufw}  malformed: {s.malformed}  "
          f"noise dropped: {flt.stats.noise}")
    print(f"Detections: {len(episodes)}\n")
    for d in sorted(episodes.values(), key=lambda x: x.first_seen):
        print(f"[{d.severity.upper():8}] {d.rule_name:28} {d.src_ip:18} "
              f"{d.first_seen:%Y-%m-%d %H:%M:%S} -> {d.last_seen:%H:%M:%S}  "
              f"{d.details.get('summary', '')}")


def cmd_analyze_auth(args):
    """Command-line SSH brute-force check over an auth.log; nothing is stored.

    Runs the same auth parser and detector as the live monitor and prints one
    line per detection. Useful for checking a captured /var/log/auth.log, and
    for showing the auth-log detection without the web interface.
    """
    from app.core.authparser import DEFAULT_AUTH_RULE, AuthBruteForceDetector, AuthLogParser

    parser = AuthLogParser()
    det = AuthBruteForceDetector(DEFAULT_AUTH_RULE["threshold"], DEFAULT_AUTH_RULE["window_seconds"],
                                 DEFAULT_AUTH_RULE["severity"])
    episodes = {}
    with open(args.logfile, "r", encoding="utf-8", errors="replace") as fh:
        for ev in parser.parse_lines(fh):
            d = det.process(ev)
            if d is not None:
                episodes[d.key] = d
    s = parser.stats
    print(f"Lines: {s.total}  auth outcomes: {s.parsed}  failed: {s.failed}  accepted: {s.accepted}")
    print(f"Detections: {len(episodes)}\n")
    for d in sorted(episodes.values(), key=lambda x: x.first_seen):
        print(f"[{d.severity.upper():8}] {d.rule_name:30} {d.src_ip:18} "
              f"{d.first_seen:%Y-%m-%d %H:%M:%S} -> {d.last_seen:%H:%M:%S}  {d.details.get('summary', '')}")


def main():
    """Read the command line and run the chosen command."""
    p = argparse.ArgumentParser(description="Firewall Log Analyzer management")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="create .env, database and the first admin account")
    s.add_argument("--username")
    s.add_argument("--password", help="non-interactive (avoid on shared machines)")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("create-user", help="add a user")
    s.add_argument("username")
    s.add_argument("--role", choices=["admin", "analyst"], default="analyst")
    s.add_argument("--password")
    s.set_defaults(func=cmd_create_user)

    s = sub.add_parser("reset-password", help="reset a user's password")
    s.add_argument("username")
    s.set_defaults(func=cmd_reset_password)

    s = sub.add_parser("analyze", help="analyse a firewall (UFW) log file from the command line")
    s.add_argument("logfile")
    s.set_defaults(func=cmd_analyze)

    s = sub.add_parser("analyze-auth", help="check an SSH auth.log for brute-force from the command line")
    s.add_argument("logfile")
    s.set_defaults(func=cmd_analyze_auth)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
