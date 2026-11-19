#!/usr/bin/env bash
# Install the Firewall Log Analyzer on the Ubuntu firewall VM as a systemd service.
# Run from the project folder:   bash deploy/install_ubuntu.sh
#
# What it does, in order:
#   1. installs Python and UFW
#   2. sets UFW logging to "high" so attacks are logged without rate limits
#   3. lets your user read /var/log/ufw.log without root (adm group)
#   4. creates a Python virtual environment and installs the dependencies
#   5. runs "manage.py init" (creates .env, the database and the first admin)
#   6. installs and starts a systemd service, so the app starts on every boot

# Stop at the first error (-e), on undefined variables (-u), and if any
# command in a pipe fails (-o pipefail).
set -euo pipefail

# The project folder (one level above this script), and the user who ran
# "sudo" (the service runs as that normal user, not as root).
APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APP_USER="${SUDO_USER:-$USER}"

echo "==> Installing system packages"
sudo apt-get update -y
sudo apt-get install -y python3 python3-venv python3-pip ufw

# At the low and medium levels UFW logs only about 3 lines per minute after a
# short burst, which would hide most of a port scan.
echo "==> UFW: logging without rate limits (needed so scans are fully logged)"
sudo ufw logging high

# /var/log/ufw.log belongs to the "adm" group, so membership is enough to read it.
echo "==> Giving $APP_USER read access to /var/log/ufw.log (adm group)"
sudo usermod -aG adm "$APP_USER"

# A virtual environment keeps the app's packages separate from the system Python.
echo "==> Python environment"
cd "$APP_DIR"
python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt
./venv/bin/python manage.py init

# Fill the real folder and user name into the service template and install it.
echo "==> systemd service"
sed -e "s#__APP_DIR__#$APP_DIR#g" -e "s#__APP_USER__#$APP_USER#g" deploy/firewall-analyzer.service \
  | sudo tee /etc/systemd/system/firewall-analyzer.service >/dev/null
sudo systemctl daemon-reload
# enable = start on boot; --now = also start it right away
sudo systemctl enable --now firewall-analyzer

HOST_LINE=$(grep '^HOST=' .env || true)
echo
echo "Done. The service is running ($HOST_LINE)."
echo "To reach it from your PC, set HOST to this VM's host-only IP in .env (ip a), then:"
echo "    sudo ufw allow from 192.168.56.0/24 to any port 5000 proto tcp"
echo "    sudo systemctl restart firewall-analyzer"
echo "Log out and back in once so the adm group membership applies to your shell."
