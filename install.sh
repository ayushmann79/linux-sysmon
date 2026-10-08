#!/usr/bin/env bash
# install.sh - install sysmon system-wide.   sudo ./install.sh [--no-start]
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root: sudo $0"; exit 1; }
SRC=$(cd "$(dirname "$0")" && pwd)
PREFIX=/opt/sysmon
say() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }

command -v python3 >/dev/null || { echo "python3 is required"; exit 1; }
python3 - <<'PY' || { echo "Python 3.8+ required"; exit 1; }
import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)
PY

say "Copying program files to $PREFIX"
install -d -m 755 "$PREFIX/bin"
install -m 755 "$SRC"/bin/* "$PREFIX/bin/"
install -m 644 "$SRC/README.md" "$PREFIX/README.md" 2>/dev/null || true

say "Installing configuration to /etc/sysmon (existing files are kept)"
install -d -m 755 /etc/sysmon
for f in sysmon.conf backup.conf; do
    if [[ -e /etc/sysmon/$f ]]; then echo "   keeping existing /etc/sysmon/$f (new default saved as $f.new)"; install -m 644 "$SRC/config/$f" "/etc/sysmon/$f.new"
    else install -m 644 "$SRC/config/$f" "/etc/sysmon/$f"; fi
done

say "Creating log/state directories"
install -d -m 750 /var/log/sysmon /var/log/sysmon/reports /var/lib/sysmon /var/backups/sysmon

say "Installing cron jobs, logrotate policy and command shortcut"
install -m 644 "$SRC/cron/sysmon.cron" /etc/cron.d/sysmon
install -m 644 "$SRC/logrotate/sysmon" /etc/logrotate.d/sysmon
ln -sf "$PREFIX/bin/sysmon.py" /usr/local/bin/sysmon

if [[ -d /run/systemd/system ]]; then
    say "Installing systemd unit"
    install -m 644 "$SRC/systemd/sysmon.service" /etc/systemd/system/sysmon.service
    systemctl daemon-reload
    if [[ ${1:-} != --no-start ]]; then systemctl enable --now sysmon.service; systemctl --no-pager --lines=0 status sysmon.service || true; fi
else
    echo "systemd not running here - unit file copied to $SRC/systemd only; run the agent with: sysmon daemon"
fi

cat <<MSG

Done.  Try:
  sysmon report                       full health report
  sudo systemctl status sysmon        daemon status
  journalctl -u sysmon -f             live agent log
  sudo $PREFIX/bin/user-manage.sh audit
Actions are in DRY-RUN mode. After reviewing /var/log/sysmon/sysmon.log set  dry_run = no
in /etc/sysmon/sysmon.conf and run: sudo systemctl reload sysmon
MSG
