#!/usr/bin/env bash
# uninstall.sh - remove sysmon. Logs, backups and /etc/sysmon are kept unless --purge.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }
if [[ -d /run/systemd/system ]]; then systemctl disable --now sysmon.service 2>/dev/null || true; fi
rm -f /etc/systemd/system/sysmon.service /etc/cron.d/sysmon /etc/logrotate.d/sysmon /usr/local/bin/sysmon
[[ -d /run/systemd/system ]] && systemctl daemon-reload
rm -rf /opt/sysmon
if [[ ${1:-} == --purge ]]; then rm -rf /etc/sysmon /var/log/sysmon /var/lib/sysmon; echo "purged config, logs and state (backups in /var/backups/sysmon kept)"; fi
echo "sysmon removed."
