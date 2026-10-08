#!/usr/bin/env bash
# maintenance.sh - routine housekeeping. Safe to run from cron.
#   maintenance.sh --dry-run     show what would happen
set -uo pipefail
DRY=0; [[ "${1:-}" == "--dry-run" ]] && DRY=1
TMP_DAYS=${TMP_DAYS:-7}; LOG_DAYS=${LOG_DAYS:-30}; JOURNAL_MAX=${JOURNAL_MAX:-200M}
LOG_FILE=${LOG_FILE:-/var/log/sysmon/maintenance.log}
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null; [[ -w $(dirname "$LOG_FILE") ]] || LOG_FILE=/tmp/sysmon-maintenance.log
log() { printf '%s [%s] %s\n' "$(date '+%F %T')" "$1" "${*:2}" | tee -a "$LOG_FILE"; }
run() { if (( DRY )); then log DRY "$*"; else "$@"; fi; }
(( DRY )) && log INFO "dry-run mode: nothing will be changed"

# 1. Old temp files (regular files only, never crosses filesystems, never follows symlinks)
for d in /tmp /var/tmp; do
    [[ -d $d ]] || continue
    n=$(find "$d" -xdev -type f -atime +"$TMP_DAYS" -mtime +"$TMP_DAYS" 2>/dev/null | wc -l)
    log INFO "$d: $n file(s) unused for more than ${TMP_DAYS} days"
    (( DRY )) || find "$d" -xdev -type f -atime +"$TMP_DAYS" -mtime +"$TMP_DAYS" -delete 2>/dev/null
done

# 2. Rotated/compressed logs older than LOG_DAYS
if [[ -d /var/log ]]; then
    n=$(find /var/log -xdev -type f \( -name '*.gz' -o -name '*.[0-9]' -o -name '*.old' \) -mtime +"$LOG_DAYS" 2>/dev/null | wc -l)
    log INFO "/var/log: $n rotated log file(s) older than ${LOG_DAYS} days"
    (( DRY )) || find /var/log -xdev -type f \( -name '*.gz' -o -name '*.[0-9]' -o -name '*.old' \) -mtime +"$LOG_DAYS" -delete 2>/dev/null
fi

# 3. systemd journal size cap
if command -v journalctl >/dev/null && [[ -d /run/systemd/system ]]; then
    log INFO "journal usage: $(journalctl --disk-usage 2>/dev/null | grep -o '[0-9.]*[KMGT]' | head -n1)"
    run journalctl --vacuum-size="$JOURNAL_MAX" >/dev/null 2>&1
fi

# 4. Package manager caches + pending updates (report only, never auto-upgrades)
if command -v apt-get >/dev/null; then
    run apt-get clean
    up=$(apt list --upgradable 2>/dev/null | grep -c upgradable || true)
    log INFO "apt: $up package(s) upgradable"
    [[ -f /var/run/reboot-required ]] && log WARN "reboot required (kernel/libc update)"
elif command -v dnf >/dev/null; then
    run dnf clean all >/dev/null
    log INFO "dnf: $(dnf -q check-update 2>/dev/null | grep -cE '^\S+\.\S+\s' || true) update(s) available"
fi

# 5. Where is the space going? (top 5 directories under /var)
log INFO "largest directories in /var:"
du -xh --max-depth=2 /var 2>/dev/null | sort -rh | sed -n '2,6p' | while read -r size dir; do log INFO "   $size  $dir"; done
log INFO "maintenance finished"
