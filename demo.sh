#!/usr/bin/env bash
# demo.sh - run every component once and save the output to ./sample_output
# Safe to run: uses a temporary workspace, never touches /etc or real data.
# Root is only needed for the user-management lifecycle demo (it is skipped otherwise).
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); BIN=$HERE/bin
OUT=${1:-$HERE/sample_output}; mkdir -p "$OUT"
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
step() { printf '\033[1;34m[demo]\033[0m %s\n' "$*"; }

mkconf() {   # mkconf <disk_warn> <disk_crit> <dry_run>
cat > "$WORK/demo.conf" <<CONF
[general]
interval = 2
report_dir = $WORK/reports
state_dir = $WORK/state
log_file = $WORK/sysmon.log
[thresholds]
disk_warn = $1
disk_crit = $2
[network]
allowed_ports = 22
[actions]
dry_run = $3
cleanup_paths = $WORK/oldfiles
cleanup_days = 7
CONF
}
mkconf 80 90 yes

step "1/10 full health report";            "$BIN/sysmon.py" --config "$WORK/demo.conf" report --save > "$OUT/01-health-report.txt"
step "2/10 JSON output (for tools)";       "$BIN/sysmon.py" --config "$WORK/demo.conf" report --json --no-actions > "$OUT/02-health-report.json"

step "3/10 simulated disk emergency (dry-run, then real cleanup)"
mkdir -p "$WORK/oldfiles"; for i in 1 2 3; do head -c 200000 /dev/zero > "$WORK/oldfiles/old$i.log"; touch -d '30 days ago' "$WORK/oldfiles/old$i.log"; done
echo fresh > "$WORK/oldfiles/fresh.log"
{ echo "### thresholds lowered to warn=1% crit=2% so the root filesystem looks full"
  echo "### dry_run = yes (default): only logs what it WOULD do"; echo "files before: $(ls "$WORK/oldfiles" | tr '\n' ' ')"
  mkconf 1 2 yes; "$BIN/sysmon.py" --config "$WORK/demo.conf" report --section disk
  echo; echo "### dry_run = no: really deletes files older than 7 days (fresh files are kept)"
  mkconf 1 2 no; rm -f "$WORK/state/state.json"
  "$BIN/sysmon.py" --config "$WORK/demo.conf" report --section disk
  echo; echo "files after:  $(ls "$WORK/oldfiles" | tr '\n' ' ')"; } > "$OUT/03-automated-actions.txt" 2>&1
mkconf 80 90 yes; rm -rf "$WORK/state"

step "4/10 daemon: 3 cycles, then graceful SIGTERM"
"$BIN/sysmon.py" --config "$WORK/demo.conf" daemon > "$OUT/04-daemon-log.txt" 2>&1 &
DPID=$!; sleep 7; kill -HUP $DPID; sleep 3; kill -TERM $DPID; wait $DPID 2>/dev/null
step "5/10 history";                         "$BIN/sysmon.py" --config "$WORK/demo.conf" history --last 5 > "$OUT/05-history.txt"
step "6/10 bash health check";               { "$BIN/health-check.sh"; echo "exit code: $?"; echo; "$BIN/health-check.sh" --quiet; } > "$OUT/06-health-check.txt" 2>&1

step "7/10 log analysis (bundled sample logs)"
{ "$BIN/log-analyzer.py" auth --file "$HERE/samples/auth.log" --blocklist "$WORK/blocklist.txt"; echo "exit code: $? (1 = brute-force sources found)"; echo; echo "blocklist.txt:"; cat "$WORK/blocklist.txt"; } > "$OUT/07-log-analysis-auth.txt"
"$BIN/log-analyzer.py" syslog --file "$HERE/samples/syslog" --top 6 > "$OUT/07-log-analysis-syslog.txt"

step "8/10 backup, verify, restore-test, rotation"
mkdir -p "$WORK/data/docs"; echo "important" > "$WORK/data/docs/a.txt"; echo "config" > "$WORK/data/app.conf"
export BACKUP_CONF=/dev/null BACKUP_SOURCES="$WORK/data" BACKUP_DEST="$WORK/backups" LOG_FILE="$WORK/backup.log" MIN_FREE_PERCENT=1
{ "$BIN/backup.sh" --dry-run; "$BIN/backup.sh"; "$BIN/backup.sh" --restore-test; echo; ls -l "$WORK/backups" | sed 1d; echo; (cd "$WORK/backups" && cat ./*.sha256); } > "$OUT/08-backup.txt" 2>&1
unset BACKUP_CONF BACKUP_SOURCES BACKUP_DEST LOG_FILE MIN_FREE_PERCENT

step "9/10 users, permissions, SSH"
{ if [[ $EUID -eq 0 ]]; then
    "$BIN/user-manage.sh" add demo_ops --sudo --key "ssh-ed25519 AAAAdemoKeyForShowOnly demo@laptop" --expire 2027-12-31
    "$BIN/user-manage.sh" list; echo; echo '$ chmod 777 /home/demo_ops   # simulate a mistake'; chmod 777 /home/demo_ops
    "$BIN/user-manage.sh" audit | grep -E 'WARN|issue'; echo; "$BIN/user-manage.sh" fix-perms | tail -n1
    "$BIN/user-manage.sh" lock demo_ops; "$BIN/user-manage.sh" unlock demo_ops; "$BIN/user-manage.sh" remove demo_ops 2>/dev/null
    echo; echo "==== full audit afterwards ===="; "$BIN/user-manage.sh" audit
  else echo "(skipped: run demo.sh with sudo to include the user-management lifecycle)"; "$BIN/user-manage.sh" audit; fi; } > "$OUT/09-user-management.txt" 2>&1
{ if command -v sshd >/dev/null; then "$BIN/ssh-harden.sh"; else echo "sshd not installed - skipped"; fi; } > "$OUT/10-ssh-audit.txt" 2>&1

step "10/10 maintenance (dry run)"; LOG_FILE="$WORK/m.log" "$BIN/maintenance.sh" --dry-run > "$OUT/11-maintenance-dry-run.txt" 2>&1
sed -i "s#$WORK#<workdir>#g" "$OUT"/*.txt "$OUT"/*.json 2>/dev/null
echo; echo "Saved $(ls "$OUT" | wc -l) files to $OUT"
