#!/usr/bin/env bash
# backup.sh - verified, rotated, lock-protected tar.gz backups.
#
#   backup.sh                  run a backup using the config
#   backup.sh --dry-run        show what would be backed up
#   backup.sh --restore-test   extract the newest archive to a temp dir and compare
#   backup.sh --list           list existing backups
#
# Config (shell syntax) is read from /etc/sysmon/backup.conf, or $BACKUP_CONF.
set -euo pipefail
umask 077                                  # archives are readable by the owner only

CONF=${BACKUP_CONF:-/etc/sysmon/backup.conf}
[[ -r $CONF ]] || CONF="$(dirname "$(readlink -f "$0")")/../config/backup.conf"
# shellcheck disable=SC1090
[[ -r $CONF ]] && source "$CONF"

BACKUP_SOURCES=${BACKUP_SOURCES:-"/etc /home"}
BACKUP_DEST=${BACKUP_DEST:-/var/backups/sysmon}
RETENTION_DAYS=${RETENTION_DAYS:-7}
MIN_FREE_PERCENT=${MIN_FREE_PERCENT:-10}
EXCLUDES=${EXCLUDES:-"*.tmp *.cache */node_modules */.cache */lost+found"}
LOG_FILE=${LOG_FILE:-/var/log/sysmon/backup.log}

mkdir -p "$BACKUP_DEST" 2>/dev/null || { BACKUP_DEST="$HOME/sysmon-backups"; mkdir -p "$BACKUP_DEST"; }
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
[[ -w $(dirname "$LOG_FILE") ]] || LOG_FILE="$BACKUP_DEST/backup.log"

log() { printf '%s [%s] %s\n' "$(date '+%F %T')" "$1" "${*:2}" | tee -a "$LOG_FILE"; }
die() { log ERROR "$*"; exit 1; }
newest() { ls -1t "$BACKUP_DEST"/backup-*.tar.gz 2>/dev/null | head -n1; }

MODE=run
case "${1:-}" in
    --dry-run) MODE=dry ;;
    --restore-test) MODE=restore ;;
    --list) ls -lh "$BACKUP_DEST"/backup-*.tar.gz 2>/dev/null || echo "no backups yet"; exit 0 ;;
    "" ) ;;
    *) echo "usage: $0 [--dry-run|--restore-test|--list]"; exit 64 ;;
esac

# Only one backup at a time: flock on fd 9 is released automatically if we crash.
exec 9>"/tmp/sysmon-backup.lock"
flock -n 9 || die "another backup is already running"

if [[ $MODE == restore ]]; then
    latest=$(newest); [[ -n $latest ]] || die "no backup found in $BACKUP_DEST"
    ( cd "$(dirname "$latest")" && sha256sum -c "$(basename "$latest").sha256" >/dev/null ) || die "checksum mismatch: $latest"
    tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
    tar -xzf "$latest" -C "$tmp" || die "extract failed"
    files=$(find "$tmp" -type f | wc -l)
    log INFO "restore-test OK: $(basename "$latest") -> $files files extracted and checksum verified"
    exit 0
fi

# Build the list of sources that actually exist and the exclude flags.
sources=(); for s in $BACKUP_SOURCES; do [[ -e $s ]] && sources+=("$s") || log WARN "source missing, skipped: $s"; done
(( ${#sources[@]} )) || die "no valid sources"
excl=(); for e in $EXCLUDES; do excl+=(--exclude="$e"); done
excl+=(--exclude="$BACKUP_DEST")

need=$(du -sbc "${sources[@]}" 2>/dev/null | tail -n1 | cut -f1)
free=$(df --output=avail -B1 "$BACKUP_DEST" | tail -n1)
total=$(df --output=size -B1 "$BACKUP_DEST" | tail -n1)
if (( free < need / 2 )); then
    die "not enough space in $BACKUP_DEST (need ~$((need/2/1024/1024)) MiB, free $((free/1024/1024)) MiB)"
fi
if (( 100 * (free - need / 2) / total < MIN_FREE_PERCENT )); then
    die "backup would leave less than ${MIN_FREE_PERCENT}% free on $BACKUP_DEST (lower MIN_FREE_PERCENT or free space)"
fi

if [[ $MODE == dry ]]; then
    log INFO "DRY RUN: would back up ${sources[*]} (~$((need/1024/1024)) MiB raw) to $BACKUP_DEST, keep ${RETENTION_DAYS}d"
    exit 0
fi

name="backup-$(hostname -s)-$(date +%Y%m%d-%H%M%S).tar.gz"
out="$BACKUP_DEST/$name"
log INFO "starting backup of ${sources[*]} -> $name"

set +e
tar --create --gzip --file="$out" --warning=no-file-changed "${excl[@]}" "${sources[@]}" 2>>"$LOG_FILE"
rc=$?
set -e
# tar exit 1 = "some files differ/changed while reading" - normal on a live system, not fatal.
(( rc <= 1 )) || { rm -f "$out"; die "tar failed with exit code $rc"; }
(( rc == 1 )) && log WARN "some files changed while being archived"

tar -tzf "$out" >/dev/null || { rm -f "$out"; die "archive failed integrity test"; }
( cd "$BACKUP_DEST" && sha256sum "$name" > "$name.sha256" )
log INFO "OK $name  size=$(du -h "$out" | cut -f1)  files=$(tar -tzf "$out" | wc -l)  sha256=$(cut -c1-16 "$out.sha256")..."

# Rotation: delete archives (and their checksums) older than RETENTION_DAYS.
deleted=$(find "$BACKUP_DEST" -maxdepth 1 -name 'backup-*.tar.gz*' -mtime +"$RETENTION_DAYS" -print -delete | wc -l)
log INFO "rotation: removed $deleted old file(s), keeping ${RETENTION_DAYS} days"
