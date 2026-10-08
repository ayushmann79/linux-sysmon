#!/usr/bin/env bash
# health-check.sh - fast, dependency-free health check in pure Bash/awk.
# Reads /proc directly. Nagios-style exit codes: 0=OK 1=WARNING 2=CRITICAL.
#
#   health-check.sh            # human readable
#   health-check.sh --quiet    # single line (for cron / logs)
set -uo pipefail

CPU_WARN=${CPU_WARN:-75};  CPU_CRIT=${CPU_CRIT:-90}
MEM_WARN=${MEM_WARN:-80};  MEM_CRIT=${MEM_CRIT:-92}
DISK_WARN=${DISK_WARN:-80}; DISK_CRIT=${DISK_CRIT:-90}
QUIET=0; [[ "${1:-}" == "--quiet" || "${1:-}" == "-q" ]] && QUIET=1

level=0   # worst level seen
note() { (( $2 > level )) && level=$2; }
grade() { # value warn crit -> 0/1/2   (integer compare on the whole-number part)
    local v=${1%.*}
    if   (( v >= $3 )); then echo 2
    elif (( v >= $2 )); then echo 1
    else echo 0; fi
}
label() { case $1 in 0) echo OK;; 1) echo WARNING;; *) echo CRITICAL;; esac; }

# --- CPU: two samples of /proc/stat, 1s apart -------------------------------
read -r _ u1 n1 s1 i1 w1 q1 sq1 st1 _ < /proc/stat; sleep 1
read -r _ u2 n2 s2 i2 w2 q2 sq2 st2 _ < /proc/stat
tot1=$((u1+n1+s1+i1+w1+q1+sq1+st1)); tot2=$((u2+n2+s2+i2+w2+q2+sq2+st2))
idle=$(( (i2+w2) - (i1+w1) )); total=$(( tot2 - tot1 )); (( total == 0 )) && total=1
cpu=$(( 100 * (total - idle) / total ))
cpu_l=$(grade "$cpu" $CPU_WARN $CPU_CRIT); note cpu "$cpu_l"

# --- Load per core ------------------------------------------------------------
read -r load1 load5 load15 _ < /proc/loadavg
cores=$(grep -c '^processor' /proc/cpuinfo)

# --- Memory: MemAvailable is the honest "free" number --------------------------
mem=$(awk '/MemTotal/{t=$2} /MemAvailable/{a=$2} END{printf "%d", 100*(t-a)/t}' /proc/meminfo)
mem_l=$(grade "$mem" $MEM_WARN $MEM_CRIT); note mem "$mem_l"

# --- Disk: every real filesystem, `df -P` for stable columns ------------------
disk_lines=(); worst_disk=0; worst_mount=/
while read -r _ _ _ _ pct mount; do
    p=${pct%\%}; l=$(grade "$p" $DISK_WARN $DISK_CRIT); note disk "$l"
    disk_lines+=("$(printf '%-24s %3s%%  %s' "$mount" "$p" "$(label "$l")")")
    (( p > worst_disk )) && { worst_disk=$p; worst_mount=$mount; }
done < <(df -P -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null | tail -n +2)

# --- Zombies --------------------------------------------------------------------
zombies=$(awk '{print $3}' /proc/[0-9]*/stat 2>/dev/null | grep -c '^Z$' || true)

if (( QUIET )); then
    printf '%s %s - cpu=%s%% mem=%s%% disk=%s%%(%s) load=%s zombies=%s\n' \
        "$(date '+%F %T')" "$(label $level)" "$cpu" "$mem" "$worst_disk" "$worst_mount" "$load1" "$zombies"
else
    echo "Host      : $(hostname)    $(date '+%F %T')"
    echo "Uptime    : $(uptime -p 2>/dev/null || cut -d. -f1 /proc/uptime)"
    printf 'CPU       : %3s%%  %s   (load %s %s %s on %s cores)\n' "$cpu" "$(label $cpu_l)" "$load1" "$load5" "$load15" "$cores"
    printf 'Memory    : %3s%%  %s\n' "$mem" "$(label $mem_l)"
    echo "Disks     :"; printf '   %s\n' "${disk_lines[@]}"
    echo "Zombies   : $zombies"
    echo "OVERALL   : $(label $level)"
fi
exit $level
