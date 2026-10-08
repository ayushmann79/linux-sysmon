#!/usr/bin/env bash
# ssh-harden.sh - audit and harden OpenSSH safely.
#
#   ssh-harden.sh                       audit only: compare the EFFECTIVE config with the baseline
#   ssh-harden.sh --apply [options]     back up, write drop-in, validate with `sshd -t`, reload
#   ssh-harden.sh --rollback            remove our changes and reload
#
# options for --apply
#   --allow-users "alice bob"   restrict logins to these users
#   --port 2222                 move SSH to another port (open the firewall FIRST)
#   --keep-passwords            do not disable password authentication
#   --force                     skip the "you have an SSH key installed" safety check
set -uo pipefail

DROPIN_DIR=/etc/ssh/sshd_config.d
# "00-" so we are read FIRST. sshd uses the first value it sees for a keyword, and cloud images
# often ship 50-cloud-init.conf with PasswordAuthentication yes - a "99-" file would lose.
DROPIN=$DROPIN_DIR/00-sysmon-hardening.conf
MAIN=/etc/ssh/sshd_config
MARK_BEGIN="# BEGIN sysmon-hardening"; MARK_END="# END sysmon-hardening"
BACKUP_DIR=/var/backups/sysmon-ssh

# keyword  wanted-value
BASELINE=(
    "permitrootlogin no"
    "passwordauthentication no"
    "pubkeyauthentication yes"
    "permitemptypasswords no"
    "challengeresponseauthentication no"
    "maxauthtries 3"
    "logingracetime 30"
    "x11forwarding no"
    "allowagentforwarding no"
    "permituserenvironment no"
    "clientaliveinterval 300"
    "clientalivecountmax 2"
    "loglevel VERBOSE"
)

die() { echo "error: $*" >&2; exit 1; }
SSHD=$(command -v sshd || ls /usr/sbin/sshd 2>/dev/null || true)
[[ -n $SSHD ]] || die "sshd (openssh-server) is not installed on this machine"

[[ -d /run/sshd || $EUID -ne 0 ]] || mkdir -p -m 755 /run/sshd   # sshd -t needs its privsep dir even when the service is stopped

effective() { "$SSHD" -T 2>/dev/null; }          # the config sshd would really use, after Includes/Match

audit() {
    local conf bad=0; conf=$(effective) || true
    [[ -n $conf ]] || { echo "could not read effective config (try as root)"; return 2; }
    printf '%-38s %-14s %s\n' SETTING CURRENT STATUS
    for line in "${BASELINE[@]}"; do
        key=${line%% *}; want=${line#* }
        have=$(awk -v k="$key" '$1==k{print $2; exit}' <<<"$conf")
        # newer OpenSSH reports ChallengeResponseAuthentication under its new name
        [[ -z $have && $key == challengeresponseauthentication ]] && have=$(awk '$1=="kbdinteractiveauthentication"{print $2; exit}' <<<"$conf")
        if [[ ${have,,} == "${want,,}" ]]; then st="ok"; else st="DIFFERS (want $want)"; bad=$((bad+1)); fi
        printf '%-38s %-14s %s\n' "$key" "${have:-unset}" "$st"
    done
    echo; echo "port: $(awk '$1=="port"{print $2}' <<<"$conf" | tr '\n' ' ')"
    echo "$bad setting(s) differ from the baseline."
    (( bad == 0 ))
}

has_key() {   # does the invoking (non-root) user have an authorized key?
    local u=${SUDO_USER:-${USER:-root}} h
    h=$(getent passwd "$u" | cut -d: -f6)
    [[ -s $h/.ssh/authorized_keys ]]
}

reload_sshd() { systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || service ssh reload 2>/dev/null; }

apply() {
    [[ $EUID -eq 0 ]] || die "--apply needs root"
    local allow="" port="" keep_pw=0 force=0
    while (( $# )); do case $1 in
        --allow-users) allow=$2; shift;; --port) port=$2; shift;;
        --keep-passwords) keep_pw=1;; --force) force=1;; *) die "unknown option $1";; esac; shift; done

    if (( ! keep_pw && ! force )) && ! has_key; then
        die "user '${SUDO_USER:-${USER:-root}}' has no ~/.ssh/authorized_keys. Disabling passwords now would lock you out.
       Add a key first (ssh-copy-id), or use --keep-passwords, or --force."
    fi

    mkdir -p "$BACKUP_DIR"; cp -a "$MAIN" "$BACKUP_DIR/sshd_config.$(date +%Y%m%d-%H%M%S)"
    [[ -f $DROPIN ]] && cp -a "$DROPIN" "$BACKUP_DIR/00-sysmon-hardening.conf.$(date +%Y%m%d-%H%M%S)"

    local body=()
    for line in "${BASELINE[@]}"; do
        key=${line%% *}; want=${line#* }
        (( keep_pw )) && [[ $key == passwordauthentication ]] && want=yes
        body+=("$key $want")
    done
    [[ -n $allow ]] && body+=("allowusers $allow")
    [[ -n $port ]]  && body+=("port $port")

    if grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d/' "$MAIN"; then
        mkdir -p "$DROPIN_DIR"
        { echo "# Managed by sysmon ssh-harden.sh - $(date '+%F %T')"; printf '%s\n' "${body[@]}"; } > "$DROPIN"
        chmod 644 "$DROPIN"; METHOD="drop-in $DROPIN"
    else   # old systems without Include: prepend a marked block to the main file (first match wins)
        sed -i "/$MARK_BEGIN/,/$MARK_END/d" "$MAIN"
        { echo "$MARK_BEGIN"; printf '%s\n' "${body[@]}"; echo "$MARK_END"; cat "$MAIN"; } > "$MAIN.new" && mv "$MAIN.new" "$MAIN"
        METHOD="block at top of $MAIN"
    fi

    if ! "$SSHD" -t; then
        echo "sshd -t FAILED - rolling back"; rollback_quiet; die "configuration invalid, nothing was changed"
    fi
    if reload_sshd; then echo "sshd reloaded using $METHOD"; else echo "config written using $METHOD, but could not reload sshd automatically (no systemd/service?) - reload it manually"; fi
    logger -t ssh-harden "applied hardening via $METHOD"
    cat <<MSG

Applied. IMPORTANT: keep this session open and test a NEW login in another terminal.
If it fails, run:  sudo $0 --rollback
Remember: firewall (ufw/firewalld) and SELinux must allow a changed port.
MSG
}

rollback_quiet() {
    rm -f "$DROPIN"
    sed -i "/$MARK_BEGIN/,/$MARK_END/d" "$MAIN" 2>/dev/null
}
rollback() { [[ $EUID -eq 0 ]] || die "--rollback needs root"; rollback_quiet; "$SSHD" -t && reload_sshd && echo "rolled back: sysmon hardening removed, sshd reloaded"; }

case "${1:-audit}" in
    audit|--audit) audit;;
    --apply) shift; apply "$@";;
    --rollback) rollback;;
    -h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//';;
    *) die "unknown option $1 (see --help)";;
esac
