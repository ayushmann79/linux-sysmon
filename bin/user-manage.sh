#!/usr/bin/env bash
# user-manage.sh - user, permission and account-security management.
#
#   user-manage.sh add <user> [--sudo] [--key "ssh-ed25519 AAAA..."] [--expire YYYY-MM-DD]
#   user-manage.sh lock|unlock <user>
#   user-manage.sh remove <user> [--keep-home]
#   user-manage.sh list                 normal login users with last login + password status
#   user-manage.sh audit                security audit (read-only)
#   user-manage.sh fix-perms            tighten home dirs, ~/.ssh and authorized_keys
set -uo pipefail

SUDO_GROUP=$(getent group sudo >/dev/null && echo sudo || echo wheel)
MIN_UID=$(awk '/^UID_MIN/{print $2}' /etc/login.defs 2>/dev/null); MIN_UID=${MIN_UID:-1000}
ok()   { printf '  [ OK ] %s\n' "$*"; }
warn() { printf '  [WARN] %s\n' "$*"; ISSUES=$((ISSUES+1)); }
die()  { echo "error: $*" >&2; exit 1; }
need_root() { [[ $EUID -eq 0 ]] || die "this command needs root (use sudo)"; }
valid_name() { [[ $1 =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "invalid username '$1' (lowercase letters, digits, _ and -)"; }
human_users() { getent passwd | awk -F: -v min="$MIN_UID" '$3>=min && $3<60000 {print $1}'; }

cmd_add() {
    need_root; local user=${1:-}; shift || true; valid_name "$user"
    id "$user" &>/dev/null && die "user $user already exists"
    local sudo=0 key="" expire=""
    while (( $# )); do case $1 in
        --sudo) sudo=1;; --key) key=$2; shift;; --expire) expire=$2; shift;; *) die "unknown option $1";; esac; shift; done
    useradd --create-home --shell /bin/bash --user-group "$user" || die "useradd failed"
    passwd -l "$user" >/dev/null                       # no password login until one is set; keys only
    chmod 750 "/home/$user"                            # other users cannot browse the home directory
    if [[ -n $key ]]; then
        install -d -m 700 -o "$user" -g "$user" "/home/$user/.ssh"
        printf '%s\n' "$key" > "/home/$user/.ssh/authorized_keys"
        chown "$user:$user" "/home/$user/.ssh/authorized_keys"; chmod 600 "/home/$user/.ssh/authorized_keys"
    fi
    (( sudo )) && usermod -aG "$SUDO_GROUP" "$user"
    [[ -n $expire ]] && chage -E "$expire" "$user"
    chage -M 90 -m 1 -W 14 "$user"                     # password aging: max 90d, warn 14d before
    logger -t user-manage "created user $user (sudo=$sudo)"
    echo "created $user  home=/home/$user (750)  sudo=$sudo  key=$([[ -n $key ]] && echo installed || echo none)  password=locked"
}

cmd_lock()   { need_root; id "$1" &>/dev/null || die "no such user"; usermod -L -e 1 "$1" && logger -t user-manage "locked $1" && echo "locked $1 (password + account expired; existing sessions are NOT killed)"; }
cmd_unlock() {
    need_root; id "$1" &>/dev/null || die "no such user"
    chage -E -1 "$1"                                   # remove the account expiry set by `lock`
    # Only unlock the password if one exists; key-only accounts ("!" with no hash) stay password-less-locked.
    if getent shadow "$1" | cut -d: -f2 | grep -qE '^!.+'; then usermod -U "$1"; fi
    logger -t user-manage "unlocked $1"; echo "unlocked $1 (key-only accounts keep their password locked, which is intended)"
}

cmd_remove() {
    need_root; local user=${1:-}; valid_name "$user"; id "$user" &>/dev/null || die "no such user"
    [[ $(id -u "$user") -eq 0 ]] && die "refusing to remove a UID 0 account"
    pkill -KILL -u "$user" 2>/dev/null || true
    if [[ ${2:-} == --keep-home ]]; then userdel "$user"; else userdel --remove "$user"; fi
    logger -t user-manage "removed $user"; echo "removed $user"
}

cmd_list() {
    printf '%-16s %-6s %-9s %-10s %-9s %s\n' USER UID SUDO PASSWORD SHELL LAST-LOGIN
    for u in $(human_users); do
        local st; st=$(passwd -S "$u" 2>/dev/null | awk '{print $2}')
        case $st in L|LK) st=locked;; P|PS) st=set;; NP) st=EMPTY!;; *) st=${st:-?};; esac
        id -nG "$u" | tr ' ' '\n' | grep -qx "$SUDO_GROUP" && s=yes || s=no
        last=$(lastlog -u "$u" 2>/dev/null | awk 'NR==2{ if ($0 ~ /Never/) print "never"; else print $4,$5,$6,$7 }')
        printf '%-16s %-6s %-9s %-10s %-9s %s\n' "$u" "$(id -u "$u")" "$s" "$st" "$(getent passwd "$u" | awk -F: '{n=split($7,a,"/"); print a[n]}')" "${last:-n/a}"
    done
}

cmd_audit() {
    ISSUES=0
    echo "== Accounts =="
    extra=$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd)
    [[ -z $extra ]] && ok "only root has UID 0" || warn "extra UID 0 accounts: $extra"
    if [[ -r /etc/shadow ]]; then
        empty=$(awk -F: '$2==""{print $1}' /etc/shadow)
        [[ -z $empty ]] && ok "no accounts with an empty password" || warn "EMPTY password: $empty"
    else echo "  [SKIP] /etc/shadow not readable (run as root)"; fi
    sudoers=$(getent group "$SUDO_GROUP" | cut -d: -f4)
    echo "  members of $SUDO_GROUP: ${sudoers:-none}"
    if [[ -d /etc/sudoers.d || -r /etc/sudoers ]]; then
        nop=$(grep -rhE '^[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null)
        [[ -z $nop ]] && ok "no NOPASSWD sudo rules" || warn "NOPASSWD sudo rules present: $(echo "$nop" | head -n2 | tr '\n' ';')"
    fi
    dupuid=$(getent passwd | awk -F: '{print $3}' | sort | uniq -d | head -n3 | tr '\n' ' ')
    [[ -z $dupuid ]] && ok "no duplicate UIDs" || warn "duplicate UIDs: $dupuid"

    echo "== Home directories & SSH keys =="
    for u in $(human_users); do
        h=$(getent passwd "$u" | cut -d: -f6); [[ -d $h ]] || continue
        mode=$(stat -c %a "$h")
        if (( 8#$mode & 8#007 )); then warn "$h is $mode - world-accessible (want 750 or 700)"; else ok "$h is $mode"; fi
        [[ -d $h/.ssh ]] && { m=$(stat -c %a "$h/.ssh"); [[ $m == 700 ]] || warn "$h/.ssh is $m (want 700)"; }
        [[ -f $h/.ssh/authorized_keys ]] && { m=$(stat -c %a "$h/.ssh/authorized_keys"); [[ $m == 600 || $m == 400 ]] || warn "authorized_keys of $u is $m (want 600)"; }
    done

    echo "== Critical file permissions =="
    for spec in "/etc/passwd:644" "/etc/shadow:640,600,000,0" "/etc/group:644" "/etc/sudoers:440" "/etc/ssh/sshd_config:644,600"; do
        f=${spec%%:*}; want=${spec#*:}; [[ -e $f ]] || continue
        m=$(stat -c %a "$f"); [[ ,$want, == *,$m,* ]] && ok "$f is $m" || warn "$f is $m (expected $want)"
    done
    ww=$(find /etc -xdev -type f -perm -0002 2>/dev/null | head -n5)
    [[ -z $ww ]] && ok "no world-writable files in /etc" || warn "world-writable in /etc: $(echo $ww)"

    echo "== SUID/SGID outside standard locations =="
    odd=$(find /usr /opt /home /tmp /var -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null \
          | grep -vE '^/usr/(bin|sbin|lib|libexec)/' | head -n5)
    [[ -z $odd ]] && ok "none found" || warn "unusual SUID/SGID files: $(echo $odd)"
    echo
    echo "Audit finished: $ISSUES issue(s)."; (( ISSUES == 0 ))
}

cmd_fix_perms() {
    need_root
    for u in $(human_users); do
        h=$(getent passwd "$u" | cut -d: -f6); [[ -d $h ]] || continue
        chmod 750 "$h"
        [[ -d $h/.ssh ]] && { chmod 700 "$h/.ssh"; find "$h/.ssh" -type f -name authorized_keys -exec chmod 600 {} +; }
        echo "fixed $u: $h -> 750"
    done
}

case "${1:-}" in
    add) shift; cmd_add "$@";;
    lock) cmd_lock "${2:?user}";;   unlock) cmd_unlock "${2:?user}";;
    remove) shift; cmd_remove "$@";;
    list) cmd_list;;   audit) cmd_audit;;   fix-perms) cmd_fix_perms;;
    *) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 64;;
esac
