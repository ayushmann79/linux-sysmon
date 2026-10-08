#!/usr/bin/env python3
"""
log-analyzer - security and error analysis for Linux logs (stdlib only).

Modes
  auth    SSH brute-force detection, successful logins, sudo usage (auth.log / secure / journal)
  syslog  error/warning/OOM/segfault counts, noisiest programs, top repeated messages

Examples
  log-analyzer.py auth                          # auto-detects /var/log/auth.log or /var/log/secure
  log-analyzer.py auth --file samples/auth.log --threshold 5 --blocklist /tmp/block.txt
  log-analyzer.py auth --journal "24 hours ago"
  log-analyzer.py syslog --file /var/log/syslog --top 10
  log-analyzer.py auth --json

Exit code: 0 = clean, 1 = brute-force sources found (useful from cron).
"""
import argparse
import collections
import gzip
import json
import os
import re
import subprocess
import sys

AUTH_CANDIDATES = ["/var/log/auth.log", "/var/log/secure"]
SYSLOG_CANDIDATES = ["/var/log/syslog", "/var/log/messages"]

RE_FAILED = re.compile(r"Failed (?P<method>password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port")
RE_INVALID = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+)")
RE_ACCEPT = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port")
RE_SUDO = re.compile(r"sudo:\s+(?P<user>\S+) : .*?COMMAND=(?P<cmd>.*)$")
RE_SUDO_FAIL = re.compile(r"sudo:.*(?:authentication failure|incorrect password attempts)")
RE_STAMP = re.compile(r"^(?:[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")
RE_TIME = re.compile(r"(?:^|\s|T)(?P<h>\d{2}):\d{2}:\d{2}")
RE_PROG = re.compile(r"^\S+\s+\d+\s+[\d:]+\s+\S+\s+(?P<prog>[\w\-./]+)(?:\[\d+\])?:|^\S+T\S+\s+\S+\s+(?P<prog2>[\w\-./]+)(?:\[\d+\])?:")
SEVERITY = {
    "critical": re.compile(r"\b(panic|segfault|out of memory|oom-killer|killed process|call trace|i/o error)\b", re.I),
    "error": re.compile(r"\b(error|failed|failure|denied|refused|cannot|unable)\b", re.I),
    "warning": re.compile(r"\b(warn|warning|timeout|timed out|deprecated|retry)\b", re.I),
}


def stamp(ln):
    m = RE_STAMP.match(ln)
    return m.group(0) if m else ln[:15]


def open_log(path):
    return gzip.open(path, "rt", errors="replace") if path.endswith(".gz") else open(path, errors="replace")


def lines_from(args, candidates):
    if args.journal:
        cmd = ["journalctl", "--no-pager", "-o", "short-iso", "--since", args.journal]
        if args.cmd == "auth":
            cmd += ["-t", "sshd", "-t", "sudo"]
        out = subprocess.run(cmd, capture_output=True, text=True)
        return out.stdout.splitlines(), "journalctl --since '%s'" % args.journal
    path = args.file or next((p for p in candidates if os.path.exists(p)), None)
    if not path:
        sys.exit("no log file found; use --file PATH or --journal 'SINCE'")
    with open_log(path) as f:
        return f.read().splitlines(), path


def analyze_auth(lines, threshold):
    failed_by_ip = collections.Counter()
    users_by_ip = collections.defaultdict(set)
    failed_users = collections.Counter()
    hours = collections.Counter()
    accepted, sudo_cmds = [], collections.Counter()
    sudo_fail = 0
    first = last = None
    for ln in lines:
        m = RE_TIME.search(ln)
        h = m.group("h") if m else None
        f = RE_FAILED.search(ln)
        inv = RE_INVALID.search(ln) if not f else None
        if f or inv:
            m2 = f or inv
            ip, user = m2.group("ip"), m2.group("user")
            users_by_ip[ip].add(user)
            first = first or stamp(ln)
            last = stamp(ln)
            # Count only "Failed ..." lines: sshd also logs a separate "Invalid user" line
            # for the same attempt, so counting both would double the numbers.
            if f:
                failed_by_ip[ip] += 1
                failed_users[user] += 1
                if h:
                    hours[h] += 1
            continue
        a = RE_ACCEPT.search(ln)
        if a:
            accepted.append({"user": a["user"], "ip": a["ip"], "method": a["method"], "when": stamp(ln)})
            continue
        s = RE_SUDO.search(ln)
        if s:
            sudo_cmds[(s["user"], s["cmd"].strip()[:60])] += 1
        elif RE_SUDO_FAIL.search(ln):
            sudo_fail += 1
    attackers = [{"ip": ip, "attempts": n, "distinct_users": len(users_by_ip[ip]),
                  "sample_users": sorted(users_by_ip[ip])[:5]}
                 for ip, n in failed_by_ip.most_common() if n >= threshold]
    return {
        "total_failed": sum(failed_by_ip.values()),
        "unique_ips": len(failed_by_ip),
        "top_ips": [{"ip": ip, "attempts": n} for ip, n in failed_by_ip.most_common(10)],
        "top_users": [{"user": u, "attempts": n} for u, n in failed_users.most_common(10)],
        "by_hour": dict(sorted(hours.items())),
        "brute_force": attackers,
        "accepted_logins": accepted,
        "sudo": [{"user": u, "cmd": c, "count": n} for (u, c), n in sudo_cmds.most_common(10)],
        "sudo_failures": sudo_fail,
        "root_login_attempts": failed_users.get("root", 0),
    }


def analyze_syslog(lines, top):
    sev = collections.Counter()
    progs = collections.Counter()
    msgs = collections.Counter()
    for ln in lines:
        level = next((name for name, rx in SEVERITY.items() if rx.search(ln)), None)
        if not level:
            continue
        sev[level] += 1
        m = RE_PROG.search(ln)
        prog = (m.group("prog") or m.group("prog2")) if m else "unknown"
        progs[prog] += 1
        body = ln.split(": ", 1)[-1]
        body = re.sub(r"0x[0-9a-f]+|\d+", "N", body)[:90]       # collapse numbers so repeats group together
        msgs[(level, body)] += 1
    return {
        "lines": len(lines),
        "by_severity": dict(sev),
        "top_programs": [{"program": p, "events": n} for p, n in progs.most_common(top)],
        "top_messages": [{"level": l, "message": m, "count": n} for (l, m), n in msgs.most_common(top)],
    }


def render_auth(r, source, threshold):
    L = ["=" * 70, f" SSH / AUTH LOG ANALYSIS   source: {source}", "=" * 70,
         f" Failed logins: {r['total_failed']}   unique source IPs: {r['unique_ips']}   "
         f"root attempts: {r['root_login_attempts']}   sudo failures: {r['sudo_failures']}", ""]
    L.append(f"-- BRUTE-FORCE SOURCES (>= {threshold} failures) " + "-" * 20)
    if r["brute_force"]:
        L.append(f"  {'IP':<18}{'ATTEMPTS':>9}{'USERS':>7}  USERNAMES TRIED")
        L += [f"  {b['ip']:<18}{b['attempts']:>9}{b['distinct_users']:>7}  {', '.join(b['sample_users'])}" for b in r["brute_force"]]
    else:
        L.append("  none")
    L += ["", "-- MOST TARGETED USERNAMES " + "-" * 40]
    L += [f"  {u['user']:<20}{u['attempts']:>6}" for u in r["top_users"][:8]] or ["  none"]
    L += ["", "-- FAILURES BY HOUR " + "-" * 47]
    mx = max(r["by_hour"].values(), default=1)
    L += [f"  {h}:00 {'#' * max(1, int(30 * n / mx))} {n}" for h, n in r["by_hour"].items()] or ["  none"]
    L += ["", "-- SUCCESSFUL LOGINS " + "-" * 46]
    L += [f"  {a['when']}  {a['user']:<10} from {a['ip']:<16} via {a['method']}" for a in r["accepted_logins"][:10]] or ["  none"]
    L += ["", "-- SUDO USAGE " + "-" * 52]
    L += [f"  {s['user']:<10} x{s['count']:<3} {s['cmd']}" for s in r["sudo"]] or ["  none"]
    L.append("=" * 70)
    return "\n".join(L)


def render_syslog(r, source):
    L = ["=" * 70, f" SYSLOG ANALYSIS   source: {source}   lines: {r['lines']}", "=" * 70,
         "  Severity counts: " + (", ".join(f"{k}={v}" for k, v in r["by_severity"].items()) or "none"), "",
         "-- NOISIEST PROGRAMS " + "-" * 46]
    L += [f"  {p['program']:<28}{p['events']:>6}" for p in r["top_programs"]] or ["  none"]
    L += ["", "-- MOST REPEATED PROBLEM MESSAGES " + "-" * 33]
    L += [f"  [{m['level']:<8}] x{m['count']:<4} {m['message']}" for m in r["top_messages"]] or ["  none"]
    L.append("=" * 70)
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description="Linux log analyzer")
    ap.add_argument("cmd", choices=["auth", "syslog"])
    ap.add_argument("--file", help="log file (.gz supported)")
    ap.add_argument("--journal", metavar="SINCE", help="read from journalctl instead, e.g. '24 hours ago'")
    ap.add_argument("--threshold", type=int, default=5, help="failures before an IP is flagged (auth)")
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--blocklist", help="write flagged IPs to this file (one per line)")
    ap.add_argument("--out", help="also write the report to this file")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    lines, source = lines_from(args, AUTH_CANDIDATES if args.cmd == "auth" else SYSLOG_CANDIDATES)
    if args.cmd == "auth":
        r = analyze_auth(lines, args.threshold)
        text = json.dumps(r, indent=2) if args.json else render_auth(r, source, args.threshold)
        if args.blocklist:
            with open(args.blocklist, "w") as f:
                f.write("".join(b["ip"] + "\n" for b in r["brute_force"]))
        code = 1 if r["brute_force"] else 0
    else:
        r = analyze_syslog(lines, args.top)
        text = json.dumps(r, indent=2) if args.json else render_syslog(r, source)
        code = 0
    print(text)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w") as f:
            f.write(text + "\n")
    sys.exit(code)


if __name__ == "__main__":
    main()
