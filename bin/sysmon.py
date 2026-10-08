#!/usr/bin/env python3
"""
sysmon - lightweight Linux monitoring agent.

Pure standard library. Metrics are read straight from the kernel interfaces
(/proc, /sys, statvfs) instead of wrapping tools like top/free/df, so every
number can be traced back to its source.

Usage:
    sysmon.py report [--section cpu,memory,...] [--json] [--save] [--no-actions]
    sysmon.py daemon [--no-actions]
    sysmon.py history [--last N]

Exit code of `report`: 0 = OK, 1 = WARNING, 2 = CRITICAL  (cron/Nagios friendly)
"""
import argparse
import configparser
import json
import logging
import logging.handlers
import os
import pwd
import shutil
import signal
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

VERSION = "1.0.0"
CLK_TCK = os.sysconf("SC_CLK_TCK")
PAGE_KB = os.sysconf("SC_PAGE_SIZE") // 1024
SECTIONS = ["info", "cpu", "memory", "disk", "network", "processes", "services"]

DEFAULTS = {
    "general": {
        "interval": "60",
        "report_dir": "/var/log/sysmon/reports",
        "state_dir": "/var/lib/sysmon",
        "log_file": "/var/log/sysmon/sysmon.log",
        "history_limit": "1440",
        "keep_reports": "100",
    },
    "thresholds": {
        "cpu_warn": "75", "cpu_crit": "90",
        "mem_warn": "80", "mem_crit": "92",
        "swap_warn": "50", "swap_crit": "80",
        "disk_warn": "80", "disk_crit": "90",
        "inode_warn": "80", "inode_crit": "90",
        "load_warn": "1.0", "load_crit": "2.0",   # per CPU core (1-minute load)
        "zombie_warn": "5",
    },
    "services": {"watch": "ssh|sshd, cron|crond, rsyslog", "auto_restart": "yes"},
    "network": {"allowed_ports": ""},   # empty = do not check exposure
    "processes": {"top_n": "5"},
    "actions": {
        "enabled": "yes",
        "dry_run": "yes",               # SAFE DEFAULT: log what would be done
        "restart_cooldown": "300",
        "cleanup_paths": "/tmp, /var/tmp",
        "cleanup_days": "7",
        "cleanup_cooldown": "3600",
    },
}

PSEUDO_FS = {
    "proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "cgroup", "cgroup2", "securityfs",
    "pstore", "bpf", "autofs", "mqueue", "hugetlbfs", "debugfs", "tracefs", "configfs",
    "fusectl", "binfmt_misc", "squashfs", "ramfs", "nsfs", "efivarfs", "rpc_pipefs",
}
PROTECTED_DIRS = {"/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64",
                  "/opt", "/proc", "/root", "/sbin", "/sys", "/usr", "/var"}

log = logging.getLogger("sysmon")


# --------------------------------------------------------------------------- config
def load_config(path=None):
    cfg = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
    cfg.read_dict(DEFAULTS)
    here = Path(__file__).resolve().parent.parent / "config" / "sysmon.conf"
    candidates = [path] if path else ["/etc/sysmon/sysmon.conf", str(here)]
    loaded = None
    for p in candidates:
        if p and os.path.isfile(p):
            cfg.read(p)
            loaded = p
            break
    cfg.read_dict({"_meta": {"path": loaded or "(built-in defaults)"}})
    return cfg


def as_list(value):
    return [x.strip() for x in value.split(",") if x.strip()]


def yes(value):
    return str(value).strip().lower() in ("1", "yes", "true", "on")


def writable_dir(preferred, name):
    """Return `preferred` if we can write there, else a per-user fallback."""
    try:
        os.makedirs(preferred, exist_ok=True)
        if os.access(preferred, os.W_OK):
            return preferred
    except OSError:
        pass
    fallback = os.path.join(os.path.expanduser("~"), ".local", "state", "sysmon", name)
    os.makedirs(fallback, exist_ok=True)
    return fallback


def setup_logging(cfg, to_stdout=False):
    log.setLevel(logging.INFO)
    log.handlers.clear()
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%Y-%m-%d %H:%M:%S")
    log_file = cfg["general"]["log_file"]
    d = writable_dir(os.path.dirname(log_file), "log")
    fh = logging.handlers.WatchedFileHandler(os.path.join(d, os.path.basename(log_file)))
    fh.setFormatter(fmt)
    log.addHandler(fh)
    if to_stdout:
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(fmt)
        log.addHandler(sh)


# --------------------------------------------------------------------------- collectors
def collect_info():
    u = os.uname()
    osr = {}
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    osr[k] = v.strip('"')
    except OSError:
        pass
    model = "unknown"
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith(("model name", "Model", "Hardware")):
                    model = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass
    with open("/proc/uptime") as f:
        up = float(f.read().split()[0])
    return {
        "hostname": socket.gethostname(),
        "os": osr.get("PRETTY_NAME", u.sysname),
        "kernel": u.release,
        "arch": u.machine,
        "cpu_model": model,
        "cpu_cores": os.cpu_count() or 1,
        "uptime_seconds": int(up),
        "uptime": fmt_duration(up),
        "boot_time": datetime.fromtimestamp(time.time() - up).strftime("%Y-%m-%d %H:%M:%S"),
        "logged_in_users": count_logged_in(),
    }


def count_logged_in():
    try:
        out = subprocess.run(["who"], capture_output=True, text=True, timeout=5).stdout
        return len([l for l in out.splitlines() if l.strip()])
    except (OSError, subprocess.SubprocessError):
        return 0


def fmt_duration(sec):
    sec = int(sec)
    d, r = divmod(sec, 86400)
    h, r = divmod(r, 3600)
    m, _ = divmod(r, 60)
    return (f"{d}d " if d else "") + f"{h}h {m}m"


def human(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{int(n)} B" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def cpu_stat():
    """Aggregate jiffies from the first line of /proc/stat."""
    with open("/proc/stat") as f:
        vals = [int(x) for x in f.readline().split()[1:]]
    return vals + [0] * (10 - len(vals))


def cpu_usage(a, b):
    """Percent busy between two /proc/stat samples (fields: user nice system idle iowait irq softirq steal)."""
    d = [y - x for x, y in zip(a, b)]
    total = sum(d[:8]) or 1
    idle = d[3] + d[4]
    pct = lambda n: round(100.0 * n / total, 1)
    l1, l5, l15 = os.getloadavg()
    cores = os.cpu_count() or 1
    return {
        "percent": round(100.0 * (total - idle) / total, 1),
        "user": pct(d[0] + d[1]), "system": pct(d[2] + d[5] + d[6]),
        "iowait": pct(d[4]), "steal": pct(d[7]),
        "load1": l1, "load5": l5, "load15": l15,
        "load_per_core": round(l1 / cores, 2), "cores": cores,
    }


def collect_memory():
    m = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, v = line.split(":", 1)
            m[k] = int(v.split()[0])           # kB
    total = m["MemTotal"]
    avail = m.get("MemAvailable", m["MemFree"] + m.get("Cached", 0))
    swap_t, swap_f = m.get("SwapTotal", 0), m.get("SwapFree", 0)
    return {
        "total": total * 1024, "available": avail * 1024, "used": (total - avail) * 1024,
        "percent": round(100.0 * (total - avail) / total, 1),
        "buffers_cache": (m.get("Buffers", 0) + m.get("Cached", 0)) * 1024,
        "swap_total": swap_t * 1024, "swap_used": (swap_t - swap_f) * 1024,
        "swap_percent": round(100.0 * (swap_t - swap_f) / swap_t, 1) if swap_t else 0.0,
    }


def collect_disk():
    disks, seen = [], set()
    with open("/proc/mounts") as f:
        for line in f:
            dev, mnt, fstype = line.split()[:3]
            if fstype in PSEUDO_FS or dev in seen:
                continue
            mnt = mnt.replace("\\040", " ")
            try:
                st = os.statvfs(mnt)
            except OSError:
                continue
            total = st.f_blocks * st.f_frsize
            if total == 0:
                continue
            seen.add(dev)
            used = (st.f_blocks - st.f_bfree) * st.f_frsize
            avail = st.f_bavail * st.f_frsize
            pct = round(100.0 * used / (used + avail), 1) if (used + avail) else 0.0   # same math as df
            ipct = round(100.0 * (st.f_files - st.f_ffree) / st.f_files, 1) if st.f_files else 0.0
            disks.append({"device": dev, "mount": mnt, "fstype": fstype, "total": total,
                          "used": used, "avail": avail, "percent": pct, "inode_percent": ipct})
    return disks


def net_snapshot():
    snap = {}
    with open("/proc/net/dev") as f:
        for line in list(f)[2:]:
            name, data = line.split(":", 1)
            v = [int(x) for x in data.split()]
            snap[name.strip()] = {"rx": v[0], "rx_err": v[2], "rx_drop": v[3],
                                  "tx": v[8], "tx_err": v[10], "tx_drop": v[11]}
    return snap


def listening_ports():
    ports = {}
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path) as f:
                next(f)
                for line in f:
                    p = line.split()
                    if p[3] != "0A":                      # 0A = LISTEN
                        continue
                    addr, port = p[1].split(":")
                    port = int(port, 16)
                    zeros = set(addr) == {"0"}
                    loop = addr in ("0100007F", "00000000000000000000000001000000")
                    scope = "all-interfaces" if zeros else "loopback" if loop else "specific"
                    if port not in ports or scope == "all-interfaces":
                        ports[port] = scope
        except OSError:
            pass
    return [{"port": p, "scope": s} for p, s in sorted(ports.items())]


def collect_network(a, b, elapsed):
    ifaces = []
    for name, now in b.items():
        if name == "lo":
            continue
        prev = a.get(name, now)
        try:
            with open(f"/sys/class/net/{name}/operstate") as f:
                state = f.read().strip()
        except OSError:
            state = "unknown"
        ifaces.append({
            "name": name, "state": state,
            "rx_total": now["rx"], "tx_total": now["tx"],
            "rx_rate": round((now["rx"] - prev["rx"]) / elapsed, 1),
            "tx_rate": round((now["tx"] - prev["tx"]) / elapsed, 1),
            "errors": now["rx_err"] + now["tx_err"], "drops": now["rx_drop"] + now["tx_drop"],
        })
    return {"interfaces": ifaces, "listening": listening_ports()}


def proc_snapshot():
    snap = {}
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/stat") as f:
                raw = f.read()
        except OSError:
            continue                                      # process exited while we scanned
        rp = raw.rfind(")")                               # comm may contain spaces/parens
        comm = raw[raw.find("(") + 1:rp]
        rest = raw[rp + 2:].split()
        snap[int(pid)] = {"comm": comm, "state": rest[0],
                          "ticks": int(rest[11]) + int(rest[12]),     # utime + stime
                          "rss_kb": int(rest[21]) * PAGE_KB}
    return snap


def describe(pid, fallback):
    user, cmd = "?", fallback
    try:
        user = pwd.getpwuid(os.stat(f"/proc/{pid}").st_uid).pw_name
    except (OSError, KeyError):
        pass
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            raw = f.read().replace(b"\0", b" ").decode(errors="replace").strip()
            cmd = raw or f"[{fallback}]"
    except OSError:
        pass
    return user, cmd[:70]


def collect_processes(a, b, elapsed, top_n):
    rows = []
    for pid, now in b.items():
        prev = a.get(pid, now)
        cpu = (now["ticks"] - prev["ticks"]) / CLK_TCK / elapsed * 100
        rows.append((pid, now, round(cpu, 1)))
    states = {}
    for _, p, _ in rows:
        states[p["state"]] = states.get(p["state"], 0) + 1

    def entry(pid, p, cpu):
        user, cmd = describe(pid, p["comm"])
        return {"pid": pid, "user": user, "cpu": cpu, "rss": p["rss_kb"] * 1024, "cmd": cmd}

    top_cpu = [entry(*r) for r in sorted(rows, key=lambda r: r[2], reverse=True)[:top_n]]
    top_mem = [entry(*r) for r in sorted(rows, key=lambda r: r[1]["rss_kb"], reverse=True)[:top_n]]
    zombies = [{"pid": pid, "name": p["comm"]} for pid, p, _ in rows if p["state"] == "Z"]
    return {"total": len(rows), "running": states.get("R", 0),
            "sleeping": states.get("S", 0) + states.get("D", 0) + states.get("I", 0),
            "stopped": states.get("T", 0), "zombies": zombies, "top_cpu": top_cpu, "top_mem": top_mem}


def systemd_available():
    return shutil.which("systemctl") is not None and os.path.isdir("/run/systemd/system")


def systemctl(*args):
    return subprocess.run(["systemctl", *args], capture_output=True, text=True, timeout=15)


def resolve_unit(spec):
    """'ssh|sshd' -> first alias systemd actually knows about."""
    names = [n.strip() for n in spec.split("|")]
    for n in names:
        r = systemctl("show", f"{n}.service", "-p", "LoadState", "--value")
        if r.stdout.strip() == "loaded":
            return n
    return names[0]


def collect_services(cfg):
    if not systemd_available():
        return {"available": False, "units": [], "failed": []}
    units = []
    for spec in as_list(cfg["services"]["watch"]):
        name = resolve_unit(spec)
        active = systemctl("is-active", f"{name}.service").stdout.strip() or "unknown"
        enabled = systemctl("is-enabled", f"{name}.service").stdout.strip() or "unknown"
        units.append({"name": name, "active": active, "enabled": enabled})
    failed = [l.split()[0] for l in systemctl("--failed", "--no-legend", "--plain").stdout.splitlines() if l.strip()]
    return {"available": True, "units": units, "failed": failed}


def collect_all(cfg, interval=1.0):
    """Take two samples `interval` seconds apart so rates (CPU%, bytes/s) are real deltas."""
    cpu_a, net_a, proc_a, t0 = cpu_stat(), net_snapshot(), proc_snapshot(), time.monotonic()
    info, mem, disks, services = collect_info(), collect_memory(), collect_disk(), collect_services(cfg)
    time.sleep(interval)
    cpu_b, net_b, proc_b = cpu_stat(), net_snapshot(), proc_snapshot()
    elapsed = max(time.monotonic() - t0, 0.001)
    return {
        "version": VERSION,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "host": info["hostname"],
        "info": info,
        "cpu": cpu_usage(cpu_a, cpu_b),
        "memory": mem,
        "disk": disks,
        "network": collect_network(net_a, net_b, elapsed),
        "processes": collect_processes(proc_a, proc_b, elapsed, int(cfg["processes"]["top_n"])),
        "services": services,
    }


# --------------------------------------------------------------------------- evaluation
def grade(value, warn, crit):
    return "CRITICAL" if value >= crit else "WARNING" if value >= warn else "OK"


def evaluate(d, cfg):
    t = {k: float(v) for k, v in cfg["thresholds"].items()}
    findings = []

    def check(value, w, c, comp, label, unit="%"):
        lvl = grade(value, t[w], t[c])
        if lvl != "OK":
            findings.append({"level": lvl, "component": comp,
                             "message": f"{label} is {value}{unit} (warn {t[w]:g}, crit {t[c]:g})"})

    check(d["cpu"]["percent"], "cpu_warn", "cpu_crit", "cpu", "CPU usage")
    check(d["cpu"]["load_per_core"], "load_warn", "load_crit", "cpu", "Load per core", "")
    check(d["memory"]["percent"], "mem_warn", "mem_crit", "memory", "Memory usage")
    if d["memory"]["swap_total"]:
        check(d["memory"]["swap_percent"], "swap_warn", "swap_crit", "memory", "Swap usage")
    for disk in d["disk"]:
        check(disk["percent"], "disk_warn", "disk_crit", "disk", f"Disk {disk['mount']}")
        check(disk["inode_percent"], "inode_warn", "inode_crit", "disk", f"Inodes {disk['mount']}")
    if len(d["processes"]["zombies"]) >= t["zombie_warn"]:
        findings.append({"level": "WARNING", "component": "processes",
                         "message": f"{len(d['processes']['zombies'])} zombie processes"})
    allowed = {int(p) for p in as_list(cfg["network"]["allowed_ports"])}
    if allowed:
        for lp in d["network"]["listening"]:
            if lp["scope"] == "all-interfaces" and lp["port"] not in allowed:
                findings.append({"level": "WARNING", "component": "network",
                                 "message": f"Unexpected port {lp['port']} listening on all interfaces"})
    svc = d["services"]
    for u in svc["units"]:
        if u["active"] != "active":
            findings.append({"level": "CRITICAL", "component": "services",
                             "message": f"Service {u['name']} is {u['active']}"})
    for name in svc["failed"]:
        findings.append({"level": "WARNING", "component": "services", "message": f"Failed unit: {name}"})

    rank = {"OK": 0, "WARNING": 1, "CRITICAL": 2}
    status = max((f["level"] for f in findings), key=rank.get, default="OK")
    score = max(0, 100 - sum(25 if f["level"] == "CRITICAL" else 10 for f in findings))
    return findings, status, score


# --------------------------------------------------------------------------- automated actions
def state_path(cfg):
    return os.path.join(writable_dir(cfg["general"]["state_dir"], "state"), "state.json")


def load_state(cfg):
    try:
        with open(state_path(cfg)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(cfg, st):
    with open(state_path(cfg), "w") as f:
        json.dump(st, f)


def cleanup_old_files(paths, days, dry_run):
    cutoff, count, size = time.time() - days * 86400, 0, 0
    for p in paths:
        real = os.path.realpath(p)
        if real in PROTECTED_DIRS or not os.path.isdir(real):
            log.warning("cleanup: refusing/skipping %s", p)
            continue
        for root, _, files in os.walk(real, followlinks=False):
            for name in files:
                fp = os.path.join(root, name)
                try:
                    st = os.lstat(fp)
                    if os.path.islink(fp) or st.st_mtime > cutoff or st.st_atime > cutoff:
                        continue
                    if not dry_run:
                        os.unlink(fp)
                    count, size = count + 1, size + st.st_size
                except OSError:
                    continue
    return count, size


def run_actions(d, findings, cfg):
    a = cfg["actions"]
    if not yes(a["enabled"]):
        return []
    dry = yes(a["dry_run"])
    tag = "[DRY-RUN] " if dry else ""
    state, now, taken = load_state(cfg), time.time(), []

    # 1) restart dead services (with cooldown so we never restart-loop a broken unit)
    if yes(cfg["services"]["auto_restart"]) and d["services"]["available"]:
        for u in d["services"]["units"]:
            if u["active"] == "active":
                continue
            key = f"restart:{u['name']}"
            if now - state.get(key, 0) < float(a["restart_cooldown"]):
                taken.append(f"{tag}skip restart {u['name']} (cooldown)")
                continue
            if dry:
                taken.append(f"{tag}would run: systemctl restart {u['name']}")
            else:
                r = systemctl("restart", f"{u['name']}.service")
                ok = systemctl("is-active", f"{u['name']}.service").stdout.strip() == "active"
                taken.append(f"restarted {u['name']} -> {'active' if ok else 'STILL FAILING: ' + r.stderr.strip()}")
                state[key] = now

    # 2) free disk space when any filesystem is CRITICAL
    if any(f["level"] == "CRITICAL" and f["component"] == "disk" for f in findings):
        if now - state.get("cleanup", 0) >= float(a["cleanup_cooldown"]):
            n, size = cleanup_old_files(as_list(a["cleanup_paths"]), float(a["cleanup_days"]), dry)
            taken.append(f"{tag}disk cleanup: {n} files older than {a['cleanup_days']}d, {human(size)}")
            if not dry:
                state["cleanup"] = now
                if shutil.which("journalctl"):
                    subprocess.run(["journalctl", "--vacuum-size=200M"], capture_output=True)
        else:
            taken.append(f"{tag}skip disk cleanup (cooldown)")

    # 3) memory / zombies are *reported only* - killing processes automatically is too dangerous
    if any(f["component"] == "memory" and f["level"] == "CRITICAL" for f in findings):
        top = d["processes"]["top_mem"][0]
        taken.append(f"report-only: top memory consumer is PID {top['pid']} ({top['cmd'][:40]}, {human(top['rss'])})")

    for t in taken:
        log.warning("ACTION %s", t)
    if not dry:
        save_state(cfg, state)
    return taken


# --------------------------------------------------------------------------- rendering
def bar(pct, width=20):
    filled = int(round(min(pct, 100) / 100 * width))
    return "[" + "#" * filled + "." * (width - filled) + "]"


def render(d, sections):
    L, W = [], 74
    L += ["=" * W, f" SYSMON HEALTH REPORT   host={d['host']}   {d['timestamp']}", "=" * W,
          f" Overall status : {d['status']}    Health score : {d['score']}/100", ""]
    if "info" in sections:
        i = d["info"]
        L += ["-- SYSTEM " + "-" * (W - 10),
              f"  OS        : {i['os']}   kernel {i['kernel']} ({i['arch']})",
              f"  CPU       : {i['cpu_model']} x{i['cpu_cores']}",
              f"  Uptime    : {i['uptime']} (booted {i['boot_time']})   users logged in: {i['logged_in_users']}", ""]
    if "cpu" in sections:
        c = d["cpu"]
        L += ["-- CPU " + "-" * (W - 7),
              f"  Usage     : {bar(c['percent'])} {c['percent']}%   (user {c['user']}% sys {c['system']}% iowait {c['iowait']}% steal {c['steal']}%)",
              f"  Load avg  : {c['load1']:.2f} {c['load5']:.2f} {c['load15']:.2f}   per core (1m): {c['load_per_core']}  cores: {c['cores']}", ""]
    if "memory" in sections:
        m = d["memory"]
        L += ["-- MEMORY " + "-" * (W - 10),
              f"  RAM       : {bar(m['percent'])} {m['percent']}%   {human(m['used'])} used / {human(m['total'])}  (available {human(m['available'])})",
              f"  Swap      : {bar(m['swap_percent'])} {m['swap_percent']}%   {human(m['swap_used'])} / {human(m['swap_total'])}", ""]
    if "disk" in sections:
        L += ["-- DISK " + "-" * (W - 8), f"  {'MOUNT':<22}{'FS':<9}{'USED%':>6}  {'USAGE':<24}{'SIZE':>10}  INODE%"]
        for k in d["disk"]:
            L.append(f"  {k['mount'][:21]:<22}{k['fstype']:<9}{k['percent']:>6}  {bar(k['percent']):<24}{human(k['total']):>10}  {k['inode_percent']:>5}")
        L.append("")
    if "network" in sections:
        L += ["-- NETWORK " + "-" * (W - 11)]
        for n in d["network"]["interfaces"]:
            L.append(f"  {n['name']:<10}{n['state']:<8} rx {human(n['rx_total']):>10} ({human(n['rx_rate'])}/s)  tx {human(n['tx_total']):>10} ({human(n['tx_rate'])}/s)  err {n['errors']} drop {n['drops']}")
        lp = d["network"]["listening"]
        L.append("  Listening : " + (", ".join(f"{p['port']}({p['scope']})" for p in lp) if lp else "none"))
        L.append("")
    if "processes" in sections:
        p = d["processes"]
        L += ["-- PROCESSES " + "-" * (W - 13),
              f"  total {p['total']}  running {p['running']}  sleeping {p['sleeping']}  stopped {p['stopped']}  zombies {len(p['zombies'])}",
              f"  {'PID':>7} {'USER':<10}{'CPU%':>6} {'MEM':>10}  COMMAND (top by CPU)"]
        L += [f"  {x['pid']:>7} {x['user']:<10}{x['cpu']:>6} {human(x['rss']):>10}  {x['cmd'][:36]}" for x in p["top_cpu"]]
        L.append(f"  {'PID':>7} {'USER':<10}{'CPU%':>6} {'MEM':>10}  COMMAND (top by memory)")
        L += [f"  {x['pid']:>7} {x['user']:<10}{x['cpu']:>6} {human(x['rss']):>10}  {x['cmd'][:36]}" for x in p["top_mem"]]
        L.append("")
    if "services" in sections:
        s = d["services"]
        L += ["-- SERVICES " + "-" * (W - 12)]
        if not s["available"]:
            L.append("  systemd not available on this host - service checks skipped")
        else:
            for u in s["units"]:
                L.append(f"  {u['name']:<18}{u['active']:<10} enabled={u['enabled']}")
            L.append("  failed units: " + (", ".join(s["failed"]) or "none"))
        L.append("")
    L += ["-- FINDINGS " + "-" * (W - 12)]
    L += [f"  [{f['level']}] {f['component']}: {f['message']}" for f in d["findings"]] or ["  No problems detected."]
    L += ["", "-- AUTOMATED ACTIONS " + "-" * (W - 21)]
    L += [f"  {a}" for a in d["actions"]] or ["  None."]
    L.append("=" * W)
    return "\n".join(L)


# --------------------------------------------------------------------------- persistence
def persist(d, cfg, save_copy):
    state_dir = writable_dir(cfg["general"]["state_dir"], "state")
    report_dir = writable_dir(cfg["general"]["report_dir"], "reports")
    with open(os.path.join(state_dir, "latest.json"), "w") as f:
        json.dump(d, f, indent=2)
    hist = os.path.join(state_dir, "history.jsonl")
    slim = {"ts": d["timestamp"], "status": d["status"], "score": d["score"], "cpu": d["cpu"]["percent"],
            "mem": d["memory"]["percent"], "load1": d["cpu"]["load1"],
            "disk_max": max((x["percent"] for x in d["disk"]), default=0)}
    with open(hist, "a") as f:
        f.write(json.dumps(slim) + "\n")
    limit = int(cfg["general"]["history_limit"])
    with open(hist) as f:
        lines = f.readlines()
    if len(lines) > limit * 1.2:                       # trim in batches, not on every write
        with open(hist, "w") as f:
            f.writelines(lines[-limit:])
    text = render(d, SECTIONS)
    with open(os.path.join(report_dir, "latest.txt"), "w") as f:
        f.write(text + "\n")
    if save_copy or d["status"] != "OK":
        name = f"health-{datetime.now():%Y%m%d-%H%M%S}.txt"
        with open(os.path.join(report_dir, name), "w") as f:
            f.write(text + "\n")
        keep = int(cfg["general"]["keep_reports"])
        old = sorted(p for p in os.listdir(report_dir) if p.startswith("health-"))[:-keep]
        for p in old:
            os.unlink(os.path.join(report_dir, p))


def cycle(cfg, actions=True, save=False):
    d = collect_all(cfg)
    d["findings"], d["status"], d["score"] = evaluate(d, cfg)
    d["actions"] = run_actions(d, d["findings"], cfg) if actions else []
    persist(d, cfg, save)
    log.info("status=%s score=%s cpu=%s%% mem=%s%% findings=%d", d["status"], d["score"],
             d["cpu"]["percent"], d["memory"]["percent"], len(d["findings"]))
    for f in d["findings"]:
        log.warning("finding [%s] %s: %s", f["level"], f["component"], f["message"])
    return d


# --------------------------------------------------------------------------- commands
def cmd_report(args, cfg):
    d = cycle(cfg, actions=not args.no_actions, save=args.save)
    if args.json:
        print(json.dumps(d, indent=2))
    else:
        wanted = args.section.split(",") if args.section else SECTIONS
        bad = [s for s in wanted if s not in SECTIONS]
        if bad:
            sys.exit(f"unknown section(s): {bad}. choose from {SECTIONS}")
        print(render(d, wanted))
    return {"OK": 0, "WARNING": 1, "CRITICAL": 2}[d["status"]]


def cmd_daemon(args, cfg):
    stop, reload_flag = False, False

    def on_term(sig, frm):
        nonlocal stop
        stop = True

    def on_hup(sig, frm):
        nonlocal reload_flag
        reload_flag = True

    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)
    signal.signal(signal.SIGHUP, on_hup)
    log.info("sysmon %s daemon started (pid %d, config %s, dry_run=%s)", VERSION, os.getpid(),
             cfg["_meta"]["path"], cfg["actions"]["dry_run"])
    while not stop:
        if reload_flag:
            cfg, reload_flag = load_config(args.config), False
            log.info("configuration reloaded (SIGHUP)")
        started = time.time()
        try:
            cycle(cfg, actions=not args.no_actions)
        except Exception:                                  # a bad cycle must never kill the daemon
            log.exception("monitoring cycle failed")
        while not stop and not reload_flag and time.time() - started < float(cfg["general"]["interval"]):
            time.sleep(0.5)
    log.info("sysmon daemon stopped cleanly")
    return 0


def cmd_history(args, cfg):
    path = os.path.join(writable_dir(cfg["general"]["state_dir"], "state"), "history.jsonl")
    try:
        with open(path) as f:
            rows = [json.loads(l) for l in f.readlines()[-args.last:]]
    except OSError:
        sys.exit("no history yet - run `sysmon.py report` or start the daemon")
    print(f"{'TIME':<20}{'STATUS':<10}{'SCORE':>5}{'CPU%':>7}{'MEM%':>7}{'LOAD':>7}{'DISK%':>7}")
    for r in rows:
        print(f"{r['ts']:<20}{r['status']:<10}{r['score']:>5}{r['cpu']:>7}{r['mem']:>7}{r['load1']:>7.2f}{r['disk_max']:>7}")
    return 0


def main():
    ap = argparse.ArgumentParser(description="sysmon - Linux monitoring agent", prog="sysmon")
    ap.add_argument("--config", help="path to sysmon.conf")
    ap.add_argument("--version", action="version", version=f"sysmon {VERSION}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("report", help="collect once and print a health report")
    r.add_argument("--section", help=f"comma list of: {','.join(SECTIONS)}")
    r.add_argument("--json", action="store_true")
    r.add_argument("--save", action="store_true", help="also keep a timestamped copy")
    r.add_argument("--no-actions", action="store_true")
    dm = sub.add_parser("daemon", help="run continuously (used by systemd)")
    dm.add_argument("--no-actions", action="store_true")
    h = sub.add_parser("history", help="show recent samples")
    h.add_argument("--last", type=int, default=20)
    args = ap.parse_args()
    cfg = load_config(args.config)
    setup_logging(cfg, to_stdout=(args.cmd == "daemon"))
    sys.exit({"report": cmd_report, "daemon": cmd_daemon, "history": cmd_history}[args.cmd](args, cfg))


if __name__ == "__main__":
    main()
