# Linux Server Administration & Monitoring (`sysmon`)

A small but complete Linux administration platform: a monitoring agent that reads the kernel's own interfaces (`/proc`, `/sys`), turns what it sees into a health report, and takes **safe, automated actions** — plus the Bash tooling around it that a real sysadmin uses every day (backups, user/permission management, SSH hardening, log analysis, scheduled maintenance).

> **Scope:** Linux, Bash, Python (standard library only), systemd, cron, SSH, networking, permissions, logs.
> **Not used:** Docker, Kubernetes, AWS, third-party Python packages (no `psutil`, no `pip install`).

The goal is to demonstrate that you **understand Linux**, not just that you know commands. Where a typical script would call `top`, `free` or `df`, this project reads `/proc/stat`, `/proc/meminfo` and `statvfs()` itself and does the math — so every number can be explained.

---

## 1. Architecture

```
                         Linux Server
                              │
          ┌───────────────────┴────────────────────┐
          │       Monitoring Agent  (sysmon.py)     │   runs as a systemd service
          │   sample /proc twice, 1 s apart → deltas │   (cron health-check.sh is an
          └───┬───────┬───────┬───────┬───────┬─────┘    independent second opinion)
              │       │       │       │       │
             CPU     RAM    Disk   Network  Processes + Services
              └───────┴───────┴───┬───┴───────┘
                                  ▼
                    Evaluate against thresholds
                    (config/sysmon.conf: warn / crit)
                                  │
                                  ▼
                  Health Report  (text + JSON + history)
                  status OK/WARNING/CRITICAL · score 0-100
                                  │
                                  ▼
                        Automated Actions
         restart dead service │ clean old temp files when disk is critical
         (cooldowns, DRY-RUN by default, protected paths, never kills processes)

   Around the agent (cron + Bash):
   backup.sh · log-analyzer.py · maintenance.sh · user-manage.sh · ssh-harden.sh
```

## 2. Requirements → files

| Requirement | Where it lives |
|---|---|
| System information | `sysmon.py` → `collect_info()` (OS, kernel, CPU model, uptime, boot time) |
| CPU / RAM / Disk / Network monitoring | `sysmon.py` → `cpu_usage()`, `collect_memory()`, `collect_disk()`, `collect_network()` |
| Process monitoring | `sysmon.py` → `proc_snapshot()`, `collect_processes()` (top by CPU/memory, zombies) |
| Service monitoring | `sysmon.py` → `collect_services()` (systemd state, failed units) |
| **Server health checker** | `sysmon.py report` (full) and `health-check.sh` (pure Bash, Nagios-style exit codes) |
| **Disk-space monitor** | disk + inode usage per filesystem, thresholds, auto-cleanup |
| **Log analyzer** | `log-analyzer.py` (SSH brute force, sudo use, error/OOM counts) |
| **Backup script** | `backup.sh` (lock, space check, verify, SHA-256, rotation, restore test) |
| **User/permission management** | `user-manage.sh` (add/lock/unlock/remove/list/audit/fix-perms) |
| **SSH hardening** | `ssh-harden.sh` (audit, apply with lock-out protection, rollback) |
| **Cron jobs** | `cron/sysmon.cron` → `/etc/cron.d/sysmon` |
| **systemd service** | `systemd/sysmon.service` (resource-limited, sandboxed, reloadable) |
| **Bash automation** | `install.sh`, `uninstall.sh`, `maintenance.sh`, `demo.sh` and all the tools above |
| Automated maintenance | `maintenance.sh` + the agent's actions + logrotate |

## 3. Project structure

```
linux-sysmon/
├── README.md                  this file
├── install.sh / uninstall.sh  one-command (un)installation
├── demo.sh                    runs every component safely, regenerates sample_output/
├── bin/
│   ├── sysmon.py              monitoring agent  (report | daemon | history)
│   ├── health-check.sh        fast pure-Bash health check
│   ├── log-analyzer.py        auth + syslog analysis
│   ├── backup.sh              verified, rotated backups
│   ├── maintenance.sh         housekeeping
│   ├── user-manage.sh         users, permissions, security audit
│   └── ssh-harden.sh          SSH audit / harden / rollback
├── config/
│   ├── sysmon.conf            thresholds, services, actions
│   └── backup.conf            what/where/how long to back up
├── systemd/sysmon.service     the daemon unit
├── cron/sysmon.cron           scheduled jobs
├── logrotate/sysmon           keeps the project's own logs from growing forever
├── samples/                   realistic auth.log + syslog used by the demo
└── sample_output/             captured output of every component (see §8)
```

## 4. Quick start


```bash
cd linux-sysmon
chmod +x demo.sh bin/*
./demo.sh                      # add sudo to also run the user-management demo
cat sample_output/01-health-report.txt

./bin/sysmon.py report                      # live report on your machine
./bin/sysmon.py report --section cpu,memory # only some sections
./bin/sysmon.py report --json | less        # machine-readable
./bin/health-check.sh --quiet; echo $?      # 0=OK 1=WARNING 2=CRITICAL
```

Without root the agent writes to `~/.local/state/sysmon/` instead of `/var/...`.

### Install as a real service

```bash
sudo ./install.sh                 # copies to /opt/sysmon, enables the systemd service + cron jobs
sysmon report                     # command shortcut
sudo systemctl status sysmon
journalctl -u sysmon -f           # live agent log
sudo ./uninstall.sh [--purge]
```

The agent starts in **dry-run mode**: it logs what it *would* do (restart a service, delete old files) but changes nothing. Review `/var/log/sysmon/sysmon.log` for a day, then set `dry_run = no` in `/etc/sysmon/sysmon.conf` and `sudo systemctl reload sysmon`.

## 5. Components in detail

### 5.1 Monitoring agent — `bin/sysmon.py`

| Metric | Source | How it is computed |
|---|---|---|
| CPU % | `/proc/stat` | Two samples 1 s apart. `busy = 1 − Δidle/Δtotal`, where idle = idle + iowait. Also reports user/system/iowait/steal. |
| Load | `/proc/loadavg` | 1/5/15-min load, **divided by core count** (load 4.0 means something different on 2 vs 16 cores). |
| RAM | `/proc/meminfo` | Uses `MemAvailable` (what can really be allocated), not "free" — cache is not "used". |
| Swap | `/proc/meminfo` | `SwapTotal − SwapFree`. |
| Disk % + inodes | `/proc/mounts` + `statvfs()` | Same formula as `df` (`used / (used + available)`, so root-reserved blocks are handled). Pseudo-filesystems skipped. A disk can be "full" with free space if **inodes** run out, so both are checked. |
| Network | `/proc/net/dev`, `/sys/class/net/*/operstate` | Byte counters sampled twice → bytes/second. Errors and drops. |
| Listening ports | `/proc/net/tcp`, `tcp6` | State `0A` = LISTEN. Classified as loopback / all-interfaces; unexpected exposed ports raise a warning (`allowed_ports`). |
| Processes | `/proc/<pid>/stat`, `cmdline` | `utime+stime` ticks delta ÷ `CLK_TCK` ÷ elapsed → CPU %. RSS from `statm` pages. Zombie = state `Z`. The `comm` field can contain spaces/parentheses, so the parser splits at the *last* `)`. |
| Services | `systemctl is-active / is-enabled / --failed` | Aliases like `ssh\|sshd` pick whichever unit exists (Debian vs RHEL). |

**Health model.** Each finding is `WARNING` (−10 points) or `CRITICAL` (−25). Overall status is the worst finding. `report` exits `0/1/2`, so it plugs straight into cron, scripts or Nagios.

**Automated actions** (only when `[actions] enabled = yes`):

| Trigger | Action | Safety |
|---|---|---|
| Watched service not `active` | `systemctl restart` + verify it came back | cooldown (default 300 s) prevents restart loops |
| Any filesystem `CRITICAL` | delete regular files older than N days in `cleanup_paths`; vacuum journal to 200 MB | refuses `/`, `/etc`, `/usr`, `/var`, `/home`… ; never follows symlinks; cooldown; checks atime *and* mtime |
| Memory `CRITICAL` | **report only** (names the top consumer) | killing processes automatically is deliberately not implemented |

**Daemon behaviour.** `SIGTERM`/`SIGINT` finish the current cycle and exit cleanly; `SIGHUP` reloads the config (this is what `systemctl reload sysmon` sends); an exception in one cycle is logged and the loop continues. Logs use `WatchedFileHandler`, so logrotate can rotate them without signalling the process.

### 5.2 `health-check.sh` — the independent second opinion
Pure Bash + awk, no Python. If the Python agent ever crashes, this cron job (every 5 min) still reports. Output is one line per run for easy `grep`/graphing.

### 5.3 `log-analyzer.py`
* **auth mode:** counts failed SSH logins per IP, usernames tried, failures per hour, successful logins (and by what method), `sudo` commands and failures. IPs at or above `--threshold` are flagged and optionally written to a blocklist file (feed it to `ufw`/`fail2ban`/`nftables`). `sshd` logs both an `Invalid user` line and a `Failed password` line for one attempt, so only the latter is counted. Reads `.gz`, or `journalctl` with `--journal`.
* **syslog mode:** classifies lines as critical/error/warning, ranks the noisiest programs, and groups repeated messages by replacing numbers with `N` — so 9 different "connection refused" lines collapse into one finding.

### 5.4 `backup.sh`
`flock` (one run at a time) → free-space check → `tar --gzip` with excludes → `tar -t` integrity test → SHA-256 file → rotation by age → logging. `tar` exit code 1 ("file changed while reading", normal on a live system) is a warning, not a failure. Archives are created with `umask 077`. `--restore-test` verifies the checksum and extracts the newest archive to a temp dir — **a backup you have never restored is not a backup**; cron runs this monthly.

### 5.5 `user-manage.sh`
`add` creates a user with a locked password (key-only), a `750` home, an optional SSH key and expiry date, and password aging (`chage -M 90`). `lock` also expires the account so key logins stop too. `audit` is read-only and checks: extra UID 0 accounts, empty passwords, `NOPASSWD` sudo rules, duplicate UIDs, home/`.ssh`/`authorized_keys` modes, permissions of `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, world-writable files in `/etc`, and unexpected SUID/SGID binaries. `fix-perms` repairs home directory modes.

### 5.6 `ssh-harden.sh`
* **Audit** compares the *effective* configuration (`sshd -T`, which resolves `Include` and `Match`) with the baseline.
* **Apply** refuses if the invoking user has no `authorized_keys` (so you cannot lock yourself out), backs up the config, writes `/etc/ssh/sshd_config.d/00-sysmon-hardening.conf`, validates with `sshd -t`, and only then reloads. If validation fails it rolls back automatically.
* The drop-in is named **`00-`** on purpose: `sshd` uses the *first* value it reads for each keyword, and many cloud images ship `50-cloud-init.conf` with `PasswordAuthentication yes` — a `99-` file would silently lose.
* Baseline: no root login, no password auth, max 3 auth tries, 30 s login grace, no X11/agent forwarding, idle timeout, verbose logging; optional `--allow-users` and `--port`.

### 5.7 `maintenance.sh`
Removes unused temp files and old rotated logs, caps the journal, cleans the package cache, reports pending updates and "reboot required" (never auto-upgrades), and lists the biggest directories under `/var`. Supports `--dry-run`.

### 5.8 systemd unit and cron
The unit limits the agent to 128 MB RAM and 20 % CPU, runs it at `Nice=10`, and applies `NoNewPrivileges`, `ProtectSystem=full`, `ProtectKernelTunables` etc. with explicit `ReadWritePaths`. `Restart=on-failure` brings it back if it dies. The cron file schedules: health check (5 min), backup (daily 02:00), auth-log analysis (daily 06:30), maintenance (Sundays), user audit (Mondays), restore test (monthly).

## 6. Configuration

Everything is in `/etc/sysmon/sysmon.conf` (see `config/sysmon.conf`, fully commented):

```ini
[thresholds]   cpu_warn=75 cpu_crit=90 mem_warn=80 mem_crit=92 disk_warn=80 disk_crit=90 ...
[services]     watch = ssh|sshd, cron|crond, rsyslog
[network]      allowed_ports = 22
[actions]      enabled = yes   dry_run = yes   restart_cooldown = 300   cleanup_days = 7
```

Backups are configured in `/etc/sysmon/backup.conf` (`BACKUP_SOURCES`, `BACKUP_DEST`, `RETENTION_DAYS`, `EXCLUDES`).

## 7. Linux concepts this project demonstrates

| Concept | Where |
|---|---|
| The `/proc` and `/sys` virtual filesystems | all collectors |
| Jiffies, `CLK_TCK`, delta sampling | CPU and per-process CPU |
| `MemAvailable` vs "free", page size, RSS | memory, processes |
| `statvfs`, reserved blocks, inodes | disk |
| Process states (R/S/D/Z/T), zombies | process monitor |
| Sockets in `/proc/net/tcp`, bind scope | exposure check |
| Signals (`SIGTERM`, `SIGHUP`), graceful shutdown | daemon |
| systemd units, `Restart=`, resource limits, sandboxing, `reload` | `sysmon.service` |
| cron syntax, `/etc/cron.d` with a user field, `MAILTO` | `sysmon.cron` |
| File modes, `umask`, `chmod 750/700/600`, SUID/SGID | `user-manage.sh`, `backup.sh` |
| `useradd`, `chage`, `passwd -l`, `usermod -L -e`, sudo/wheel groups | `user-manage.sh` |
| sshd first-match-wins config, drop-ins, `sshd -t`, `sshd -T` | `ssh-harden.sh` |
| `flock`, `set -euo pipefail`, exit codes, traps | Bash scripts |
| logrotate, journald vacuuming, syslog formats | logs, maintenance |
| Idempotent, rollback-able, dry-run-first automation | everywhere |

## 8. Sample output

All files below were **captured by running `./demo.sh`** and are saved in `sample_output/`. They were produced on a small Ubuntu 24.04 VM (1 vCPU) used for testing. That VM has no running systemd, so the *Services* section reports "skipped", and the two "unexpected ports" (2024/2025) and the `fuse.rclone` mounts belong to that environment — which conveniently shows the exposure check and the disk filter working. On a normal server you will see your own services, disks and ports.

### 8.1 Full health report — `sample_output/01-health-report.txt`
```text
==========================================================================
 SYSMON HEALTH REPORT   host=vm   2026-10-07 06:36:24
==========================================================================
 Overall status : WARNING    Health score : 80/100

-- SYSTEM ----------------------------------------------------------------
  OS        : Ubuntu 24.04.4 LTS   kernel 6.18.44-fc-v77 (x86_64)
  CPU       : Intel(R) Xeon(R) Processor @ 2.10GHz x1
  Uptime    : 0h 6m (booted 2026-10-07 06:29:25)   users logged in: 0

-- CPU -------------------------------------------------------------------
  Usage     : [....................] 0.0%   (user 0.0% sys 0.0% iowait 0.0% steal 0.0%)
  Load avg  : 0.12 0.06 0.02   per core (1m): 0.12  cores: 1

-- MEMORY ----------------------------------------------------------------
  RAM       : [##..................] 9.7%   389.0 MB used / 3.9 GB  (available 3.5 GB)
  Swap      : [....................] 0.0%   0 B / 0 B

-- DISK ------------------------------------------------------------------
  MOUNT                 FS        USED%  USAGE                         SIZE  INODE%
  /                     ext4       46.2  [#########...........]    252.0 GB    1.2
  /mnt/user-data/tool_r fuse.rclone   0.0  [....................]   1024.0 TB    0.0
  /mnt/user-data/output fuse.rclone   0.0  [....................]   1024.0 TB    0.0
  /mnt/user-data/upload fuse.rclone   0.0  [....................]   1024.0 TB    0.0
  /mnt/transcripts      fuse.rclone   0.0  [....................]   1024.0 TB    0.0

-- NETWORK ---------------------------------------------------------------
  ifb0      down     rx        0 B (0 B/s)  tx        0 B (0 B/s)  err 0 drop 0
  ifb1      down     rx        0 B (0 B/s)  tx        0 B (0 B/s)  err 0 drop 0
  eth0      up       rx    13.8 MB (0 B/s)  tx   139.2 KB (0 B/s)  err 0 drop 6
  Listening : 2024(all-interfaces), 2025(all-interfaces)

-- PROCESSES -------------------------------------------------------------
  total 51  running 1  sleeping 50  stopped 0  zombies 0
      PID USER        CPU%        MEM  COMMAND (top by CPU)
        1 root         0.0     5.3 MB  /process_api --firecracker-init --ad
        2 root         0.0        0 B  [kthreadd]
        3 root         0.0        0 B  [pool_workqueue_release]
        4 root         0.0        0 B  [kworker/R-rcu_gp]
        5 root         0.0        0 B  [kworker/R-sync_wq]
      PID USER        CPU%        MEM  COMMAND (top by memory)
       55 root         0.0    32.8 MB  /opt/rclone/rclone-filestore multimo
     2581 root         0.0    16.9 MB  python3 /home/claude/linux-sysmon/bi
        1 root         0.0     5.3 MB  /process_api --firecracker-init --ad
     2575 root         0.0     3.3 MB  bash ./demo.sh
       54 ?            0.0     2.9 MB  sbx-telemetry-collector

-- SERVICES --------------------------------------------------------------
  systemd not available on this host - service checks skipped

-- FINDINGS --------------------------------------------------------------
  [WARNING] network: Unexpected port 2024 listening on all interfaces
  [WARNING] network: Unexpected port 2025 listening on all interfaces

-- AUTOMATED ACTIONS -----------------------------------------------------
  None.
==========================================================================
```

### 8.2 Automated actions — `sample_output/03-automated-actions.txt`
Thresholds were lowered to make the root disk look "critical"; first run is dry-run, second is live. The three 30-day-old files were removed, the fresh file was kept.
```text
### thresholds lowered to warn=1% crit=2% so the root filesystem looks full
### dry_run = yes (default): only logs what it WOULD do
files before: fresh.log old1.log old2.log old3.log 
==========================================================================
 SYSMON HEALTH REPORT   host=vm   2026-10-07 06:36:26
==========================================================================
 Overall status : CRITICAL    Health score : 55/100

-- DISK ------------------------------------------------------------------
  MOUNT                 FS        USED%  USAGE                         SIZE  INODE%
  /                     ext4       46.2  [#########...........]    252.0 GB    1.2
  /mnt/user-data/tool_r fuse.rclone   0.0  [....................]   1024.0 TB    0.0
  /mnt/user-data/output fuse.rclone   0.0  [....................]   1024.0 TB    0.0
  /mnt/user-data/upload fuse.rclone   0.0  [....................]   1024.0 TB    0.0
  /mnt/transcripts      fuse.rclone   0.0  [....................]   1024.0 TB    0.0

-- FINDINGS --------------------------------------------------------------
  [CRITICAL] disk: Disk / is 46.2% (warn 1, crit 2)
  [WARNING] network: Unexpected port 2024 listening on all interfaces
  [WARNING] network: Unexpected port 2025 listening on all interfaces

-- AUTOMATED ACTIONS -----------------------------------------------------
  [DRY-RUN] disk cleanup: 3 files older than 7d, 585.9 KB
==========================================================================

### dry_run = no: really deletes files older than 7 days (fresh files are kept)
==========================================================================
 SYSMON HEALTH REPORT   host=vm   2026-10-07 06:36:27
==========================================================================
 Overall status : CRITICAL    Health score : 55/100

-- DISK ------------------------------------------------------------------
  MOUNT                 FS        USED%  USAGE                         SIZE  INODE%
  /                     ext4       46.2  [#########...........]    252.0 GB    1.2
  /mnt/user-data/tool_r fuse.rclone   0.0  [....................]   1024.0 TB    0.0
  /mnt/user-data/output fuse.rclone   0.0  [....................]   1024.0 TB    0.0
  /mnt/user-data/upload fuse.rclone   0.0  [....................]   1024.0 TB    0.0
  /mnt/transcripts      fuse.rclone   0.0  [....................]   1024.0 TB    0.0

-- FINDINGS --------------------------------------------------------------
  [CRITICAL] disk: Disk / is 46.2% (warn 1, crit 2)
  [WARNING] network: Unexpected port 2024 listening on all interfaces
  [WARNING] network: Unexpected port 2025 listening on all interfaces

-- AUTOMATED ACTIONS -----------------------------------------------------
  disk cleanup: 3 files older than 7d, 585.9 KB
==========================================================================

files after:  fresh.log 
```

### 8.3 Daemon log (3 cycles, a `SIGHUP` reload, graceful `SIGTERM`) — `04-daemon-log.txt`
```text
2026-10-07 06:36:27 INFO    sysmon 1.0.0 daemon started (pid 2608, config <workdir>/demo.conf, dry_run=yes)
2026-10-07 06:36:28 INFO    status=WARNING score=80 cpu=0.0% mem=9.2% findings=2
2026-10-07 06:36:28 WARNING finding [WARNING] network: Unexpected port 2024 listening on all interfaces
2026-10-07 06:36:28 WARNING finding [WARNING] network: Unexpected port 2025 listening on all interfaces
2026-10-07 06:36:30 INFO    status=WARNING score=80 cpu=1.0% mem=9.2% findings=2
2026-10-07 06:36:30 WARNING finding [WARNING] network: Unexpected port 2024 listening on all interfaces
2026-10-07 06:36:30 WARNING finding [WARNING] network: Unexpected port 2025 listening on all interfaces
2026-10-07 06:36:32 INFO    status=WARNING score=80 cpu=1.0% mem=9.2% findings=2
2026-10-07 06:36:32 WARNING finding [WARNING] network: Unexpected port 2024 listening on all interfaces
2026-10-07 06:36:32 WARNING finding [WARNING] network: Unexpected port 2025 listening on all interfaces
2026-10-07 06:36:34 INFO    status=WARNING score=80 cpu=0.0% mem=9.2% findings=2
2026-10-07 06:36:34 WARNING finding [WARNING] network: Unexpected port 2024 listening on all interfaces
2026-10-07 06:36:34 WARNING finding [WARNING] network: Unexpected port 2025 listening on all interfaces
2026-10-07 06:36:34 INFO    configuration reloaded (SIGHUP)
2026-10-07 06:36:35 INFO    status=WARNING score=80 cpu=1.0% mem=9.2% findings=2
2026-10-07 06:36:35 WARNING finding [WARNING] network: Unexpected port 2024 listening on all interfaces
2026-10-07 06:36:35 WARNING finding [WARNING] network: Unexpected port 2025 listening on all interfaces
2026-10-07 06:36:37 INFO    status=WARNING score=80 cpu=0.0% mem=9.2% findings=2
2026-10-07 06:36:37 WARNING finding [WARNING] network: Unexpected port 2024 listening on all interfaces
2026-10-07 06:36:37 WARNING finding [WARNING] network: Unexpected port 2025 listening on all interfaces
2026-10-07 06:36:37 INFO    sysmon daemon stopped cleanly
```

### 8.4 History — `05-history.txt`
```text
TIME                STATUS    SCORE   CPU%   MEM%   LOAD  DISK%
2026-10-07 06:36:30 WARNING      80    1.0    9.2   0.11   46.2
2026-10-07 06:36:32 WARNING      80    1.0    9.2   0.10   46.2
2026-10-07 06:36:34 WARNING      80    0.0    9.2   0.10   46.2
2026-10-07 06:36:35 WARNING      80    1.0    9.2   0.10   46.2
2026-10-07 06:36:37 WARNING      80    0.0    9.2   0.09   46.2
```

### 8.5 Bash health check — `06-health-check.txt`
```text
Host      : vm    2026-10-07 06:36:38
Uptime    : up 7 minutes
CPU       :   0%  OK   (load 0.09 0.06 0.01 on 1 cores)
Memory    :   9%  OK
Disks     :
   /                         47%  OK
   /mnt/user-data/tool_results   0%  OK
   /mnt/user-data/outputs     0%  OK
   /mnt/user-data/uploads     0%  OK
   /mnt/transcripts           0%  OK
Zombies   : 0
OVERALL   : OK
exit code: 0

2026-10-07 06:36:39 OK - cpu=0% mem=9% disk=47%(/) load=0.09 zombies=0
```

### 8.6 SSH brute-force analysis — `07-log-analysis-auth.txt`
```text
======================================================================
 SSH / AUTH LOG ANALYSIS   source: /home/claude/linux-sysmon/samples/auth.log
======================================================================
 Failed logins: 50   unique source IPs: 4   root attempts: 19   sudo failures: 1

-- BRUTE-FORCE SOURCES (>= 5 failures) --------------------
  IP                 ATTEMPTS  USERS  USERNAMES TRIED
  185.220.101.47           34      7  admin, oracle, postgres, root, test
  103.77.12.9              12      1  root

-- MOST TARGETED USERNAMES ----------------------------------------
  root                    19
  admin                    8
  user                     6
  test                     5
  ubuntu                   4
  deploy                   3
  postgres                 2
  oracle                   2

-- FAILURES BY HOUR -----------------------------------------------
  02:00 ############################## 34
  03:00 ########## 12
  14:00 ## 3
  16:00 # 1

-- SUCCESSFUL LOGINS ----------------------------------------------
  Oct  6 09:01:12  ayush      from 203.0.113.10     via publickey
  Oct  6 09:40:03  deploy     from 203.0.113.55     via publickey
  Oct  6 16:02:49  ayush      from 203.0.113.10     via password

-- SUDO USAGE ----------------------------------------------------
  ayush      x2   /usr/bin/systemctl restart nginx
  ayush      x1   /usr/bin/apt-get update
  ayush      x1   /usr/bin/tail -f /var/log/auth.log
======================================================================
exit code: 1 (1 = brute-force sources found)

blocklist.txt:
185.220.101.47
103.77.12.9
```

### 8.7 Syslog analysis — `07-log-analysis-syslog.txt`
```text
======================================================================
 SYSLOG ANALYSIS   source: /home/claude/linux-sysmon/samples/syslog   lines: 26
======================================================================
  Severity counts: error=16, critical=3, warning=6

-- NOISIEST PROGRAMS ----------------------------------------------
  nginx                            9
  cron                             6
  systemd                          4
  kernel                           3
  postgres                         2
  sshd                             1

-- MOST REPEATED PROBLEM MESSAGES ---------------------------------
  [error   ] x9    [error] N#N: *N connect() failed (N: Connection refused) while connecting to upstream
  [warning ] x6    (CRON) warning: timeout waiting for lock N
  [error   ] x4    app.service: Failed with result 'exit-code'.
  [error   ] x2    ERROR:  permission denied for table users
  [critical] x1    [ N.N] Out of memory: Killed process N (java) total-vm:NkB
  [critical] x1    [ N.N] oom-killer: gfp_mask=N(GFP_HIGHUSER_MOVABLE)
======================================================================
```

### 8.8 Backup, checksum, restore test — `08-backup.txt`
```text
2026-10-07 06:36:39 [INFO] DRY RUN: would back up <workdir>/data (~0 MiB raw) to <workdir>/backups, keep 7d
2026-10-07 06:36:39 [INFO] starting backup of <workdir>/data -> backup-vm-20261007-063639.tar.gz
2026-10-07 06:36:39 [INFO] OK backup-vm-20261007-063639.tar.gz  size=4.0K  files=4  sha256=374365cf30b66814...
2026-10-07 06:36:39 [INFO] rotation: removed 0 old file(s), keeping 7 days
2026-10-07 06:36:39 [INFO] restore-test OK: backup-vm-20261007-063639.tar.gz -> 2 files extracted and checksum verified

-rw------- 1 root root 222 Oct  7 06:36 backup-vm-20261007-063639.tar.gz
-rw------- 1 root root  99 Oct  7 06:36 backup-vm-20261007-063639.tar.gz.sha256

374365cf30b66814306f13a3ee2b7ba0da778b0d251a78546066891d90eb29bf  backup-vm-20261007-063639.tar.gz
```

### 8.9 User management lifecycle and audit — `09-user-management.txt`
```text
created demo_ops  home=/home/demo_ops (750)  sudo=1  key=installed  password=locked
USER             UID    SUDO      PASSWORD   SHELL     LAST-LOGIN
ubuntu           1000   yes       locked     bash      never
demo_ops         1001   yes       locked     bash      never

$ chmod 777 /home/demo_ops   # simulate a mistake
  [WARN] /home/demo_ops is 777 - world-accessible (want 750 or 700)
Audit finished: 1 issue(s).

fixed demo_ops: /home/demo_ops -> 750
locked demo_ops (password + account expired; existing sessions are NOT killed)
unlocked demo_ops (key-only accounts keep their password locked, which is intended)
removed demo_ops

==== full audit afterwards ====
== Accounts ==
  [ OK ] only root has UID 0
  [ OK ] no accounts with an empty password
  members of sudo: ubuntu
  [ OK ] no duplicate UIDs
== Home directories & SSH keys ==
  [ OK ] /home/ubuntu is 750
== Critical file permissions ==
  [ OK ] /etc/passwd is 644
  [ OK ] /etc/shadow is 640
  [ OK ] /etc/group is 644
  [ OK ] /etc/ssh/sshd_config is 644
  [ OK ] no world-writable files in /etc
== SUID/SGID outside standard locations ==
  [ OK ] none found

Audit finished: 0 issue(s).
```

### 8.10 SSH audit (before hardening) — `10-ssh-audit.txt`
```text
SETTING                                CURRENT        STATUS
permitrootlogin                        without-password DIFFERS (want no)
passwordauthentication                 yes            DIFFERS (want no)
pubkeyauthentication                   yes            ok
permitemptypasswords                   no             ok
challengeresponseauthentication        no             ok
maxauthtries                           6              DIFFERS (want 3)
logingracetime                         120            DIFFERS (want 30)
x11forwarding                          yes            DIFFERS (want no)
allowagentforwarding                   yes            DIFFERS (want no)
permituserenvironment                  no             ok
clientaliveinterval                    0              DIFFERS (want 300)
clientalivecountmax                    3              DIFFERS (want 2)
loglevel                               INFO           DIFFERS (want VERBOSE)

port: 22 
9 setting(s) differ from the baseline.
```

### 8.11 Maintenance dry run — `11-maintenance-dry-run.txt`
```text
2026-10-07 06:36:41 [INFO] dry-run mode: nothing will be changed
2026-10-07 06:36:41 [INFO] /tmp: 560 file(s) unused for more than 7 days
2026-10-07 06:36:41 [INFO] /var/tmp: 0 file(s) unused for more than 7 days
2026-10-07 06:36:41 [INFO] /var/log: 0 rotated log file(s) older than 30 days
2026-10-07 06:36:41 [DRY] apt-get clean
2026-10-07 06:36:42 [INFO] apt: 207 package(s) upgradable
2026-10-07 06:36:42 [INFO] largest directories in /var:
2026-10-07 06:36:42 [INFO]    190M  /var/lib
2026-10-07 06:36:42 [INFO]    99M  /var/lib/texmf
2026-10-07 06:36:42 [INFO]    52M  /var/lib/apt
2026-10-07 06:36:42 [INFO]    35M  /var/lib/dpkg
2026-10-07 06:36:42 [INFO]    3.9M  /var/lib/ucf
2026-10-07 06:36:42 [INFO] maintenance finished
```

The JSON form of the report (`02-health-report.json`) is also included; every section above is a key in it.

## 9. What was tested (and what was not)

Tested in a real Linux VM (Ubuntu 24.04, running as root):

* `sysmon.py` report / JSON / history / daemon (including `SIGHUP` reload and clean `SIGTERM`), dry-run and live disk cleanup
* `health-check.sh`, `log-analyzer.py` (both modes), `backup.sh` (run, dry-run, restore-test, listing), `maintenance.sh --dry-run`
* `user-manage.sh` add → list → lock → unlock → remove, plus `audit` and `fix-perms` catching a deliberate `chmod 777`
* `ssh-harden.sh` against a real `sshd`: audit, refusal when no key exists, apply with `sshd -t` validation, audit-after, rollback
* `install.sh` / `uninstall.sh --purge`, and `systemd-analyze verify` on the unit file

**Not exercised in that VM** because systemd was not running there: starting the unit with `systemctl`, and the live "restart a dead service" action. Both are short code paths — test them on your own machine by stopping `cron` (`sudo systemctl stop cron`), setting `dry_run = no`, and watching `journalctl -u sysmon -f`.

## 10. Safety design

* **Dry-run first.** Destructive actions only log until you switch `dry_run = no`.
* **Cooldowns** on every action; **protected directories** the cleaner will never touch.
* **No automatic process killing.** Memory pressure is reported, not "fixed".
* **SSH hardening cannot lock you out silently:** key check, `sshd -t` validation, automatic rollback, backups in `/var/backups/sysmon-ssh`.
* **Least surprise:** every script supports `--dry-run`/read-only modes where it matters; installers never overwrite your edited config (the new default is saved as `*.new`).
* **Trade-off to know about:** the agent runs as root because restarting services and cleaning `/tmp` require it. The unit mitigates this with sandboxing and resource limits; a stricter design would split a read-only monitor from a small privileged "actions" helper.

## 11. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `systemd not available … skipped` | Running in a container/WSL without systemd. Expected; everything else still works. |
| No logs in `/var/log/sysmon` as normal user | The agent falls back to `~/.local/state/sysmon/`. |
| `log-analyzer.py: no log file found` | Use `--file`, or `--journal "24 hours ago"` on journald-only systems. |
| `ssh-harden.sh --apply` refuses | No `authorized_keys` for you. Run `ssh-copy-id`, or `--keep-passwords`. |
| Service shows `inactive` but you want it ignored | Remove it from `[services] watch`. |
| Backup refuses to run | Not enough free space, or it would leave less than `MIN_FREE_PERCENT` free. |

## 12. Ideas to extend it

Push alerts (email/webhook) from the actions step · Prometheus text-format exporter from `latest.json` · per-process memory-leak trend from `history.jsonl` · nftables rules generated from the blocklist · split the agent into unprivileged monitor + privileged helper · unit tests with fixture copies of `/proc` files.


## License
MIT — use it, modify it, put it on your GitHub.
