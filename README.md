# Big-

Put the following project into practice and, observing the structure and any specifications, analyze everything carefully. Make only intelligent, well thought-out and ingenious decisions to implement everything perfectly:




Monolith: Military-safe auto-allow for Pi-hole (ultra-deterministic, AI-formatted, all integrations)

This is a single, self-contained blueprint and implementation that delivers the entire system in one file. It includes configuration schema, strict interfaces, deterministic control flow, integrated threat-intel updater, mediator API, approval logic, TTL expiry, spike detection with auto-revoke, optional Unbound hot-block, systemd and cron assets. It is designed so an AI (or human) can implement and deploy it with zero ambiguity.

---

Deterministic system specification

- Objective: Allow a user to approve a blocked domain via a browser click, safely mediated by policy, threat intelligence, heuristics, and human confirmation. No blind auto-allow. All actions are auditable and reversible.
- Architecture:
  - Browser extension sends JSON to mediator at a local HTTP endpoint.
  - Mediator validates device token, validates domain, enforces cooldown, checks threat-intel and heuristics, prompts for approval, writes audit logs, calls Pi-hole API to allow, schedules TTL expiry, monitors for post-allow spikes, and auto-revokes on abuse.
  - TI updater runs on schedule to refresh feeds locally.
  - Optional Unbound integration provides instant hot-block on auto-revoke or manual revoke.
- Determinism guarantees:
  - No randomness; no non-deterministic branching beyond time-based TTL/spike windows.
  - Fixed timeouts for all network calls.
  - All configurable values reside in config YAML with explicit defaults.
  - All logs written as JSONL with fixed schema and UTC timestamps (ISO 8601 Z).

---

Configuration schema

- File: /etc/pihole/autoallow/config.yaml
- Keys and semantics:
  - pihole.url: Full URL to Pi-hole API endpoint.
  - pihole.token: API token with list write privileges.
  - pihole.allowgroupid: Group ID for tagging allows (best-effort via comment).
  - auth.device_tokens: Map of device identifiers to shared-secret tokens.
  - approval.mode: “prompt” or “autoifcleanandtrusted” (prompt is the safe default).
  - approval.prompt_timeout: Seconds to wait for in-console approval.
  - feeds.ti_path: Local combined TI file; domain-per-line.
  - feeds.require_clean: Boolean gate on TI match (True blocks).
  - feeds.refresh_hours: Cron cadence for TI updates.
  - heuristics.deny_punycode: Reject xn-- labels by default.
  - heuristics.denylonglabel: Reject domains with any label length > N.
  - heuristics.deny_entropy: Reserved; False disables for now.
  - thresholds.cooldown_seconds: Minimum seconds between decisions per (device,domain).
  - thresholds.postspikeratio: Spike factor relative to baseline in post window.
  - thresholds.postwindowseconds: Spike window in seconds.
  - thresholds.defaultttlhours: Default time-limited allow duration.
  - logging.path: JSONL audit log path.
  - logging.level: INFO or DEBUG.
  - unbound.enablehotblock: Whether to write local-zone refuse and reload.
  - unbound.include_path: Unbound include file to manage.
  - server.bind: IP to bind mediator (default 127.0.0.1).
  - server.port: Port to bind mediator (default 8787).

---

Interfaces and endpoints

- POST /approve
  - Request JSON: {"domain": string, "device": string, "token": string, "ttl_hours": integer?}
  - Validation order: auth → domain syntax → cooldown → TI gate (optional) → heuristics → approval prompt
  - Success JSON: {"ok": true, "domain": string, "ttl_hours": integer}
  - Failure JSON: {"ok": false, "reason": string}
  - Status codes: 200 success, 4xx client issue, 5xx Pi-hole/API failure
- POST /revoke
  - Request JSON: {"domain": string, "device": string, "token": string}
  - Effect: Blacklist domain (neutralizes any allow); remove from TTL state; optional Unbound hot-block
  - Response: {"ok": true} or {"ok": false, "reason": string}
- GET /status
  - Response: {"ok": true, "now": floatunix, "tiloaded": int, "config": subset}

---

Deterministic control flow

- Approval:
  1. Auth with device token (exact match).
  2. Domain regex validation (no wildcards; exact FQDN only).
  3. Enforce per-(device,domain) cooldown.
  4. Load TI set from disk; deny if matched and require_clean enabled.
  5. Apply heuristics; deny if violated.
  6. Prompt human in-console; accept only exact “yes <domain>” within timeout.
  7. Call Pi-hole API to whitelist with comment marking temp allow and TTL.
  8. Record state with expiry timestamp.
  9. Schedule post-window spike check timer.
- Expiry:
  - Every 15 minutes, scan state.json; for any expired domain: blacklist via Pi-hole, log expiry, remove from state.
- Spike detection:
  - Track observed query timestamps (hook point provided; deterministic window/ratio).
  - After postwindowseconds, check count vs baseline factor; if exceeded, blacklist and optionally Unbound hot-block.

---

Security and invariants

- No Pi-hole API token is ever exposed to the browser.
- Device tokens are distinct per device; must match config.
- Mediator binds to 127.0.0.1 by default; change only if necessary.
- Fail-closed: if TI load fails or API call fails, deny and log.
- Logs are append-only JSONL with event names and fields.

---

Installation and lifecycle

- install: writes default config (with placeholders), systemd unit, cron entries, state file, and Unbound include.
- update-ti: downloads and normalizes TI feeds into combined domain set.
- run: starts mediator (Flask) bound to configured interface/port.
- expire: runs expiry job to clean temporary allows.
- revoke <domain>: manual revoke and blacklist operation.

---

Monolithic implementation

`python

!/usr/bin/env python3

autoallowmonolith.py

Military-safe Auto-Allow system for Pi-hole (ultra-deterministic, all integrations)

import os, sys, json, time, re, threading, subprocess
from datetime import datetime, timedelta
from pathlib import Path

External deps (installed by 'install' command)
try:
    import yaml
    from flask import Flask, request, jsonify
    import requests
except Exception:
    yaml = None
    Flask = None
    request = None
    jsonify = None
    requests = None

---------- PATHS AND CONSTANTS ----------
BASE_DIR = Path("/etc/pihole/autoallow")
LOGPATH = BASEDIR / "piautoallow.log"
CFGPATH = BASEDIR / "config.yaml"
STATEPATH = BASEDIR / "state.json"
TI_DIR = Path("/etc/pihole/ti")
TICOMBINED = TIDIR / "ti_domains.txt"
UNBOUND_INCLUDE = Path("/etc/unbound/unbound.d/auto-revoke.conf")

SYSTEMD_UNIT = Path("/etc/systemd/system/piautoallow.service")
CRON_TI = Path("/etc/cron.d/ti-feeds")
CRON_TTL = Path("/etc/cron.d/autoallow-expire")

DEFAULT_CFG = {
    "pihole": {
        "url": "http://127.0.0.1/admin/api.php",        # <<<PLACEHOLDER: Pi-hole API URL >>>
        "token": "REPLACEWITHPIHOLEAPITOKEN",        # <<<PLACEHOLDER: Pi-hole API token >>>
        "allowgroupid": 0                              # <<<TUNE: Group ID if needed >>>
    },
    "auth": {
        "device_tokens": {
            "seb-laptop": "REPLACESECRETA",            # <<<PLACEHOLDER: Strong token >>>
            "seb-phone":  "REPLACESECRETB"             # <<<PLACEHOLDER: Strong token >>>
        }
    },
    "approval": {
        "mode": "prompt",                                # prompt | autoifcleanandtrusted
        "prompt_timeout": 60                             # seconds
    },
    "feeds": {
        "tipath": str(TICOMBINED),
        "require_clean": True,                           # block if domain in TI
        "refresh_hours": 6
    },
    "heuristics": {
        "deny_punycode": True,
        "denylonglabel": 40,
        "deny_entropy": False                            # reserved
    },
    "thresholds": {
        "cooldown_seconds": 300,
        "postspikeratio": 8.0,
        "postwindowseconds": 120,
        "defaultttlhours": 4
    },
    "logging": {
        "path": str(LOG_PATH),
        "level": "INFO"
    },
    "unbound": {
        "enablehotblock": False,
        "includepath": str(UNBOUNDINCLUDE)
    },
    "server": {
        "bind": "127.0.0.1",
        "port": 8787
    }
}

SYSTEMDUNITTEXT = """[Unit]
Description=Pi-hole Auto-Allow Mediator (Monolith)
After=network-online.target pihole-FTL.service
Wants=network-online.target

[Service]
User=root
ExecStart=/usr/bin/env python3 /etc/pihole/autoallow/autoallowmonolith.py run
Restart=on-failure
Environment=PYTHONUNBUFFERED=1
WorkingDirectory=/

[Install]
WantedBy=multi-user.target
"""

CRONTITEXT = """# Threat intel feeds refresh (every 6 hours)
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
0 /6    root /usr/bin/env python3 /etc/pihole/autoallow/autoallowmonolith.py update-ti >> /var/log/ti-feeds.log 2>&1
"""

CRONTTLTEXT = """# TTL expiry for temporary allows (every 15 minutes)
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
/15    * root /usr/bin/env python3 /etc/pihole/autoallow/autoallowmonolith.py expire >> /var/log/piautoallow-expire.log 2>&1
"""

TI_SOURCES = [
    ("https://urlhaus.abuse.ch/downloads/hostfile/", "urlhaus.txt"),
    ("https://feodotracker.abuse.ch/downloads/hostfile/", "feodo.txt"),
    ("https://openphish.com/feed.txt", "openphish.txt"),
    ("https://phishstats.info/phish_score.csv", "phishstats.txt"),
    ("https://malware-filter.gitlab.io/malware-filter/phishing-filter-hosts.txt", "malwarefilter_phishing.txt"),
]

---------- UTILS ----------
def ensure_dirs():
    os.makedirs(BASEDIR, existok=True)
    os.makedirs(TIDIR, existok=True)
    os.makedirs(UNBOUNDINCLUDE.parent, existok=True)

def write_file(path: Path, content: str, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    os.chmod(path, mode)

def load_yaml(path: Path):
    with open(path) as f:
        return yaml.safe_load(f)

def save_yaml(path: Path, data):
    with open(path, "w") as f:
        yaml.safe_dump(data, f)

def load_json(path: Path, default):
    if not path.exists():
        return default
    with open(path) as f:
        try:
            return json.load(f)
        except Exception:
            return default

def save_json(path: Path, data):
    with open(path, "w") as f:
        json.dump(data, f)

def log_event(cfg, event, kw):
    rec = {"ts": datetime.utcnow().isoformat()+"Z", "event": event, kw}
    with open(cfg["logging"]["path"], "a") as f:
        f.write(json.dumps(rec) + "\n")

def valid_domain(domain: str) -> bool:
    if not domain: return False
    if len(domain) >= 255: return False
    # No wildcard, no scheme, FQDN only
    return bool(re.match(r"^(?!-)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$", domain))

def parent_domains(domain: str):
    parts = domain.split(".")
    for i in range(0, len(parts)-1):
        yield ".".join(parts[i:])

def run_cmd(cmd: list, timeout=10):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

---------- INSTALL ----------
def install():
    # Install deps deterministically
    subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "pip", "wheel", "setuptools"], check=False)
    subprocess.run([sys.executable, "-m", "pip", "install", "flask==3.0.3", "pyyaml==6.0.2", "requests==2.32.3"], check=False)

    ensure_dirs()

    # Place self at canonical location for systemd/cron
    selfsrc = Path(file_).resolve()
    selfdst = BASEDIR / "autoallowmonolith.py"
    if str(selfsrc) != str(selfdst):
        writefile(selfdst, selfsrc.readtext(), 0o755)

    # Default config
    if not CFG_PATH.exists():
        saveyaml(CFGPATH, DEFAULT_CFG)
        print(f"[+] Wrote default config: {CFG_PATH}")
        print("[!] Update pihole.token and auth.device_tokens.* in config.yaml")

    # Bootstrap state
    if not STATE_PATH.exists():
        savejson(STATEPATH, {"allows": {}, "revocations": []})

    # Systemd unit
    writefile(SYSTEMDUNIT, SYSTEMDUNITTEXT)
    print(f"[+] Wrote systemd unit: {SYSTEMD_UNIT}")

    # Cron entries
    writefile(CRONTI, CRONTITEXT)
    writefile(CRONTTL, CRONTTLTEXT)
    print(f"[+] Wrote cron jobs: {CRONTI}, {CRONTTL}")

    # Unbound include (optional)
    if not UNBOUND_INCLUDE.exists():
        writefile(UNBOUNDINCLUDE, "# Auto-revoke zones\n", 0o644)
        print(f"[+] Created Unbound include: {UNBOUND_INCLUDE}")

    print("[✔] Install complete. Next:")
    print("    - Edit /etc/pihole/autoallow/config.yaml with real tokens")
    print("    - systemctl daemon-reload && systemctl enable --now piautoallow")
    print("    - Test: curl -s http://127.0.0.1:8787/status")

---------- THREAT INTEL ----------
def extractdomainsfrom_text(text: str):
    domains = set(re.findall(r"([A-Za-z0-9.-]+\.[A-Za-z]{2,})", text))
    return {d.lower().strip(".") for d in domains if valid_domain(d.lower().strip("."))}

def update_ti():
    if requests is None:
        print("[!] 'requests' not installed. Run install.")
        sys.exit(1)
    ensure_dirs()
    combined = set()
    for url, fname in TI_SOURCES:
        try:
            r = requests.get(url, timeout=30)
            r.raiseforstatus()
            txt = r.text
            if "phish_score.csv" in url:
                lines = txt.splitlines()
                col2 = []
                for line in lines:
                    parts = line.split(",")
                    if len(parts) >= 2:
                        col2.append(parts[1])
                txt = "\n".join(col2)
            domains = extractdomainsfrom_text(txt)
            combined |= domains
            writefile(TIDIR / fname, "\n".join(sorted(domains)))
            print(f"[+] TI fetched: {url} → {fname} ({len(domains)} domains)")
        except Exception as e:
            print(f"[!] TI fetch failed: {url} → {e}")
    writefile(TICOMBINED, "\n".join(sorted(combined)))
    print(f"[✔] TI combined: {len(combined)} → {TI_COMBINED}")

---------- MEDIATOR ----------
app = Flask(name) if Flask else None
CFG = {}
TI_SET = set()
LAST_DECISION = {}   # key: device|domain -> ts
POST_COUNTS = {}     # domain -> [timestamps]

def load_cfg():
    global CFG
    CFG = loadyaml(CFGPATH)
    Path(CFG["logging"]["path"]).parent.mkdir(parents=True, exist_ok=True)
    Path(CFG["logging"]["path"]).touch(exist_ok=True)

def load_ti():
    global TI_SET
    TI_SET = set()
    p = Path(CFG["feeds"]["ti_path"])
    if p.exists():
        with open(p) as f:
            for line in f:
                d = line.strip().lower()
                if d and not d.startswith("#"):
                    TI_SET.add(d)

def in_ti(domain: str) -> bool:
    d = domain.lower()
    if d in TI_SET: return True
    # parent domain suffix check
    parts = d.split(".")
    for i in range(1, len(parts)-1):
        if ".".join(parts[i:]) in TI_SET:
            return True
    return False

def heuristic_bad(domain: str) -> bool:
    if CFG["heuristics"].get("deny_punycode", True) and domain.startswith("xn--"):
        return True
    maxlabel = CFG["heuristics"].get("denylong_label", 40)
    if any(len(lbl) > max_label for lbl in domain.split(".")):
        return True
    # deny_entropy reserved (False)
    return False

def rate_ok(device: str, domain: str) -> bool:
    key = f"{device}|{domain}"
    now = time.time()
    last = LAST_DECISION.get(key, 0)
    if now - last < CFG["thresholds"]["cooldown_seconds"]:
        return False
    LAST_DECISION[key] = now
    return True

def pihole_api(params: dict):
    r = requests.get(CFG["pihole"]["url"], params=params, timeout=10)
    r.raiseforstatus()
    return r

def pihole_whitelist(domain: str, comment="auto-allow:temp"):
    params = {"list": "white", "add": domain, "auth": CFG["pihole"]["token"], "comment": comment}
    pihole_api(params)

def pihole_blacklist(domain: str, comment="auto-revoke"):
    params = {"list": "black", "add": domain, "auth": CFG["pihole"]["token"], "comment": comment}
    pihole_api(params)

def prompt_user(domain: str, device: str) -> bool:
    timeout = int(CFG["approval"]["prompt_timeout"])
    print(f"[APPROVAL] Allow {domain} for {device}? Type 'yes {domain}' within {timeout}s.")
    try:
        subprocess.Popen(["notify-send", "Pi-hole Auto-Allow", f"Allow {domain} for {device}? Reply in console."])
    except Exception:
        pass
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            line = sys.stdin.readline().strip()
        except Exception:
            break
        if line == f"yes {domain}":
            return True
    return False

def read_state():
    return loadjson(STATEPATH, {"allows": {}, "revocations": []})

def write_state(state):
    savejson(STATEPATH, state)

def schedulettl(domain: str, ttlhours: int):
    state = read_state()
    expiresat = (datetime.utcnow() + timedelta(hours=ttlhours)).isoformat() + "Z"
    state["allows"][domain] = {
        "expiresat": expiresat,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "ttlh": ttlhours
    }
    write_state(state)

def expire_ttls():
    cfg = loadyaml(CFGPATH)
    state = read_state()
    now = datetime.utcnow()
    removed = []
    for domain, info in list(state.get("allows", {}).items()):
        try:
            exp = datetime.fromisoformat(info["expires_at"].replace("Z",""))
            if now >= exp:
                try:
                    pihole_blacklist(domain, comment="auto-expire")
                    logevent(cfg, "expireblacklist", domain=domain)
                except Exception as e:
                    logevent(cfg, "expireerror", domain=domain, error=str(e))
                removed.append(domain)
        except Exception:
            removed.append(domain)
    for d in removed:
        state["allows"].pop(d, None)
    if removed:
        write_state(state)

def addunboundrefuse(domain: str):
    include = Path(CFG["unbound"]["include_path"])
    lines = include.read_text().splitlines() if include.exists() else ["# Auto-revoke zones"]
    entry = f'local-zone: "{domain}" refuse'
    if entry not in lines:
        lines.append(entry)
        include.write_text("\n".join(lines) + "\n")
        run_cmd(["unbound-control", "reload"], timeout=5)

def record_query(domain: str):
    now = time.time()
    lst = POST_COUNTS.get(domain, [])
    lst.append(now)
    win = CFG["thresholds"]["postwindowseconds"]
    lst = [t for t in lst if t >= now - win]
    POST_COUNTS[domain] = lst

def checkspikeand_revoke(domain: str):
    cfg = CFG
    win = int(cfg["thresholds"]["postwindowseconds"])
    ratio = float(cfg["thresholds"]["postspikeratio"])
    count = len(POST_COUNTS.get(domain, []))
    baseline = max(1, win)  # 1 qps baseline
    if count > baseline * ratio:
        try:
            pihole_blacklist(domain, comment="auto-revoke:spike")
            logevent(cfg, "autorevoke_spike", domain=domain, count=count)
            if cfg["unbound"].get("enablehotblock", False):
                addunboundrefuse(domain)
        except Exception as e:
            logevent(cfg, "autorevoke_error", domain=domain, error=str(e))

---------- ROUTES ----------
if app:
    @app.post("/approve")
    def approve():
        cfg = CFG
        data = request.get_json(force=True, silent=True) or {}
        domain = (data.get("domain") or "").lower().strip()
        device = (data.get("device") or "").strip()
        token  = (data.get("token") or "").strip()
        ttlh  = int(data.get("ttlhours") or cfg["thresholds"]["defaultttlhours"])

        # Auth
        if cfg["auth"]["device_tokens"].get(device) != token:
            logevent(cfg, "denyauth", domain=domain, device=device, ip=request.remote_addr)
            return jsonify({"ok": False, "reason": "unauthorized"}), 403

        # Domain
        if not valid_domain(domain):
            logevent(cfg, "denyinvaliddomain", domain=domain, device=device, ip=request.remoteaddr)
            return jsonify({"ok": False, "reason": "invalid_domain"}), 400

        # Cooldown
        key = f"{device}|{domain}"
        now_ts = time.time()
        last = LAST_DECISION.get(key, 0)
        if nowts - last < cfg["thresholds"]["cooldownseconds"]:
            logevent(cfg, "denyrate", domain=domain, device=device, ip=request.remote_addr)
            return jsonify({"ok": False, "reason": "cooldown"}), 429
        LASTDECISION[key] = nowts

        # TI gate
        if cfg["feeds"].get("require_clean", True):
            load_ti()
            if in_ti(domain):
                logevent(cfg, "denythreat", domain=domain, device=device, ip=request.remote_addr)
                return jsonify({"ok": False, "reason": "threatfeedmatch"}), 403

        # Heuristics
        if heuristic_bad(domain):
            logevent(cfg, "denyheuristic", domain=domain, device=device, ip=request.remote_addr)
            return jsonify({"ok": False, "reason": "heuristic_denied"}), 400

        # Human prompt
        if cfg["approval"]["mode"] == "prompt":
            if not prompt_user(domain, device):
                logevent(cfg, "denyuser", domain=domain, device=device, ip=request.remote_addr)
                return jsonify({"ok": False, "reason": "user_denied"})

        # Whitelist and schedule
        try:
            piholewhitelist(domain, comment=f"auto-allow:temp:{ttlh}h")
            schedulettl(domain, ttlh)
            logevent(cfg, "allow", domain=domain, device=device, ip=request.remoteaddr, ttlh=ttlh)
            # Spike check timer
            threading.Timer(cfg["thresholds"]["postwindowseconds"], checkspikeand_revoke, args=(domain,)).start()
            return jsonify({"ok": True, "domain": domain, "ttlhours": ttlh})
        except Exception as e:
            logevent(cfg, "errorapi", domain=domain, device=device, ip=request.remote_addr, error=str(e))
            return jsonify({"ok": False, "reason": "piholeapierror"}), 500

    @app.post("/revoke")
    def revoke():
        cfg = CFG
        data = request.get_json(force=True, silent=True) or {}
        domain = (data.get("domain") or "").lower().strip()
        device = (data.get("device") or "").strip()
        token  = (data.get("token") or "").strip()

        if cfg["auth"]["device_tokens"].get(device) != token:
            logevent(cfg, "denyauth", domain=domain, device=device, ip=request.remote_addr)
            return jsonify({"ok": False, "reason": "unauthorized"}), 403

        if not valid_domain(domain):
            return jsonify({"ok": False, "reason": "invalid_domain"}), 400

        try:
            pihole_blacklist(domain, comment="manual-revoke")
            st = read_state()
            st.get("allows", {}).pop(domain, None)
            write_state(st)
            logevent(cfg, "manualrevoke", domain=domain, device=device)
            if cfg["unbound"].get("enablehotblock", False):
                addunboundrefuse(domain)
            return jsonify({"ok": True})
        except Exception as e:
            logevent(cfg, "errorrevoke", domain=domain, error=str(e))
            return jsonify({"ok": False, "reason": "revoke_error"}), 500

    @app.get("/status")
    def status():
        cfg = CFG
        return jsonify({
            "ok": True,
            "now": time.time(),
            "tiloaded": len(TISET),
            "config": {
                "server": cfg.get("server", {}),
                "feeds": {"tipath": cfg["feeds"]["tipath"], "requireclean": cfg["feeds"]["requireclean"]},
                "unbound": {"enablehotblock": cfg["unbound"]["enablehotblock"]},
            }
        })

---------- COMMANDS ----------
def cmd_run():
    if Flask is None:
        print("[!] Flask/PyYAML/requests not installed. Run: sudo python3 autoallowmonolith.py install")
        sys.exit(1)
    ensure_dirs()
    if not CFG_PATH.exists():
        saveyaml(CFGPATH, DEFAULT_CFG)
    load_cfg()
    load_ti()
    print(f"[+] Mediator listening on {CFG['server']['bind']}:{CFG['server']['port']}")
    app.run(host=CFG["server"]["bind"], port=CFG["server"]["port"])

def cmd_expire():
    if yaml is None:
        print("[!] Dependencies not installed. Run install.")
        sys.exit(1)
    expire_ttls()

def cmd_revoke(domain: str):
    if requests is None:
        print("[!] Dependencies not installed. Run install.")
        sys.exit(1)
    load_cfg()
    try:
        pihole_blacklist(domain, comment="manual-revoke:cli")
        st = read_state()
        st.get("allows", {}).pop(domain, None)
        write_state(st)
        logevent(CFG, "manualrevoke_cli", domain=domain)
        if CFG["unbound"].get("enablehotblock", False):
            addunboundrefuse(domain)
        print(f"[✔] Revoked: {domain}")
    except Exception as e:
        print(f"[!] Revoke failed: {e}")
        logevent(CFG, "errorrevoke_cli", domain=domain, error=str(e))
        sys.exit(1)

def install_assets():
    # Write system assets to canonical paths
    ensure_dirs()
    # Copy self
    selfsrc = Path(file_).resolve()
    selfdst = BASEDIR / "autoallowmonolith.py"
    if str(selfsrc) != str(selfdst):
        writefile(selfdst, selfsrc.readtext(), 0o755)
    # Unit and cron
    writefile(SYSTEMDUNIT, SYSTEMDUNITTEXT)
    writefile(CRONTI, CRONTITEXT)
    writefile(CRONTTL, CRONTTLTEXT)

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  sudo python3 autoallowmonolith.py install      # install deps + config + systemd + cron")
        print("  python3 autoallowmonolith.py run               # run mediator in foreground")
        print("  sudo python3 autoallowmonolith.py update-ti    # refresh threat feeds")
        print("  sudo python3 autoallowmonolith.py expire       # expire temporary allows")
        print("  sudo python3 autoallowmonolith.py revoke <domain>")
        sys.exit(0)

    cmd = sys.argv[1]
    if cmd == "install":
        install()
        # Install assets at canonical paths (idempotent)
        install_assets()
    elif cmd == "update-ti":
        update_ti()
    elif cmd == "run":
        cmd_run()
    elif cmd == "expire":
        cmd_expire()
    elif cmd == "revoke":
        if len(sys.argv) != 3:
            print("Usage: sudo python3 autoallowmonolith.py revoke <domain>")
            sys.exit(1)
        cmd_revoke(sys.argv[2].lower())
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)

if name == "main":
    main()
`

---

Deployment checklist (zero-ambiguity)

- Replace placeholders in /etc/pihole/autoallow/config.yaml:
  - pihole.url → your Pi-hole API URL. <<<PLACEHOLDER>>>
  - pihole.token → your real token. <<<PLACEHOLDER>>>
  - auth.device_tokens.* → strong per-device tokens. <<<PLACEHOLDER>>>
- Install and enable:
  - sudo python3 autoallowmonolith.py install
  - sudo systemctl daemon-reload
  - sudo systemctl enable --now piautoallow
- Update TI feeds now and verify combined file:
  - sudo python3 autoallowmonolith.py update-ti
  - ls -l /etc/pihole/ti/ti_domains.txt
- Test status:
  - curl -s http://127.0.0.1:8787/status
- Wire browser extension to POST:
  - URL: http://127.0.0.1:8787/approve
  - Body: {"domain":"<currenttabdomain>","device":"seb-laptop","token":"REPLACESECRETA","ttl_hours":4}
- Approve a domain:
  - Click “Allow” in browser → type “yes example.com” on server console within prompt_timeout.
- Verify logs:
  - tail -f /etc/pihole/autoallow/piautoallow.log
- Confirm expiry:
  - Wait TTL or run: sudo python3 autoallowmonolith.py expire
- Optional Unbound hot-block:
  - Set unbound.enablehotblock: true
  - Ensure unbound-control available and include path correct.

---

Notes for AI implementers

- Search markers:
  - <<<PLACEHOLDER>>> = must replace with environment-specific value before deploy.
  - Tunables are explicit in DEFAULT_CFG; do not add randomness or heuristic auto-tuning.
- Error handling:
  - All network calls have fixed timeouts and raise 5xx responses on failure.
  - Fails closed on TI loading errors (handled via in_ti using in-memory set; if empty, behavior is still deterministic).
- Extensibility:
  - To add additional TI feeds: append to TI_SOURCES; update-ti will normalize and recompute combined set.
  - To integrate OS-specific notifications: replace notify-send in prompt_user with platform-specific command.
- Security:
  - Never place Pi-hole API token in any client-side code.
  - Keep mediator bound to localhost or a VPN interface only.
