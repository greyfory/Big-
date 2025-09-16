#!/usr/bin/env python3
"""
autoallowmonolith.py

Military-safe Auto-Allow system for Pi-hole (ultra-deterministic, all integrations)
"""

import os, sys, json, time, re, threading, subprocess
from datetime import datetime, timedelta
from pathlib import Path

# External deps (installed by 'install' command)
try:
    import yaml
except ImportError:
    yaml = None

try:
    from flask import Flask, request, jsonify
except ImportError:
    Flask = None
    request = None
    jsonify = None

try:
    import requests
except ImportError:
    requests = None

# ---------- PATHS AND CONSTANTS ----------
BASE_DIR = Path("/etc/pihole/autoallow")
LOG_PATH = BASE_DIR / "piautoallow.log"
CFG_PATH = BASE_DIR / "config.yaml"
STATE_PATH = BASE_DIR / "state.json"
TI_DIR = Path("/etc/pihole/autoallow/ti")
TI_COMBINED = TI_DIR / "ti_domains.txt"
UNBOUND_INCLUDE = Path("/etc/pihole/autoallow/auto-revoke.conf")

SYSTEMD_UNIT = Path("/etc/pihole/autoallow/piautoallow.service")
CRON_TI = Path("/etc/pihole/autoallow/ti-feeds")
CRON_TTL = Path("/etc/pihole/autoallow/autoallow-expire")

DEFAULT_CFG = {
    "pihole": {
        "url": "http://127.0.0.1/admin/api.php",        # <<<PLACEHOLDER: Pi-hole API URL >>>
        "token": "REPLACEWITHPIHOLEAPITOKEN",            # <<<PLACEHOLDER: Pi-hole API token >>>
        "allowgroupid": 0                                # <<<TUNE: Group ID if needed >>>
    },
    "auth": {
        "device_tokens": {
            "seb-laptop": "REPLACESECRETA",              # <<<PLACEHOLDER: Strong token >>>
            "seb-phone":  "REPLACESECRETB"               # <<<PLACEHOLDER: Strong token >>>
        }
    },
    "approval": {
        "mode": "prompt",                                # prompt | autoifcleanandtrusted
        "prompt_timeout": 60                             # seconds
    },
    "feeds": {
        "ti_path": str(TI_COMBINED),
        "require_clean": True,                           # block if domain in TI
        "refresh_hours": 6
    },
    "heuristics": {
        "deny_punycode": True,
        "deny_long_label": 40,
        "deny_entropy": False                            # reserved
    },
    "thresholds": {
        "cooldown_seconds": 300,
        "post_spike_ratio": 8.0,
        "post_window_seconds": 120,
        "default_ttl_hours": 4
    },
    "logging": {
        "path": str(LOG_PATH),
        "level": "INFO"
    },
    "unbound": {
        "enable_hot_block": False,
        "include_path": str(UNBOUND_INCLUDE)
    },
    "server": {
        "bind": "127.0.0.1",
        "port": 8787
    }
}

SYSTEMD_UNIT_TEXT = """[Unit]
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

CRON_TI_TEXT = """# Threat intel feeds refresh (every 6 hours)
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
0 */6    * * * root /usr/bin/env python3 /etc/pihole/autoallow/autoallowmonolith.py update-ti >> /var/log/ti-feeds.log 2>&1
"""

CRON_TTL_TEXT = """# TTL expiry for temporary allows (every 15 minutes)
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
*/15    * * * * root /usr/bin/env python3 /etc/pihole/autoallow/autoallowmonolith.py expire >> /var/log/piautoallow-expire.log 2>&1
"""

TI_SOURCES = [
    ("https://urlhaus.abuse.ch/downloads/hostfile/", "urlhaus.txt"),
    ("https://feodotracker.abuse.ch/downloads/hostfile/", "feodo.txt"),
    ("https://openphish.com/feed.txt", "openphish.txt"),
    ("https://phishstats.info/phish_score.csv", "phishstats.txt"),
    ("https://malware-filter.gitlab.io/malware-filter/phishing-filter-hosts.txt", "malwarefilter_phishing.txt"),
]

# ---------- UTILS ----------
def ensure_dirs():
    os.makedirs(BASE_DIR, exist_ok=True)
    os.makedirs(TI_DIR, exist_ok=True)
    os.makedirs(UNBOUND_INCLUDE.parent, exist_ok=True)

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

def log_event(cfg, event, **kw):
    rec = {"ts": datetime.utcnow().isoformat()+"Z", "event": event, **kw}
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

# ---------- INSTALL ----------
def install():
    # Install deps deterministically
    subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "pip", "wheel", "setuptools"], check=False)
    subprocess.run([sys.executable, "-m", "pip", "install", "flask==3.0.3", "pyyaml==6.0.2", "requests==2.32.3"], check=False)

    # Import yaml after installation
    global yaml
    import yaml

    ensure_dirs()

    # Place self at canonical location for systemd/cron
    self_src = Path(__file__).resolve()
    self_dst = BASE_DIR / "autoallowmonolith.py"
    if str(self_src) != str(self_dst):
        write_file(self_dst, self_src.read_text(), 0o755)

    # Default config
    if not CFG_PATH.exists():
        save_yaml(CFG_PATH, DEFAULT_CFG)
        print(f"[+] Wrote default config: {CFG_PATH}")
        print("[!] Update pihole.token and auth.device_tokens.* in config.yaml")

    # Bootstrap state
    if not STATE_PATH.exists():
        save_json(STATE_PATH, {"allows": {}, "revocations": []})

    # Systemd unit
    write_file(SYSTEMD_UNIT, SYSTEMD_UNIT_TEXT)
    print(f"[+] Wrote systemd unit: {SYSTEMD_UNIT}")

    # Cron entries
    write_file(CRON_TI, CRON_TI_TEXT)
    write_file(CRON_TTL, CRON_TTL_TEXT)
    print(f"[+] Wrote cron jobs: {CRON_TI}, {CRON_TTL}")

    # Unbound include (optional)
    if not UNBOUND_INCLUDE.exists():
        write_file(UNBOUND_INCLUDE, "# Auto-revoke zones\n", 0o644)
        print(f"[+] Created Unbound include: {UNBOUND_INCLUDE}")

    print("[✔] Install complete. Next:")
    print("    - Edit /etc/pihole/autoallow/config.yaml with real tokens")
    print("    - systemctl daemon-reload && systemctl enable --now piautoallow")
    print("    - Test: curl -s http://127.0.0.1:8787/status")

# ---------- THREAT INTEL ----------
def extract_domains_from_text(text: str):
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
            r.raise_for_status()
            txt = r.text
            if "phish_score.csv" in url:
                lines = txt.splitlines()
                col2 = []
                for line in lines:
                    parts = line.split(",")
                    if len(parts) >= 2:
                        col2.append(parts[1])
                txt = "\n".join(col2)
            domains = extract_domains_from_text(txt)
            combined |= domains
            write_file(TI_DIR / fname, "\n".join(sorted(domains)))
            print(f"[+] TI fetched: {url} → {fname} ({len(domains)} domains)")
        except Exception as e:
            print(f"[!] TI fetch failed: {url} → {e}")
    write_file(TI_COMBINED, "\n".join(sorted(combined)))
    print(f"[✔] TI combined: {len(combined)} → {TI_COMBINED}")

# ---------- MEDIATOR ----------
app = Flask(__name__) if Flask else None
CFG = {}
TI_SET = set()
LAST_DECISION = {}   # key: device|domain -> ts
POST_COUNTS = {}     # domain -> [timestamps]

def load_cfg():
    global CFG
    CFG = load_yaml(CFG_PATH)
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
    max_label = CFG["heuristics"].get("deny_long_label", 40)
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
    r.raise_for_status()
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
    return load_json(STATE_PATH, {"allows": {}, "revocations": []})

def write_state(state):
    save_json(STATE_PATH, state)

def schedule_ttl(domain: str, ttl_hours: int):
    state = read_state()
    expires_at = (datetime.utcnow() + timedelta(hours=ttl_hours)).isoformat() + "Z"
    state["allows"][domain] = {
        "expires_at": expires_at,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "ttl_h": ttl_hours
    }
    write_state(state)

def expire_ttls():
    cfg = load_yaml(CFG_PATH)
    state = read_state()
    now = datetime.utcnow()
    removed = []
    for domain, info in list(state.get("allows", {}).items()):
        try:
            exp = datetime.fromisoformat(info["expires_at"].replace("Z",""))
            if now >= exp:
                try:
                    pihole_blacklist(domain, comment="auto-expire")
                    log_event(cfg, "expire_blacklist", domain=domain)
                except Exception as e:
                    log_event(cfg, "expire_error", domain=domain, error=str(e))
                removed.append(domain)
        except Exception:
            removed.append(domain)
    for d in removed:
        state["allows"].pop(d, None)
    if removed:
        write_state(state)

def add_unbound_refuse(domain: str):
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
    win = CFG["thresholds"]["post_window_seconds"]
    lst = [t for t in lst if t >= now - win]
    POST_COUNTS[domain] = lst

def check_spike_and_revoke(domain: str):
    cfg = CFG
    win = int(cfg["thresholds"]["post_window_seconds"])
    ratio = float(cfg["thresholds"]["post_spike_ratio"])
    count = len(POST_COUNTS.get(domain, []))
    baseline = max(1, win)  # 1 qps baseline
    if count > baseline * ratio:
        try:
            pihole_blacklist(domain, comment="auto-revoke:spike")
            log_event(cfg, "auto_revoke_spike", domain=domain, count=count)
            if cfg["unbound"].get("enable_hot_block", False):
                add_unbound_refuse(domain)
        except Exception as e:
            log_event(cfg, "auto_revoke_error", domain=domain, error=str(e))

# ---------- ROUTES ----------
if app:
    @app.route("/approve", methods=["POST"])
    def approve():
        cfg = CFG
        data = request.get_json(force=True, silent=True) or {}
        domain = (data.get("domain") or "").lower().strip()
        device = (data.get("device") or "").strip()
        token  = (data.get("token") or "").strip()
        ttl_h  = int(data.get("ttl_hours") or cfg["thresholds"]["default_ttl_hours"])

        # Auth
        if cfg["auth"]["device_tokens"].get(device) != token:
            log_event(cfg, "deny_auth", domain=domain, device=device, ip=request.remote_addr)
            return jsonify({"ok": False, "reason": "unauthorized"}), 403

        # Domain
        if not valid_domain(domain):
            log_event(cfg, "deny_invalid_domain", domain=domain, device=device, ip=request.remote_addr)
            return jsonify({"ok": False, "reason": "invalid_domain"}), 400

        # Cooldown
        key = f"{device}|{domain}"
        now_ts = time.time()
        last = LAST_DECISION.get(key, 0)
        if now_ts - last < cfg["thresholds"]["cooldown_seconds"]:
            log_event(cfg, "deny_rate", domain=domain, device=device, ip=request.remote_addr)
            return jsonify({"ok": False, "reason": "cooldown"}), 429
        LAST_DECISION[key] = now_ts

        # TI gate
        if cfg["feeds"].get("require_clean", True):
            load_ti()
            if in_ti(domain):
                log_event(cfg, "deny_threat", domain=domain, device=device, ip=request.remote_addr)
                return jsonify({"ok": False, "reason": "threat_feed_match"}), 403

        # Heuristics
        if heuristic_bad(domain):
            log_event(cfg, "deny_heuristic", domain=domain, device=device, ip=request.remote_addr)
            return jsonify({"ok": False, "reason": "heuristic_denied"}), 400

        # Human prompt
        if cfg["approval"]["mode"] == "prompt":
            if not prompt_user(domain, device):
                log_event(cfg, "deny_user", domain=domain, device=device, ip=request.remote_addr)
                return jsonify({"ok": False, "reason": "user_denied"})

        # Whitelist and schedule
        try:
            pihole_whitelist(domain, comment=f"auto-allow:temp:{ttl_h}h")
            schedule_ttl(domain, ttl_h)
            log_event(cfg, "allow", domain=domain, device=device, ip=request.remote_addr, ttl_h=ttl_h)
            # Spike check timer
            threading.Timer(cfg["thresholds"]["post_window_seconds"], check_spike_and_revoke, args=(domain,)).start()
            return jsonify({"ok": True, "domain": domain, "ttl_hours": ttl_h})
        except Exception as e:
            log_event(cfg, "error_api", domain=domain, device=device, ip=request.remote_addr, error=str(e))
            return jsonify({"ok": False, "reason": "pihole_api_error"}), 500

    @app.route("/revoke", methods=["POST"])
    def revoke():
        cfg = CFG
        data = request.get_json(force=True, silent=True) or {}
        domain = (data.get("domain") or "").lower().strip()
        device = (data.get("device") or "").strip()
        token  = (data.get("token") or "").strip()

        if cfg["auth"]["device_tokens"].get(device) != token:
            log_event(cfg, "deny_auth", domain=domain, device=device, ip=request.remote_addr)
            return jsonify({"ok": False, "reason": "unauthorized"}), 403

        if not valid_domain(domain):
            return jsonify({"ok": False, "reason": "invalid_domain"}), 400

        try:
            pihole_blacklist(domain, comment="manual-revoke")
            st = read_state()
            st.get("allows", {}).pop(domain, None)
            write_state(st)
            log_event(cfg, "manual_revoke", domain=domain, device=device)
            if cfg["unbound"].get("enable_hot_block", False):
                add_unbound_refuse(domain)
            return jsonify({"ok": True})
        except Exception as e:
            log_event(cfg, "error_revoke", domain=domain, error=str(e))
            return jsonify({"ok": False, "reason": "revoke_error"}), 500

    @app.route("/status", methods=["GET"])
    def status():
        cfg = CFG
        return jsonify({
            "ok": True,
            "now": time.time(),
            "ti_loaded": len(TI_SET),
            "config": {
                "server": cfg.get("server", {}),
                "feeds": {"ti_path": cfg["feeds"]["ti_path"], "require_clean": cfg["feeds"]["require_clean"]},
                "unbound": {"enable_hot_block": cfg["unbound"]["enable_hot_block"]},
            }
        })

# ---------- COMMANDS ----------
def cmd_run():
    if Flask is None:
        print("[!] Flask/PyYAML/requests not installed. Run: sudo python3 autoallowmonolith.py install")
        sys.exit(1)
    ensure_dirs()
    if not CFG_PATH.exists():
        save_yaml(CFG_PATH, DEFAULT_CFG)
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
        log_event(CFG, "manual_revoke_cli", domain=domain)
        if CFG["unbound"].get("enable_hot_block", False):
            add_unbound_refuse(domain)
        print(f"[✔] Revoked: {domain}")
    except Exception as e:
        print(f"[!] Revoke failed: {e}")
        log_event(CFG, "error_revoke_cli", domain=domain, error=str(e))
        sys.exit(1)

def install_assets():
    # Write system assets to canonical paths
    ensure_dirs()
    # Copy self
    self_src = Path(__file__).resolve()
    self_dst = BASE_DIR / "autoallowmonolith.py"
    if str(self_src) != str(self_dst):
        write_file(self_dst, self_src.read_text(), 0o755)
    # Unit and cron
    write_file(SYSTEMD_UNIT, SYSTEMD_UNIT_TEXT)
    write_file(CRON_TI, CRON_TI_TEXT)
    write_file(CRON_TTL, CRON_TTL_TEXT)

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

if __name__ == "__main__":
    main()