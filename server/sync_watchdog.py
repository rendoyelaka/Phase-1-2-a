"""
sync_watchdog.py - Phase 4B Auto-Sync + Cloudflare URL Updater
Runs as Windows Service via NSSM.

Does 3 things automatically:
1. Git pull every 60 seconds (auto-sync GitHub → RDP)
2. Monitors cloudflared tunnel URL → auto-updates StringPool.kt → git push
3. Sends Telegram alerts for new devices, URL changes, errors
"""

import os, sys, time, json, re, subprocess, logging, threading, base64, hmac, hashlib
import urllib.request

# ── Config ────────────────────────────────────────────────────────────────────
REPO_DIR        = r"C:\apk_factory\repo"
TOOLS_DIR       = r"C:\apk_factory\tools"
LOGS_DIR        = r"C:\apk_factory\logs"
CLOUDFLARED_LOG = os.path.join(LOGS_DIR, "cloudflared.log")
WATCHDOG_LOG    = os.path.join(LOGS_DIR, "sync_watchdog.log")
STRINGPOOL_PATH = os.path.join(REPO_DIR, "app", "src", "main", "java")
BOT_TOKEN       = "8897727723:AAGQ5aT2JbBV6p7mGC_PXssYhgSzZF7nak4"
MASTER_CHAT_ID  = "8205672036"
GIT_PULL_INTERVAL = 60   # seconds
URL_CHECK_INTERVAL = 10  # seconds
XOR_KEY         = b"n0vAsEed"

os.makedirs(LOGS_DIR, exist_ok=True)

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(WATCHDOG_LOG, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
log = logging.getLogger("watchdog")

# ── State ─────────────────────────────────────────────────────────────────────
current_tunnel_url = ""
last_pull_commit   = ""

# ── Helpers ───────────────────────────────────────────────────────────────────
def xor_encrypt(plaintext: str) -> str:
    b = plaintext.encode('utf-8')
    return base64.b64encode(
        bytes([b[i] ^ XOR_KEY[i % len(XOR_KEY)] for i in range(len(b))])
    ).decode('ascii')

def send_telegram(msg: str):
    try:
        url  = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        data = json.dumps({"chat_id": MASTER_CHAT_ID, "text": msg,
                           "parse_mode": "HTML"}).encode()
        req  = urllib.request.Request(url, data=data,
               headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        log.error(f"Telegram error: {e}")

def run_git(cmd: str):
    result = subprocess.run(
        cmd, shell=True, cwd=REPO_DIR,
        capture_output=True, text=True, timeout=60
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()

def find_stringpool():
    """Find StringPool.kt anywhere in repo."""
    for root, dirs, files in os.walk(STRINGPOOL_PATH):
        for f in files:
            if f == "StringPool.kt":
                return os.path.join(root, f)
    return None

def update_stringpool_url(new_url: str) -> bool:
    """Update SERVER_URL in StringPool.kt with new tunnel URL."""
    sp_path = find_stringpool()
    if not sp_path:
        log.error("StringPool.kt not found")
        return False

    with open(sp_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Encrypt new URL
    encrypted = xor_encrypt(new_url)

    # Replace SERVER_URL value
    new_content = re.sub(
        r'(val SERVER_URL\s*=\s*")[^"]*(")',
        f'\\g<1>{encrypted}\\g<2>',
        content
    )

    if new_content == content:
        log.warning("SERVER_URL pattern not found in StringPool.kt")
        return False

    with open(sp_path, 'w', encoding='utf-8') as f:
        f.write(new_content)

    log.info(f"StringPool.kt updated: {new_url}")
    return True

def git_push_url_update(new_url: str):
    """Commit and push StringPool.kt update."""
    sp_path = find_stringpool()
    if not sp_path:
        return

    # Stage only StringPool.kt
    rel_path = os.path.relpath(sp_path, REPO_DIR)
    run_git(f'git add "{rel_path}"')
    rc, out, err = run_git(f'git commit -m "Auto: Update tunnel URL [{new_url[:30]}...]"')
    if rc == 0:
        rc2, out2, err2 = run_git("git push")
        if rc2 == 0:
            log.info("StringPool.kt pushed to GitHub")
            send_telegram(
                f"🔗 <b>Tunnel URL Updated</b>\n"
                f"New URL: <code>{new_url}</code>\n"
                f"StringPool.kt auto-updated and pushed to GitHub.\n"
                f"GitHub Actions will rebuild Nova APK automatically."
            )
        else:
            log.error(f"Git push failed: {err2}")
    else:
        log.warning(f"Git commit: {out}")

# ── Thread 1: Git Pull ────────────────────────────────────────────────────────
def git_pull_loop():
    global last_pull_commit
    log.info("Git pull loop started")
    while True:
        try:
            rc, out, err = run_git("git pull")
            if rc == 0 and "Already up to date" not in out:
                log.info(f"Git pull: {out[:100]}")
                send_telegram(f"🔄 <b>Auto-Synced</b>\n{out[:200]}")
        except Exception as e:
            log.error(f"Git pull error: {e}")
        time.sleep(GIT_PULL_INTERVAL)

# ── Thread 2: Cloudflare URL Monitor ─────────────────────────────────────────
def cloudflare_url_loop():
    global current_tunnel_url
    log.info("Cloudflare URL monitor started")

    while True:
        try:
            # Method 1: Read from cloudflared log file
            new_url = None
            if os.path.exists(CLOUDFLARED_LOG):
                with open(CLOUDFLARED_LOG, 'r', encoding='utf-8', errors='replace') as f:
                    for line in f:
                        m = re.search(r'https://[a-z0-9\-]+\.trycloudflare\.com', line)
                        if m:
                            new_url = m.group(0)

            # Method 2: Check cloudflared API
            if not new_url:
                try:
                    with urllib.request.urlopen(
                        "http://localhost:2000/quicktunnel", timeout=3
                    ) as r:
                        data = json.loads(r.read())
                        new_url = "https://" + data.get("hostname", "")
                except Exception:
                    pass

            if new_url and new_url != current_tunnel_url:
                log.info(f"Tunnel URL changed: {new_url}")
                current_tunnel_url = new_url

                # Update StringPool.kt and push
                if update_stringpool_url(new_url):
                    git_push_url_update(new_url)

        except Exception as e:
            log.error(f"URL monitor error: {e}")

        time.sleep(URL_CHECK_INTERVAL)

# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    log.info("="*50)
    log.info("Sync Watchdog starting")
    log.info(f"Repo: {REPO_DIR}")
    log.info(f"Logs: {LOGS_DIR}")
    log.info("="*50)

    send_telegram("🟢 <b>Sync Watchdog Started</b>\nAuto-sync active. Monitoring GitHub and Cloudflare tunnel.")

    # Start threads
    t1 = threading.Thread(target=git_pull_loop, daemon=True)
    t2 = threading.Thread(target=cloudflare_url_loop, daemon=True)
    t1.start()
    t2.start()

    # Keep main thread alive
    while True:
        time.sleep(60)
