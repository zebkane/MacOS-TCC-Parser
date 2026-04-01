#!/usr/bin/env python3
"""
generate_tcc_samples.py

Generates realistic TCC.db test databases for forensic tool development.
Creates samples for multiple macOS schema versions:
  - Pre-Big Sur (Mojave/Catalina): uses allowed/prompt_count columns
  - Big Sur+  (Big Sur through Sequoia): uses auth_value/auth_reason/auth_version columns

Each database is populated with realistic-looking entries covering common
services, bundle IDs, and edge cases you'd encounter in real IR work.

Usage:
    python3 generate_tcc_samples.py [output_dir]
    Default output_dir: ./tcc_samples/
"""

import sqlite3
import os
import sys
import time
import struct
import hashlib

OUTPUT_DIR = sys.argv[1] if len(sys.argv) > 1 else "./tcc_samples"

# ─── Schema Definitions ────────────────────────────────────────────

# Pre-Big Sur schema (Mojave 10.14 / Catalina 10.15)
SCHEMA_PRE_BIGSUR = """
CREATE TABLE admin (key TEXT PRIMARY KEY NOT NULL, value INTEGER NOT NULL);

CREATE TABLE policies (
    id INTEGER NOT NULL PRIMARY KEY,
    bundle_id TEXT NOT NULL,
    uuid TEXT NOT NULL,
    display TEXT NOT NULL,
    UNIQUE (bundle_id, uuid)
);

CREATE TABLE active_policy (
    client TEXT NOT NULL,
    client_type INTEGER NOT NULL,
    policy_id INTEGER NOT NULL,
    PRIMARY KEY (client, client_type),
    FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE access (
    service        TEXT    NOT NULL,
    client         TEXT    NOT NULL,
    client_type    INTEGER NOT NULL,
    allowed        INTEGER NOT NULL,
    prompt_count   INTEGER NOT NULL,
    csreq          BLOB,
    policy_id      INTEGER,
    indirect_object_identifier_type INTEGER,
    indirect_object_identifier      TEXT NOT NULL DEFAULT 'UNUSED',
    indirect_object_code_identity   BLOB,
    flags          INTEGER,
    last_modified  INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),
    CONSTRAINT key PRIMARY KEY (service, client, client_type)
);

CREATE TABLE access_overrides (service TEXT NOT NULL PRIMARY KEY);
CREATE TABLE expired  (service TEXT NOT NULL, client TEXT NOT NULL, client_type INTEGER NOT NULL, csreq BLOB, last_modified INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)), expired_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)), CONSTRAINT key PRIMARY KEY (service, client, client_type));
"""

# Big Sur+ schema (11.0 through current Sequoia 15.x)
SCHEMA_BIGSUR_PLUS = """
CREATE TABLE admin (key TEXT PRIMARY KEY NOT NULL, value INTEGER NOT NULL);

CREATE TABLE policies (
    id INTEGER NOT NULL PRIMARY KEY,
    bundle_id TEXT NOT NULL,
    uuid TEXT NOT NULL,
    display TEXT NOT NULL,
    UNIQUE (bundle_id, uuid)
);

CREATE TABLE active_policy (
    client TEXT NOT NULL,
    client_type INTEGER NOT NULL,
    policy_id INTEGER NOT NULL,
    PRIMARY KEY (client, client_type),
    FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE access (
    service        TEXT    NOT NULL,
    client         TEXT    NOT NULL,
    client_type    INTEGER NOT NULL,
    auth_value     INTEGER NOT NULL,
    auth_reason    INTEGER NOT NULL,
    auth_version   INTEGER NOT NULL,
    csreq          BLOB,
    policy_id      INTEGER,
    indirect_object_identifier_type INTEGER,
    indirect_object_identifier      TEXT NOT NULL DEFAULT 'UNUSED',
    indirect_object_code_identity   BLOB,
    flags          INTEGER,
    last_modified  INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),
    CONSTRAINT key PRIMARY KEY (service, client, client_type)
);

CREATE TABLE access_overrides (service TEXT NOT NULL PRIMARY KEY);
CREATE TABLE expired  (service TEXT NOT NULL, client TEXT NOT NULL, client_type INTEGER NOT NULL, csreq BLOB, last_modified INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)), expired_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)), CONSTRAINT key PRIMARY KEY (service, client, client_type));
"""

# ─── Realistic Data ─────────────────────────────────────────────────

# auth_value meanings (Big Sur+)
AUTH_DENIED  = 0
AUTH_UNKNOWN = 1
AUTH_ALLOWED = 2
AUTH_LIMITED = 3   # e.g., Photos "limited access"

# auth_reason meanings (Big Sur+)
REASON_ERROR            = 1
REASON_USER_CONSENT     = 2
REASON_USER_SET         = 3
REASON_SYSTEM_SET       = 4
REASON_SERVICE_POLICY   = 5
REASON_MDM_POLICY       = 6
REASON_OVERRIDE_POLICY  = 7
REASON_MISSING_USAGE    = 8
REASON_PROMPT_TIMEOUT   = 9
REASON_PREFLIGHT_UNKNOWN = 10
REASON_ENTITLED         = 11
REASON_APP_TYPE_POLICY  = 12

# client_type: 0 = bundle ID, 1 = absolute path
CLIENT_BUNDLE = 0
CLIENT_PATH   = 1

def fake_csreq(bundle_id: str) -> bytes:
    """Generate a plausible-looking (but fake) csreq blob.
    Real csreq blobs are DER-encoded code signing requirements.
    We generate a recognizable fake so your parser can detect & handle them.
    """
    # Real csreq starts with 0xfade0c00 magic
    magic = b'\xfa\xde\x0c\x00'
    # Followed by length (big-endian uint32) and requirement data
    id_bytes = bundle_id.encode('utf-8') + b'\x00'
    # Pad to look realistic
    body = b'\x00\x00\x00\x01'  # expression count
    body += b'\x00\x00\x00\x06'  # identifier op
    body += b'\x00\x00\x00\x02'  # match equal
    body += struct.pack('>I', len(id_bytes))
    body += id_bytes
    # Pad to 4-byte boundary
    while len(body) % 4 != 0:
        body += b'\x00'
    total = magic + struct.pack('>I', len(magic) + 4 + len(body)) + body
    return total

def ts(days_ago: int) -> int:
    """Unix timestamp for N days ago."""
    return int(time.time()) - (days_ago * 86400)


# ─── Sample entries: (service, client, client_type, is_allowed, auth_reason, days_ago, notes) ───

# Benign / normal user apps
NORMAL_ENTRIES = [
    # Common productivity apps
    ("kTCCServiceMicrophone",          "us.zoom.xos",                    CLIENT_BUNDLE, True,  REASON_USER_SET,     90),
    ("kTCCServiceCamera",              "us.zoom.xos",                    CLIENT_BUNDLE, True,  REASON_USER_SET,     90),
    ("kTCCServiceScreenCapture",       "us.zoom.xos",                    CLIENT_BUNDLE, True,  REASON_USER_SET,     88),
    ("kTCCServiceMicrophone",          "com.microsoft.teams2",           CLIENT_BUNDLE, True,  REASON_USER_SET,     60),
    ("kTCCServiceCamera",              "com.microsoft.teams2",           CLIENT_BUNDLE, True,  REASON_USER_SET,     60),
    ("kTCCServiceMicrophone",          "com.tinyspeck.slackmacgap",      CLIENT_BUNDLE, True,  REASON_USER_SET,     45),
    ("kTCCServiceScreenCapture",       "com.tinyspeck.slackmacgap",      CLIENT_BUNDLE, True,  REASON_USER_SET,     30),
    ("kTCCServiceAppleEvents",         "com.googlecode.iterm2",          CLIENT_BUNDLE, True,  REASON_USER_SET,    120),
    ("kTCCServiceSystemPolicyAllFiles", "com.googlecode.iterm2",         CLIENT_BUNDLE, True,  REASON_USER_SET,    120),
    ("kTCCServiceAccessibility",       "com.googlecode.iterm2",          CLIENT_BUNDLE, True,  REASON_USER_SET,    120),

    # Browsers
    ("kTCCServiceMicrophone",          "com.google.Chrome",              CLIENT_BUNDLE, True,  REASON_USER_SET,    180),
    ("kTCCServiceCamera",              "com.google.Chrome",              CLIENT_BUNDLE, True,  REASON_USER_SET,    180),
    ("kTCCServiceScreenCapture",       "com.google.Chrome",              CLIENT_BUNDLE, False, REASON_USER_SET,    150),

    # Dev tools
    ("kTCCServiceDeveloperTool",       "com.apple.Terminal",             CLIENT_BUNDLE, True,  REASON_USER_SET,    200),
    ("kTCCServiceSystemPolicyAllFiles", "com.apple.Terminal",            CLIENT_BUNDLE, True,  REASON_USER_SET,    200),
    ("kTCCServiceAccessibility",       "com.microsoft.VSCode",           CLIENT_BUNDLE, True,  REASON_USER_SET,     30),

    # Apple defaults / system-set
    ("kTCCServiceAppleEvents",         "com.apple.finder",               CLIENT_BUNDLE, True,  REASON_APP_TYPE_POLICY, 365),
    ("kTCCServiceUbiquity",            "com.apple.CloudDocs.MobileDocumentsFileProvider", CLIENT_BUNDLE, True, REASON_ENTITLED, 365),

    # MDM-managed entries (corporate fleet)
    ("kTCCServiceScreenCapture",       "com.crowdstrike.falcon.Agent",   CLIENT_BUNDLE, True,  REASON_MDM_POLICY,  200),
    ("kTCCServiceSystemPolicyAllFiles", "com.crowdstrike.falcon.Agent",  CLIENT_BUNDLE, True,  REASON_MDM_POLICY,  200),
    ("kTCCServiceAccessibility",       "com.crowdstrike.falcon.Agent",   CLIENT_BUNDLE, True,  REASON_MDM_POLICY,  200),

    # Limited access (Photos)
    ("kTCCServicePhotos",              "com.tinyspeck.slackmacgap",      CLIENT_BUNDLE, "limited", REASON_USER_SET, 15),
]

# Suspicious / IR-relevant entries
SUSPICIOUS_ENTRIES = [
    # Unknown app with FDA — classic red flag
    ("kTCCServiceSystemPolicyAllFiles", "com.xyzupdater.helper",         CLIENT_BUNDLE, True,  REASON_USER_SET,     3),
    ("kTCCServiceAccessibility",       "com.xyzupdater.helper",          CLIENT_BUNDLE, True,  REASON_USER_SET,     3),
    ("kTCCServiceScreenCapture",       "com.xyzupdater.helper",          CLIENT_BUNDLE, True,  REASON_USER_SET,     3),

    # Path-based entry (unusual — often indicates manual TCC manipulation)
    ("kTCCServiceSystemPolicyAllFiles", "/tmp/.hidden/updater",          CLIENT_PATH,   True,  REASON_USER_SET,     1),
    ("kTCCServiceAccessibility",       "/usr/local/bin/helper_daemon",   CLIENT_PATH,   True,  REASON_USER_SET,     5),

    # Denied entries (user said no — still forensically relevant)
    ("kTCCServiceCamera",              "com.xyzupdater.helper",          CLIENT_BUNDLE, False, REASON_USER_SET,     3),
    ("kTCCServiceMicrophone",          "com.suspicious.screenrecorder",  CLIENT_BUNDLE, False, REASON_USER_SET,     7),
    ("kTCCServiceScreenCapture",       "com.suspicious.screenrecorder",  CLIENT_BUNDLE, True,  REASON_USER_SET,     7),

    # Input monitoring — keylogger indicator
    ("kTCCServiceListenEvent",         "com.productivity.keytracker",    CLIENT_BUNDLE, True,  REASON_USER_SET,     10),
    ("kTCCServicePostEvent",           "com.productivity.keytracker",    CLIENT_BUNDLE, True,  REASON_USER_SET,     10),

    # AppleEvents targeting (automation abuse)
    ("kTCCServiceAppleEvents",         "org.malware.dropper",            CLIENT_BUNDLE, True,  REASON_USER_SET,     2),
]

# Path-based entries for system-level TCC.db
SYSTEM_ENTRIES = [
    ("kTCCServiceSystemPolicyAllFiles", "/usr/libexec/sshd-keygen-wrapper", CLIENT_PATH, True, REASON_SYSTEM_SET, 365),
    ("kTCCServiceScreenCapture",       "com.crowdstrike.falcon.Agent",     CLIENT_BUNDLE, True, REASON_MDM_POLICY, 200),
    ("kTCCServiceSystemPolicyAllFiles", "com.crowdstrike.falcon.Agent",    CLIENT_BUNDLE, True, REASON_MDM_POLICY, 200),
    ("kTCCServiceSystemPolicyAllFiles", "com.apple.Terminal",              CLIENT_BUNDLE, True, REASON_USER_SET,   200),
    ("kTCCServiceAccessibility",       "com.crowdstrike.falcon.Agent",     CLIENT_BUNDLE, True, REASON_MDM_POLICY, 200),
    ("kTCCServiceEndpointSecurityClient", "com.crowdstrike.falcon.Agent",  CLIENT_BUNDLE, True, REASON_MDM_POLICY, 200),
]

# ─── Database Generation ────────────────────────────────────────────

def create_pre_bigsur_db(path: str, entries: list):
    """Create a TCC.db with the pre-Big Sur schema (Mojave/Catalina)."""
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA_PRE_BIGSUR)

    for (service, client, client_type, allowed, reason, days_ago) in entries:
        if allowed == "limited":
            allowed_int = 1
        elif allowed:
            allowed_int = 1
        else:
            allowed_int = 0

        csreq = fake_csreq(client) if client_type == CLIENT_BUNDLE else None

        conn.execute(
            """INSERT OR REPLACE INTO access
               (service, client, client_type, allowed, prompt_count,
                csreq, policy_id, indirect_object_identifier_type,
                indirect_object_identifier, indirect_object_code_identity,
                flags, last_modified)
               VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, NULL, 0, ?)""",
            (service, client, client_type, allowed_int, 1,
             csreq, 0, 'UNUSED', ts(days_ago))
        )

    conn.execute("INSERT OR REPLACE INTO admin VALUES ('version', 14)")
    conn.commit()
    conn.close()
    print(f"  ✓ {os.path.basename(path)}")


def create_bigsur_plus_db(path: str, entries: list, version: int = 1):
    """Create a TCC.db with the Big Sur+ schema."""
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA_BIGSUR_PLUS)

    for (service, client, client_type, allowed, reason, days_ago) in entries:
        if allowed == "limited":
            auth_val = AUTH_LIMITED
        elif allowed:
            auth_val = AUTH_ALLOWED
        else:
            auth_val = AUTH_DENIED

        csreq = fake_csreq(client) if client_type == CLIENT_BUNDLE else None

        # For AppleEvents, set indirect_object to the target app
        indirect_type = 0
        indirect_id = 'UNUSED'
        if service == 'kTCCServiceAppleEvents':
            indirect_type = 0
            indirect_id = 'com.apple.systemevents'

        conn.execute(
            """INSERT OR REPLACE INTO access
               (service, client, client_type, auth_value, auth_reason, auth_version,
                csreq, policy_id, indirect_object_identifier_type,
                indirect_object_identifier, indirect_object_code_identity,
                flags, last_modified)
               VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, NULL, 0, ?)""",
            (service, client, client_type, auth_val, reason, version,
             csreq, indirect_type, indirect_id, ts(days_ago))
        )

    conn.execute("INSERT OR REPLACE INTO admin VALUES ('version', 20)")
    conn.commit()
    conn.close()
    print(f"  ✓ {os.path.basename(path)}")


def create_expired_entries(conn_path: str):
    """Add expired entries to an existing Big Sur+ db (entries that were revoked)."""
    conn = sqlite3.connect(conn_path)
    # Simulate a revoked permission
    conn.execute(
        """INSERT OR REPLACE INTO expired
           (service, client, client_type, csreq, last_modified, expired_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        ("kTCCServiceScreenCapture", "com.old.removed.app", CLIENT_BUNDLE,
         fake_csreq("com.old.removed.app"), ts(60), ts(10))
    )
    conn.execute(
        """INSERT OR REPLACE INTO expired
           (service, client, client_type, csreq, last_modified, expired_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        ("kTCCServiceCamera", "com.xyzupdater.helper", CLIENT_BUNDLE,
         fake_csreq("com.xyzupdater.helper"), ts(30), ts(5))
    )
    conn.commit()
    conn.close()


# ─── Main ────────────────────────────────────────────────────────────

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("Generating TCC.db test samples...\n")

    # 1. Pre-Big Sur user TCC.db (Catalina-era schema)
    print("[Pre-Big Sur / Catalina schema]")
    create_pre_bigsur_db(
        os.path.join(OUTPUT_DIR, "catalina_user_TCC.db"),
        NORMAL_ENTRIES + SUSPICIOUS_ENTRIES
    )
    create_pre_bigsur_db(
        os.path.join(OUTPUT_DIR, "catalina_system_TCC.db"),
        SYSTEM_ENTRIES
    )

    # 2. Big Sur+ user TCC.db (modern schema)
    print("\n[Big Sur+ / Modern schema]")
    create_bigsur_plus_db(
        os.path.join(OUTPUT_DIR, "sonoma_user_TCC.db"),
        NORMAL_ENTRIES + SUSPICIOUS_ENTRIES,
        version=1
    )
    create_bigsur_plus_db(
        os.path.join(OUTPUT_DIR, "sonoma_system_TCC.db"),
        SYSTEM_ENTRIES,
        version=1
    )

    # 3. Add expired entries to the modern user db
    create_expired_entries(os.path.join(OUTPUT_DIR, "sonoma_user_TCC.db"))
    print("  ✓ Added expired/revoked entries to sonoma_user_TCC.db")

    # 4. Sequoia-era with additional services
    sequoia_extras = [
        ("kTCCServiceWebKitIntelligentTrackingPrevention", "com.apple.Safari", CLIENT_BUNDLE, True, REASON_APP_TYPE_POLICY, 30),
        ("kTCCServiceSystemPolicySysAdminFiles",           "com.apple.Terminal", CLIENT_BUNDLE, True, REASON_USER_SET, 10),
        ("kTCCServiceFileProviderDomain",                  "com.apple.CloudDocs.MobileDocumentsFileProvider", CLIENT_BUNDLE, True, REASON_ENTITLED, 365),
    ]
    print("\n[Sequoia schema - with newer service types]")
    create_bigsur_plus_db(
        os.path.join(OUTPUT_DIR, "sequoia_user_TCC.db"),
        NORMAL_ENTRIES + SUSPICIOUS_ENTRIES + sequoia_extras,
        version=1
    )

    # 5. Minimal / edge-case db (empty, corrupted header test)
    print("\n[Edge cases]")
    conn = sqlite3.connect(os.path.join(OUTPUT_DIR, "empty_TCC.db"))
    conn.executescript(SCHEMA_BIGSUR_PLUS)
    conn.execute("INSERT OR REPLACE INTO admin VALUES ('version', 20)")
    conn.commit()
    conn.close()
    print("  ✓ empty_TCC.db (valid schema, no access entries)")

    # 6. Malware-focused scenario db
    print("\n[Malware scenario - XCSSET-style TCC abuse]")
    malware_entries = [
        # Legitimate apps that XCSSET would piggyback on
        ("kTCCServiceScreenCapture",       "us.zoom.xos",                  CLIENT_BUNDLE, True,  REASON_USER_SET,     90),
        ("kTCCServiceScreenCapture",       "com.tinyspeck.slackmacgap",    CLIENT_BUNDLE, True,  REASON_USER_SET,     60),
        ("kTCCServiceScreenCapture",       "com.hnc.Discord",              CLIENT_BUNDLE, True,  REASON_USER_SET,     45),
        # The malware itself getting perms via injection/hijack
        ("kTCCServiceScreenCapture",       "com.apple.dt.Xcode",           CLIENT_BUNDLE, True,  REASON_USER_SET,     2),
        ("kTCCServiceSystemPolicyAllFiles", "com.apple.dt.Xcode",          CLIENT_BUNDLE, True,  REASON_USER_SET,     2),
        ("kTCCServiceAccessibility",       "com.apple.dt.Xcode",           CLIENT_BUNDLE, True,  REASON_USER_SET,     2),
        # Path-based backdoor
        ("kTCCServiceSystemPolicyAllFiles", "/Users/victim/.xcode/helper",  CLIENT_PATH,  True,  REASON_USER_SET,     1),
        ("kTCCServiceAccessibility",       "/Users/victim/.xcode/helper",   CLIENT_PATH,  True,  REASON_USER_SET,     1),
    ]
    create_bigsur_plus_db(
        os.path.join(OUTPUT_DIR, "malware_scenario_TCC.db"),
        malware_entries,
        version=1
    )

    print(f"\n{'='*60}")
    print(f"Generated {len(os.listdir(OUTPUT_DIR))} TCC.db files in: {OUTPUT_DIR}/")
    print(f"\nFiles:")
    for f in sorted(os.listdir(OUTPUT_DIR)):
        size = os.path.getsize(os.path.join(OUTPUT_DIR, f))
        print(f"  {f:45s} {size:>6,} bytes")

    print(f"""
Schema Reference:
  Pre-Big Sur:  allowed (0/1), prompt_count
  Big Sur+:     auth_value (0=denied, 2=allowed, 3=limited),
                auth_reason (2=user_consent, 3=user_set, 4=system_set,
                             6=mdm_policy, 11=entitled, 12=app_type_policy)

Key forensic services to watch:
  kTCCServiceSystemPolicyAllFiles  →  Full Disk Access
  kTCCServiceAccessibility         →  Accessibility (can control computer)
  kTCCServiceScreenCapture         →  Screen Recording
  kTCCServiceListenEvent           →  Input Monitoring (keylogger indicator)
  kTCCServicePostEvent             →  Synthetic input (keystroke injection)
  kTCCServiceCamera / Microphone   →  Camera / Microphone
  kTCCServiceEndpointSecurityClient → Endpoint Security (EDR)
  kTCCServiceAppleEvents           →  AppleEvent automation

Red flags in IR:
  - Path-based clients (client_type=1) with suspicious paths
  - Unknown bundle IDs with FDA + Accessibility + ScreenCapture
  - Recent last_modified on sensitive services
  - Entries in the 'expired' table (permissions that were revoked)
""")


if __name__ == "__main__":
    main()
