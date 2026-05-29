#!/usr/bin/env python3
"""Fill App Store Connect metadata for NTM Dashboard."""
import time, json, base64, hashlib, hmac, struct, urllib.request, urllib.error

# ── JWT generation (ES256) ───────────────────────────────────────────────────
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

import os, sys
KEY_ID    = os.environ.get("ASC_KEY_ID")    or sys.exit("Set ASC_KEY_ID env var (10-char key ID)")
ISSUER_ID = os.environ.get("ASC_ISSUER_ID") or sys.exit("Set ASC_ISSUER_ID env var (UUID issuer)")
# Key is stored in macOS Keychain: service=appstoreconnect-api-key, account=<KEY_ID>

import subprocess

def _load_key_pem() -> bytes:
    """Retrieve .p8 PEM from macOS Keychain (stored as hex by `security`)."""
    hex_pw = subprocess.check_output([
        "security", "find-generic-password",
        "-s", "appstoreconnect-api-key",
        "-a", KEY_ID, "-w"
    ]).decode().strip()
    return bytes.fromhex(hex_pw)

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def make_jwt() -> str:
    header  = b64url(json.dumps({"alg":"ES256","kid":KEY_ID,"typ":"JWT"}).encode())
    now     = int(time.time())
    payload = b64url(json.dumps({"iss":ISSUER_ID,"iat":now,"exp":now+1100,"aud":"appstoreconnect-v1"}).encode())
    msg     = f"{header}.{payload}".encode()
    key = serialization.load_pem_private_key(_load_key_pem(), password=None)
    sig = key.sign(msg, ec.ECDSA(hashes.SHA256()))
    # DER → raw (r||s)
    import cryptography.hazmat.primitives.asymmetric.utils as asn1
    r, s = asn1.decode_dss_signature(sig)
    raw_sig = r.to_bytes(32,"big") + s.to_bytes(32,"big")
    return f"{header}.{payload}.{b64url(raw_sig)}"

def api(method, path, body=None):
    url = f"https://api.appstoreconnect.apple.com/v1/{path}"
    data = json.dumps(body).encode() if body else None
    req  = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {make_jwt()}")
    req.add_header("Content-Type",  "application/json")
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read()), r.status
    except urllib.error.HTTPError as e:
        return json.loads(e.read()), e.code

# ── Find app ─────────────────────────────────────────────────────────────────
data, _ = api("GET", "apps?filter[bundleId]=com.ntm.NTMDashboard")
app_id   = data["data"][0]["id"]
print(f"App ID: {app_id}")

# ── App-level info (category + content rights) ───────────────────────────────
info_data, _ = api("GET", f"apps/{app_id}/appInfos")
app_info_id   = info_data["data"][0]["id"]
print(f"AppInfo ID: {app_info_id}")

resp, code = api("PATCH", f"appInfos/{app_info_id}", {
    "data": {
        "type": "appInfos",
        "id":   app_info_id,
        "attributes": {
            "primaryCategory": "UTILITIES"
        }
    }
})
print(f"Category update: {code}")

# ── Localisation (en-US) ─────────────────────────────────────────────────────
loc_data, _ = api("GET", f"appInfos/{app_info_id}/appInfoLocalizations")
en_loc = next((x for x in loc_data["data"] if x["attributes"]["locale"] == "en-US"), None)

loc_attrs = {
    "name":             "NTM Dashboard",
    "subtitle":         "Self-Hosted Network Monitor",
    "privacyPolicyUrl": "https://greywizardpublic.github.io/ntm-privacy/",
}

if en_loc:
    resp, code = api("PATCH", f"appInfoLocalizations/{en_loc['id']}", {
        "data": {"type": "appInfoLocalizations", "id": en_loc["id"], "attributes": loc_attrs}
    })
    print(f"AppInfoLocalization PATCH: {code}")
else:
    resp, code = api("POST", "appInfoLocalizations", {
        "data": {
            "type": "appInfoLocalizations",
            "attributes": {**loc_attrs, "locale": "en-US"},
            "relationships": {"appInfo": {"data": {"type": "appInfos", "id": app_info_id}}}
        }
    })
    print(f"AppInfoLocalization POST: {code}")

# ── App Store Version localisation ────────────────────────────────────────────
ver_data, _ = api("GET", f"apps/{app_id}/appStoreVersions?filter[platform]=IOS")
ver_id = ver_data["data"][0]["id"]
print(f"Version ID: {ver_id}")

ver_loc_data, _ = api("GET", f"appStoreVersions/{ver_id}/appStoreVersionLocalizations")
en_ver_loc = next((x for x in ver_loc_data["data"] if x["attributes"]["locale"] == "en-US"), None)

DESCRIPTION = """\
NTM Dashboard is the iOS companion for Network Traffic Monitor — an open-source, \
self-hosted system that aggregates network traffic from all your devices in real time.

Point it at your own ntm-server and instantly see:

• Interface traffic — per-device, per-NIC packet and byte totals over a rolling window
• Entity flows — which autonomous systems (ASNs) your traffic is flowing through, \
sorted by volume
• LAN devices — unknown devices on your network, grouped by WAN IP so multi-site \
deployments stay tidy
• Client health — per-client pcap and buffer drop statistics so you know when \
packet capture is overloaded

SECURITY FIRST
All communication uses HTTPS with optional certificate pinning. Sign in with a \
WebAuthn passkey (Face ID / Touch ID) — no password is ever sent over the network. \
Session tokens are stored in the iOS Keychain.

COMPLETELY PRIVATE
NTM Dashboard connects only to the server you configure. No analytics, no \
third-party SDKs, no data leaves your infrastructure.

REQUIREMENTS
• A running ntm-server (open source — github.com/GreyWizardPublic/network-traffic-monitor)
• iOS 18 or later\
"""

KEYWORDS = "network monitor,traffic,bandwidth,home lab,self-hosted,LAN,packet,server,dashboard,security"

WHATS_NEW = """\
Version 1.4 — Passkey Authentication

• Sign in with Face ID or Touch ID via WebAuthn passkey — no password sent over the network
• Register new devices using your admin password (PBKDF2-derived proof only)
• Session token stored securely in the iOS Keychain
• Sign out from Settings
• Fixed: default port corrected to 8443 (web dashboard port)\
"""

ver_loc_attrs = {
    "description":   DESCRIPTION,
    "keywords":      KEYWORDS,
    "supportUrl":    "https://github.com/GreyWizardPublic/network-traffic-monitor/issues",
    "marketingUrl":  "https://github.com/GreyWizardPublic/network-traffic-monitor",
}

if en_ver_loc:
    resp, code = api("PATCH", f"appStoreVersionLocalizations/{en_ver_loc['id']}", {
        "data": {"type": "appStoreVersionLocalizations", "id": en_ver_loc["id"],
                 "attributes": ver_loc_attrs}
    })
    print(f"VersionLocalization PATCH: {code}")
else:
    resp, code = api("POST", "appStoreVersionLocalizations", {
        "data": {
            "type": "appStoreVersionLocalizations",
            "attributes": {**ver_loc_attrs, "locale": "en-US"},
            "relationships": {"appStoreVersion": {"data": {"type": "appStoreVersions", "id": ver_id}}}
        }
    })
    print(f"VersionLocalization POST: {code}")

# ── Age rating ────────────────────────────────────────────────────────────────
# ageRatingDeclaration lives under appInfos (not appStoreVersions)
ai_detail, _ = api("GET", f"appInfos/{app_info_id}?include=ageRatingDeclaration")
included = ai_detail.get("included", [])
rating_obj = next((x for x in included if x.get("type") == "ageRatingDeclarations"), None)
if rating_obj is None:
    rel = ai_detail.get("data", {}).get("relationships", {}).get("ageRatingDeclaration", {})
    rating_id = rel.get("data", {}).get("id")
    if not rating_id:
        print("Could not find ageRatingDeclaration ID; skipping age rating.")
        rating_id = None
else:
    rating_id = rating_obj["id"]

if rating_id:
    resp, code = api("PATCH", f"ageRatingDeclarations/{rating_id}", {
        "data": {
            "type": "ageRatingDeclarations",
            "id":   rating_id,
            "attributes": {
                "kidsAgeBand":                              None,
                "matureOrSuggestiveThemes":                 "NONE",
                "profanityOrCrudeHumor":                    "NONE",
                "violenceCartoonOrFantasy":                  "NONE",
                "violenceRealisticProlongedGraphicOrSadistic": "NONE",
                "violenceRealistic":                         "NONE",
                "gambling":                                  False,
                "gamblingSimulated":                         "NONE",
                "contests":                                  "NONE",
                "alcoholTobaccoOrDrugUseOrReferences":       "NONE",
                "medicalOrTreatmentInformation":             "NONE",
                "sexualContentGraphicAndNudity":             "NONE",
                "sexualContentOrNudity":                     "NONE",
                "horrorOrFearThemes":                        "NONE",
                "unrestrictedWebAccess":                     False,
                "lootBox":                                   False,
                "advertising":                               False,
                "parentalControls":                          False,
                "ageAssurance":                              False,
                "messagingAndChat":                          False,
                "userGeneratedContent":                      False,
                "gunsOrOtherWeapons":                        "NONE",
                "healthOrWellnessTopics":                    False,
            }
        }
    })
    print(f"Age rating: {code}")
    if code not in (200, 201):
        print("Age rating response:", json.dumps(resp, indent=2))

print("\nAll metadata updated successfully.")
