#!/usr/bin/env python3
"""Upload simulator screenshot to App Store Connect."""
import time, json, base64, hashlib, urllib.request, urllib.error

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

KEY_ID    = "REDACTED_OLD_KEY_ID"
ISSUER_ID = "REDACTED_ISSUER_ID"
KEY_PATH  = "/Users/greywizard/.appstoreconnect/private_keys/AuthKey_REDACTED_OLD_KEY_ID.p8"

SCREENSHOT_PATH = "/tmp/ntm_67.png"
APP_ID   = "6771022122"
VER_ID   = "977a2b28-0c3d-4556-8556-77612b93a0f4"

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def make_jwt() -> str:
    header  = b64url(json.dumps({"alg":"ES256","kid":KEY_ID,"typ":"JWT"}).encode())
    now     = int(time.time())
    payload = b64url(json.dumps({"iss":ISSUER_ID,"iat":now,"exp":now+1100,"aud":"appstoreconnect-v1"}).encode())
    msg     = f"{header}.{payload}".encode()
    with open(KEY_PATH, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    sig = key.sign(msg, ec.ECDSA(hashes.SHA256()))
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

# ── Get version localization ID ───────────────────────────────────────────────
ver_loc_data, _ = api("GET", f"appStoreVersions/{VER_ID}/appStoreVersionLocalizations")
en_ver_loc = next(x for x in ver_loc_data["data"] if x["attributes"]["locale"] == "en-US")
ver_loc_id = en_ver_loc["id"]
print(f"VersionLocalization ID: {ver_loc_id}")

# ── Find or create screenshot set for 6.9" iPhone ────────────────────────────
sets_data, _ = api("GET", f"appStoreVersionLocalizations/{ver_loc_id}/appScreenshotSets")
ss_set = next((x for x in sets_data["data"]
               if x["attributes"]["screenshotDisplayType"] == "APP_IPHONE_67"), None)

if ss_set is None:
    resp, code = api("POST", "appScreenshotSets", {
        "data": {
            "type": "appScreenshotSets",
            "attributes": {"screenshotDisplayType": "APP_IPHONE_67"},
            "relationships": {
                "appStoreVersionLocalization": {
                    "data": {"type": "appStoreVersionLocalizations", "id": ver_loc_id}
                }
            }
        }
    })
    if code not in (200, 201):
        print("Failed to create screenshot set:", json.dumps(resp, indent=2))
        exit(1)
    ss_set_id = resp["data"]["id"]
    print(f"Created screenshot set: {ss_set_id}")
else:
    ss_set_id = ss_set["id"]
    print(f"Existing screenshot set: {ss_set_id}")

# ── Read screenshot file ──────────────────────────────────────────────────────
with open(SCREENSHOT_PATH, "rb") as f:
    img_data = f.read()
file_size = len(img_data)
file_md5  = hashlib.md5(img_data).hexdigest()
print(f"Screenshot: {file_size} bytes, MD5={file_md5}")

# ── Reserve the screenshot slot ───────────────────────────────────────────────
resp, code = api("POST", "appScreenshots", {
    "data": {
        "type": "appScreenshots",
        "attributes": {
            "fileName": "ntm_screenshot_login.png",
            "fileSize": file_size,
        },
        "relationships": {
            "appScreenshotSet": {
                "data": {"type": "appScreenshotSets", "id": ss_set_id}
            }
        }
    }
})
if code not in (200, 201):
    print("Failed to reserve screenshot:", json.dumps(resp, indent=2))
    exit(1)

screenshot_id = resp["data"]["id"]
upload_ops    = resp["data"]["attributes"]["uploadOperations"]
print(f"Reserved screenshot ID: {screenshot_id}")
print(f"Upload operations: {len(upload_ops)}")

# ── Upload via the returned upload operations ─────────────────────────────────
for op in upload_ops:
    method  = op["method"]
    url     = op["url"]
    offset  = op["offset"]
    length  = op["length"]
    headers = {h["name"]: h["value"] for h in op.get("requestHeaders", [])}

    chunk = img_data[offset:offset+length]
    req = urllib.request.Request(url, data=chunk, method=method)
    for k, v in headers.items():
        req.add_header(k, v)
    with urllib.request.urlopen(req) as r:
        print(f"  Uploaded chunk offset={offset} length={length}: HTTP {r.status}")

# ── Commit the screenshot ─────────────────────────────────────────────────────
resp, code = api("PATCH", f"appScreenshots/{screenshot_id}", {
    "data": {
        "type": "appScreenshots",
        "id": screenshot_id,
        "attributes": {
            "uploaded": True,
            "sourceFileChecksum": file_md5,
        }
    }
})
print(f"Commit screenshot: {code}")
if code not in (200, 201):
    print("Response:", json.dumps(resp, indent=2))
else:
    print("Screenshot uploaded and committed successfully.")
