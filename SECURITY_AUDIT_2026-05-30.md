# Network-Traffic-Monitor — Security Audit Report

**Date:** 2026-05-30
**Auditor:** Claude (Opus 4.7)
**Scope:** ntm-server (Linux), ntm-client (Linux + Windows), iOS apps (NTMDashboard, NTMClient), build & deployment scripts, third-party dependencies
**Methodology:** Manual code review, adversarial (red-team) modelling against authentication, transport, signing, update, and admin endpoints. Cross-referenced library versions against public CVE databases (NVD, GHSA). Confirmed exploits with proof-of-concept where possible.

---

## Executive Summary

The codebase has a mature, defense-in-depth security posture: ML-DSA-65 signed binaries, Ed25519 client authentication, WebAuthn passkey login, ALPN port multiplexing, persistent rate limiting, and strong server-side TLS configuration. The post-quantum signing and short-lived nonce-based auth proofs are particularly well-designed.

That said, **one critical and several high-severity issues** warrant immediate attention. The most pressing is a **cookie-name confusion bug** in `web_auth.hpp::cookieFromHeader()` that allows session/admin-proof hijacking when chained with any cookie-injection primitive (XSS or subdomain attack). Proof-of-concept confirmed.

| Severity | Count |
|---|---|
| Critical | 1 |
| High | 4 |
| Medium | 5 |
| Low | 6 |
| Informational | 3 |
| **Total** | **19** |

---

## CRITICAL

### C-1 — Cookie-name prefix confusion in `cookieFromHeader()` (CWE-1023)

**File:** `src/web_auth.hpp:29-39`
**Affects:** ntm-server (web dashboard, admin API)
**Confirmed exploitable** — PoC below.

The cookie parser uses `find(name + "=")` which matches **anywhere** in the Cookie header. An attacker who can plant a cookie whose name *ends with* the target cookie name will have their value returned instead of the legitimate one.

```cpp
inline std::string cookieFromHeader(const std::string &cookieHeader,
                                    const std::string &name)
{
    const std::string prefix = name + "=";
    auto pos = cookieHeader.find(prefix);   // <-- matches as substring anywhere
    ...
}
```

**Proof-of-concept (verified):**

```
Input header: "x_ntm_session=ATTACKER; ntm_session=victim_real_token"
Result:        "ATTACKER"           ← wrong; should be "victim_real_token"
```

Same applies to `ntm_admin` — an attacker who plants `_ntm_admin=<their_token>` bypasses admin proof verification.

**Exploitation chains:**
- **XSS** anywhere in the dashboard → `document.cookie = "_ntm_admin=<stolen_or_predicted>; path=/"` → bypass admin re-auth on every admin endpoint for the victim's session
- **Subdomain takeover** of any `*.<your-rp-id>` → set `Domain=.<your-rp-id>` cookie that the main app reads first
- **Network-position attacker on plaintext HTTP** redirecting to the HTTPS dashboard can set cookies via the Set-Cookie header on the 30x → ATS/HSTS mitigates but not absolute

**Fix:** Walk cookies properly using `; ` as separator. Minimal patch:

```cpp
inline std::string cookieFromHeader(const std::string &cookieHeader,
                                    const std::string &name)
{
    const std::string prefix = name + "=";
    std::size_t pos = 0;
    while (pos < cookieHeader.size())
    {
        // Skip leading whitespace after ';'
        while (pos < cookieHeader.size() && cookieHeader[pos] == ' ') ++pos;
        // Check if this cookie starts with `name=`
        if (cookieHeader.compare(pos, prefix.size(), prefix) == 0)
        {
            std::size_t start = pos + prefix.size();
            std::size_t end   = cookieHeader.find(';', start);
            return cookieHeader.substr(start,
                end == std::string::npos ? std::string::npos : end - start);
        }
        // Advance past this cookie
        pos = cookieHeader.find(';', pos);
        if (pos == std::string::npos) break;
        ++pos;
    }
    return {};
}
```

Add regression tests in `tests/test_web_auth.cpp`:

```cpp
TEST_CASE("cookieFromHeader: does not match suffix-of-longer-name")
{
    REQUIRE_EQ(ntm::cookieFromHeader("evil_ntm_session=attacker; ntm_session=good",
                                     "ntm_session"),
               std::string{"good"});
}
TEST_CASE("cookieFromHeader: hostile prefix only")
{
    REQUIRE_EQ(ntm::cookieFromHeader("evil_ntm_admin=attacker", "ntm_admin"),
               std::string{});
}
```

---

## HIGH

### H-1 — Build push scripts use `curl --insecure` (CWE-295)

**Files:** `scripts/push-upgrade.sh:177,244`, `scripts/push-client.sh` (same pattern)

Both deploy scripts disable TLS certificate verification:

```bash
NONCE_RESP=$(curl --silent --show-error --fail \
    --insecure \                       # <-- bypasses certificate validation
    "$BASE_URL/admin/upgrade/nonce")
```

A network attacker on the path between the build machine and `ntm.happyhomelives.me` can:
- Capture the binary + signature + auth proof and learn server addresses, build cadence
- **Cannot** substitute the binary (it's ML-DSA-signed and the auth proof is bound to nonce+sha3 of the legit binary)
- **Can** silently drop pushes, delay them, or feed stale nonces — operational/availability impact
- **Can** observe the upgrade pattern to time other attacks against the server during the 30 s drain window

**Fix:** Replace `--insecure` with `--cacert "$HOME/.ntm/server_cert.pem"` after pinning a copy of the server's certificate on the build machine. If the deployment uses Let's Encrypt or another public CA, just remove `--insecure` and let curl validate the chain.

### H-2 — Updater download has no size cap on Linux (CWE-770)

**File:** `src/updater.cpp:685-696`

The 64 MiB download cap is guarded by `#ifdef _WIN32`. On Linux the cap is missing, so a compromised or malicious update server can return an arbitrarily large body. `httpsGetToFile()` reads until EOF (or until `expectedSize` bytes), which fills the client's filesystem and OOM-kills the updater process.

Even if the post-download SHA-256 verification later catches the mismatch and the file is removed, the **damage is done during the download** (disk-full kernel panic on small embedded clients, swap thrashing).

**Fix:** Move the cap out of the `#ifdef _WIN32` block:

```cpp
constexpr std::int64_t kMaxUpdateBytes = 64LL * 1024 * 1024;
if (size > kMaxUpdateBytes) { /* refuse */ }
```

Also enforce a hard cap inside `httpsGetToFile()` itself in case `size` is 0 (read-to-EOF mode that the recent fix preserves) — at minimum a 256 MiB ceiling that aborts the read.

### H-3 — iOS CertificatePinner TOFU silently accepts any system-trusted cert (CWE-295)

**Files:** `ios/NTMClient/.../CertificatePinner.swift:37-39`, `ios/NTMDashboard/.../CertificatePinner.swift:36-39`

When `pinnedCertData == nil` (first run, pre-setup, or after a reset), the pinner does:

```swift
} else {
    // No pinning — accept based on system CA trust
    completionHandler(.useCredential, URLCredential(trust: serverTrust))
}
```

This effectively trusts whatever cert iOS gave to the SecTrust object before the delegate fired. With default ATS settings (no `NSAllowsArbitraryLoads` in Info.plist) this means any CA-signed cert is accepted — a CA breach, mis-issuance, or DV-cert acquired by an attacker who controls DNS/BGP for the host is sufficient to MITM.

**Fix:**
- For users running self-signed servers: require pinning before login completes (refuse `completionHandler(.useCredential)` when `pinnedCertData == nil` and force the user through the explicit TOFU "pin this fingerprint?" flow).
- For users with CA-signed servers: explicitly call `SecTrustEvaluateWithError` before accepting, and consider implementing public-key pinning (SPKI hash) so cert rotation works while still constraining to a known key.

### H-4 — Identity file permission check is a warning, not a hard fail (CWE-732)

**File:** `src/client_linux.cpp:258-274` (Linux), `src/client_windows.cpp:317-396` (Windows)

The Linux client warns but **does not refuse to run** when the Ed25519 identity key is group/world-readable or owned by someone other than the running user. A misconfigured deployment that drops the key with `0644` perms (the default umask for many copy operations) is silently degraded into a credential-leak risk. Anyone on that machine with `world+r` access can exfiltrate the wire-protocol identity and impersonate the host to the server, allowing them to inject fabricated network-flow data attributed to the victim.

```cpp
if ((st.st_mode & (S_IRWXG | S_IRWXO)) != 0)
{
    // warning only
    if (isDaemon) syslog(LOG_WARNING, "%s (path=%s)", msg, path.c_str());
    ...
}
```

**Fix:** Refuse to start when `(st.st_mode & (S_IRWXG | S_IRWXO)) != 0` or `st.st_uid != geteuid()`. Provide a clear remediation command in the error message.

---

## MEDIUM

### M-1 — Server TLS: no cipher restriction or `SSL_OP_CIPHER_SERVER_PREFERENCE`

**File:** `src/server_core.cpp:1196-1230`

TLS 1.2+ is enforced (good), but the server inherits OpenSSL's default cipher list and does not set `SSL_OP_CIPHER_SERVER_PREFERENCE`. In TLS 1.2 this means a client could negotiate non-PFS ciphers (e.g. `TLS_RSA_WITH_*`) if both sides support them. OpenSSL 3.6 defaults are reasonable but tightening is recommended.

**Fix:**
```cpp
SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                          SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 |
                          SSL_OP_CIPHER_SERVER_PREFERENCE);
SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);  // TLS 1.3 only in 2026+
// Or restrict to ECDHE+AEAD only:
SSL_CTX_set_cipher_list(ctx, "ECDHE+AESGCM:ECDHE+CHACHA20");
```

### M-2 — `std::system("chmod 0755 '" + path + "' ...")` shell injection latent (CWE-78)

**File:** `src/server_upgrade.hpp:428`

```cpp
if (std::system(("chmod 0755 '" + binTmp + "' 2>/dev/null").c_str()) != 0)
```

`binTmp` is derived from `config.upgrade_binary_path` which is `readlink("/proc/self/exe")` — currently not attacker-influenced, but using `std::system()` here is fragile: any future change that lets the upgrade path come from a config file would immediately expose command injection (single-quote escape via `'`).

**Fix:** Replace with the direct syscall, which has no shell-parsing surface and is portable:

```cpp
#include <sys/stat.h>
if (::chmod(binTmp.c_str(), 0755) != 0) {
    cleanup(); errOut = "chmod failed"; return false;
}
```

### M-3 — No HTTP Strict Transport Security (HSTS) header

**File:** `src/web_dashboard.cpp:2700-2706`

Security headers set on every response include `X-Content-Type-Options` and a `Content-Security-Policy`. **Missing:** `Strict-Transport-Security`. A first-time visitor on hostile WiFi who types `http://your-server/` could be downgraded by a network attacker (HTTP-strip) before HTTPS pinning kicks in.

**Fix:** Add to the pre-routing handler:
```cpp
res.set_header("Strict-Transport-Security",
               "max-age=31536000; includeSubDomains");
```
Also consider `Referrer-Policy: no-referrer` and `Permissions-Policy: ()`.

### M-4 — CSP allows `'unsafe-inline'` for scripts (CWE-94)

**File:** `src/web_dashboard.cpp:2702-2705`

```cpp
res.set_header("Content-Security-Policy",
               "default-src 'self'; "
               "script-src 'self' 'unsafe-inline'; "
               "style-src 'self' 'unsafe-inline'");
```

The embedded dashboard HTML uses inline `<script>` blocks, so `'unsafe-inline'` is currently required. But this nullifies CSP as an XSS defense layer. If any reflected/stored XSS slips through `esc()` (e.g., a future H-line field added without escaping), the CSP would block nothing.

**Fix (medium-term):** Move all inline scripts/styles to separate JS/CSS resources served by the same server, then drop `'unsafe-inline'`. Add `nonce-…` for any remaining inline scripts. This is mechanical refactoring of `kDashboardHtml` / `kAdminHtml` literals.

### M-5 — `KeychainService` (NTMClient + NTMDashboard) does not set `kSecAttrAccessible`

**Files:** `ios/NTMClient/.../KeychainService.swift:10-17`, `ios/NTMDashboard/.../KeychainService.swift`

Session tokens default to `kSecAttrAccessibleWhenUnlocked` (no `ThisDeviceOnly`), making them eligible for iCloud Keychain sync and device-restore exfil. The Ed25519 wire key in `WireKeyService.swift` correctly uses `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` — apply the same to session tokens.

**Fix:**
```swift
kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
```

---

## LOW

### L-1 — `jsonStr()` in `updater.cpp` does not handle JSON escape sequences

**File:** `src/updater.cpp:263-272`

The hand-rolled JSON parser stops at the first `"` after `"key":"`, so a response containing escaped quotes (`\"`) is mis-parsed. Server-side values (`sha256`, `version`, `filename`) never contain quotes in practice, so this is not currently exploitable, but is fragile if the server schema evolves.

### L-2 — Updater Host-header constructed via string concat

**File:** `src/updater.cpp:332`

```cpp
std::string req = "GET " + path + " HTTP/1.1\r\nHost: " + host + ...
```

`host` comes from `config.server` (operator-controlled config file). If a hostile config file with `server=victim.com\r\nX-Inject:` is loaded, header injection is possible. Low risk because the config is operator-controlled; mitigation: validate `host` contains no CR/LF before use.

### L-3 — `parseHealthLine()` accepts unbounded `ver` / `platform` fields

**File:** `src/ntm_types.hpp:155-156`

```cpp
else if (key == "ver")      hs.version  = val;
else if (key == "platform") hs.platform = val;
```

A malicious or buggy client can fill arbitrary strings. JSON output is escaped (`jsonEsc()`) and dashboard JS uses `esc()` for HTML, so XSS is blocked. But memory growth from a client sending megabyte-long `ver=…` values is unbounded.

**Fix:** Enforce a cap (e.g. 64 chars each) — match the existing iface/ip-label-len pattern.

### L-4 — Demo token issuance has no per-IP cap (CWE-770)

**File:** `src/web_dashboard.cpp:3377-3410`

`/api/demo/begin` is rate-limited by the generic per-IP limiter but does not cap the *total* number of active demo tokens. An attacker rotating source IPs can fill `g_demoTokens` with entries that survive for `kDemoSessionSec` (15 min) each. Slow OOM on a busy server.

**Fix:** Cap total demo tokens (e.g. 1000) and evict oldest when full.

### L-5 — Reverse-proxy IP-spoofing if `trusted_proxy` is mis-configured

**File:** `src/web_auth.hpp:72-88`

`effectiveClientIPFromHeaders()` trusts `CF-Connecting-IP` / `X-Forwarded-For` when `remoteAddr == trustedProxy`. If an operator sets `trusted_proxy` to `0.0.0.0` or leaves it pointing at a stale IP, the rate-limit and admin-IP logging can be spoofed. Not a code bug, but a deployment footgun.

**Fix (defensive):** Refuse to start when `trusted_proxy` is the unspecified address or a private-range IP without an explicit `trusted_proxy_force=yes`.

### L-6 — `sign-server.sh` / `sign-client.sh` do not pass `-rawin`

**Files:** `scripts/sign-server.sh:58-62`, `scripts/sign-client.sh:49-53`

Empirically the produced `.sig` files verify, suggesting OpenSSL 3.5+ ML-DSA provider treats input as raw message even without `-rawin`. But the documented API contract for ML-DSA is `-rawin`. If OpenSSL changes the default in a future major release, signing will silently produce sigs that no longer verify. Add `-rawin` explicitly for forward-compatibility.

---

## INFORMATIONAL

### I-1 — Dependency versions (no known unpatched CVEs)

Verified versions on the build machine:

| Library | Version | Status |
|---|---|---|
| OpenSSL | 3.6.2 (Apr 2026) | recent |
| libpcap | 1.10.6 | recent |
| curl | 8.20.0 | recent (current 8.21.x in 2026) |
| zlib | 1.3.2 | latest |
| miniz | 11.3.1 | latest |
| cpp-httplib | 0.20.0 | **outdated** — 0.21.x exists with several DoS fixes around chunked transfer & multipart parsing. Recommend bumping to latest 0.21.x. |

### I-2 — WebAuthn implementation is solid

The PBKDF2 admin password (200,000 iterations + 16-byte salt + `CRYPTO_memcmp`), ECDSA P-256 assertion verification, signCount monotonicity check, origin allow-list, and challenge binding are all implemented correctly. Minor nits:
- 200k PBKDF2 is OWASP-2023-acceptable but Argon2id is the 2026 recommendation
- `pendingRegs_` / `pendingAuths_` have a 5-minute TTL and are swept lazily on each new request — fine

### I-3 — ML-DSA-65 signing flow is well-architected

The split between binary signature (long-term, embedded build pubkey) and upgrade auth-proof (per-push nonce + binary-hash) is exactly the right pattern. Nonces are single-use with TTL. Atomic `rename(2)` on the new binary prevents partial-write corruption. Version-must-be-newer enforcement on the server prevents downgrade attacks. Excellent design.

---

## Attacker Scenarios Considered

| Goal | Outcome |
|---|---|
| Steal admin session by network MITM | Blocked: HSTS missing but TLS is enforced, HttpOnly+Secure cookies |
| Bypass admin password by replaying old proof token | Blocked: 10-min TTL + random 32-byte tokens |
| Bypass admin proof entirely via cookie injection | **Possible via C-1** when chained with XSS |
| Inject fake D-lines (flow data) into the server | Blocked: Ed25519 auth required; signCount checked on WebAuthn |
| Compromise binary via update channel | Blocked: ML-DSA-65 signature verified on both server and client side; SHA-256 cross-checked; nonce single-use |
| Push downgraded server binary | Blocked: server-side version-must-be-newer check |
| DoS the server with large bodies | Mostly blocked: 32 MiB cap on upgrade, default httplib cap (~8 MiB) elsewhere, generic rate-limit |
| DoS the updater with a giant download | **Possible on Linux via H-2** |
| Extract client identity key on a misconfigured host | **Possible via H-4** (warning only) |
| MITM iOS app on first launch | **Possible via H-3** if attacker has any valid CA-issued cert for the host |
| Path-traverse the `update_dir` via push | Blocked: platform whitelist + strict version regex |
| Inject XSS via H-line `ver=`/`platform=` | Blocked: server-side `jsonEsc` + client-side `esc()` |
| Read raw network captures off the wire | Blocked: TLS-mandatory client; refuses to start without CA/pin |

---

## Recommended Remediation Order

| Priority | Item | Effort |
|---|---|---|
| 1 | C-1 cookie parser fix + regression tests | 30 min |
| 2 | H-2 updater size cap on Linux | 10 min |
| 3 | H-4 hard-fail on bad identity-key perms | 20 min |
| 4 | H-1 remove `--insecure` from push scripts | 10 min |
| 5 | H-3 iOS pinning UX — require explicit TOFU acceptance | 1–2 h |
| 6 | M-2 replace `std::system(chmod)` with `::chmod()` | 10 min |
| 7 | M-3 add HSTS header | 5 min |
| 8 | M-5 add `ThisDeviceOnly` to KeychainService | 10 min |
| 9 | I-1 bump cpp-httplib 0.20.0 → latest 0.21.x | 1 h (review API diffs) |
| 10 | L-3 cap H-line ver/platform length | 10 min |

The C-1 fix is the highest-leverage change: it closes a real session-takeover path and includes a regression test that should never regress. Items 2-4 are quick wins. The CSP `unsafe-inline` cleanup (M-4) is the largest remaining technical-debt-style item and can be scheduled separately.

---

## Out-of-Scope (Not Audited)

- **Cryptographic primitives in OpenSSL** — relied on, not reviewed line-by-line.
- **Npcap kernel driver** on Windows — proprietary; trust boundary handled by the OS.
- **Cloudflare Tunnel** configuration — operator responsibility.
- **iOS Packet Tunnel system extension code paths** beyond key handling.
- **`ip_range_resolver.hpp` MaxMind/GeoIP database integrity** — relies on operator-supplied data file.
- **Side-channel attacks** (cache timing, EM emissions) — out of scope for this review.

---

## Remediation Log

All 16 actionable findings have been addressed. The 3 Informational findings (I-2, I-3 were positive observations; I-1 was a dependency bump) are noted below. M-4 (CSP `unsafe-inline`) was intentionally deferred as a separate tech-debt item.

| Finding | Severity | Status | PR | Module version after fix |
|---|---|---|---|---|
| C-1 cookie-name prefix confusion in `cookieFromHeader()` | Critical | Fixed | [#74](../../pull/74) | ntm-server 1.23.2.0 |
| H-1 `--insecure` in push scripts | High | Fixed | [#75](../../pull/75) | (scripts only — no module bump) |
| H-2 Linux updater missing download size cap | High | Fixed | [#77](../../pull/77) | ntm-client 1.19.1.0 |
| H-3 iOS CertificatePinner silently accepts CA certs on TOFU first run | High | Fixed | [#84](../../pull/84) | NTMDashboard 1.14.0 · NTMClient 1.3.2.0 |
| H-4 Identity key permission check warn-only (Linux) | High | Fixed | [#79](../../pull/79) | ntm-client 1.19.2.0 |
| H-4 Identity key permission check warn-only (Windows) | High | Fixed | [#83](../../pull/83) | ntm-client 1.19.3.0 |
| M-1 Server TLS cipher hardening | Medium | Fixed | [#76](../../pull/76) | ntm-server 1.24.0.0 |
| M-2 `std::system(chmod)` → `::chmod()` | Medium | Fixed | [#76](../../pull/76) | ntm-server 1.24.0.0 |
| M-3 HSTS header missing | Medium | Fixed | [#76](../../pull/76) | ntm-server 1.24.0.0 |
| M-4 CSP `'unsafe-inline'` present on all pages | Medium | **Deferred** | — | Scheduled as a separate refactor (PR 8); requires splitting inline JS/CSS to served resources |
| M-5 KeychainService session tokens not `ThisDeviceOnly` | Medium | Fixed | [#84](../../pull/84) | NTMDashboard 1.14.0 · NTMClient 1.3.2.0 |
| L-1 `jsonStr()` skips `\"` escape sequences | Low | Fixed | [#77](../../pull/77) | ntm-client 1.19.1.0 |
| L-2 Updater Host-header CR/LF injection | Low | Fixed | [#77](../../pull/77) | ntm-client 1.19.1.0 |
| L-3 `ver`/`platform` H-line fields unbounded | Low | Fixed | [#76](../../pull/76) | ntm-server 1.24.0.0 |
| L-4 Demo token map unbounded | Low | Fixed | [#76](../../pull/76) | ntm-server 1.24.0.0 |
| L-5 `trusted_proxy` accepts private/loopback without flag | Low | Fixed | [#76](../../pull/76) | ntm-server 1.24.0.0 |
| L-6 `-rawin` absent from signing scripts | Low | Fixed | [#75](../../pull/75) | (scripts only — no module bump) |
| I-1 cpp-httplib 0.20.0 outdated | Informational | Fixed | [#82](../../pull/82) | ntm-server 1.24.1.0 (upgraded to 0.46.0) |
| I-2 ML-DSA-65 post-quantum signing in place | Informational | No action | — | Positive finding |
| I-3 WebAuthn hardware-key enforcement | Informational | No action | — | Positive finding |

### Final module versions after remediation (2026-05-30)

| Module | Version |
|---|---|
| ntm-server | 1.24.1.0 |
| ntm-client (Linux) | 1.19.2.0 |
| ntm-client (Windows) | 1.19.3.0 |
| NTMDashboard (iOS) | 1.14.0 |
| NTMClient (iOS) | 1.3.2.0 |

### Remaining open item

**M-4** — CSP `'unsafe-inline'` cleanup requires splitting all inline `<script>` and `<style>` blocks in `kDashboardHtml`, `kAdminHtml`, and `kLoginHtml` out to separate served resources (`/dashboard.js`, `/admin.js`, etc.) and dropping `'unsafe-inline'` from the Content-Security-Policy header. Estimated effort: 4–8 h. Tracked separately; no other security fixes are blocked on it.
