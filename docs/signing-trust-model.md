# Binary Signing Trust Model

Design decision record for how NTM establishes the authenticity of `ntm-server` and
`ntm-client` binaries, and how signing keys are rotated **without recompiling or
reinstalling deployed binaries**.

- **Status:** Implemented — ntm-server 3.0.0.0 / ntm-client 2.0.0.0 (#133).
- **Date:** 2026-09-23; **amended 2026-09-25** by three maintainer rulings recorded on
  #133 (delegation bundled in each `.sig`; expiry gates new artifacts only; strict text
  format instead of JSON). §4, §5, §6, §9 and §11 reflect the amendment.
- **Decided by:** project owner, with review from the Swift Agent.
- **Supersedes:** the single compiled-in build key described in
  `docs/project-rules.md §9` (Binary signing).

## Table of Contents

1. [Why this changed](#1-why-this-changed)
2. [Decision](#2-decision)
3. [Trust anchor: the root keys](#3-trust-anchor-the-root-keys)
4. [The delegation document](#4-the-delegation-document)
5. [Verification algorithm](#5-verification-algorithm)
6. [Build keys: one per agent](#6-build-keys-one-per-agent)
7. [Rotation procedures](#7-rotation-procedures)
8. [Root seed handling rules](#8-root-seed-handling-rules)
9. [One-time migration](#9-one-time-migration)
10. [Alternatives considered and rejected](#10-alternatives-considered-and-rejected)
11. [Open items](#11-open-items)

---

## 1. Why this changed

The original design compiled a single ML-DSA-65 public key into every binary
(`src/build_pubkey.hpp`, `kBuildPublicKeyDer`, 1974 bytes DER). That one key served
**four** distinct purposes:

| Purpose | Site |
|---|---|
| `ntm-server` verifies its own binary at startup | `src/server_core.cpp:3247` |
| `ntm-client` verifies its own binary at startup | `src/client_main.cpp:35` |
| The auto-updater verifies a downloaded client | `src/updater.cpp:822` |
| `update_dir` housekeeping keeps/deletes binaries | `src/web_dashboard.cpp:220` |
| The two push endpoints authenticate the build machine | `web_dashboard.cpp:4298`, `:4496` |

Note the last row in particular: `/admin/upgrade/push` and `/admin/client/push` are
exempt from WebAuthn (`src/web_auth.hpp:110-128`), so the build key is their **sole**
authentication.

Because the trust anchor and the day-to-day signing key were the same object, there was
no way to change the key without recompiling and redeploying every binary in the fleet.
There was also no key id in the `.sig`, no multi-key set, no expiry and no revocation.

In September 2026 the private key (`~/.ntm/privatebuildkey.secret`) was lost when the
Linux agent's machine moved from Arch to Fedora. That forced exactly the fleet-wide
manual redeploy this design exists to prevent from recurring.

## 2. Decision

**Adopt a two-tier trust model.**

```
root keys (3, offline, threshold 2)
    │  sign
    ▼
delegation.txt   ──  names the current build key(s), versioned, expiring
    │  authorises
    ▼
build key (one per agent, in that agent's OS keyring)
    │  signs
    ▼
ntm-server / ntm-client binaries  (.sig = NTMSIG 2 bundle, §4)
```

Only the **root public keys** are compiled into binaries. Rotating a build key means
signing a new delegation and shipping it — **no recompile, no reinstall**.

This is the pattern behind TUF, Debian/Fedora/Arch keyring packages, Android signing
lineage and Sigstore's own root. We adopt the two rules that matter rather than a TUF
implementation, because ML-DSA support across TUF tooling is still draft-stage.

### What stays the same

- ML-DSA-65 (FIPS 204) everywhere. Post-quantum is a requirement.
- Signatures remain **raw ML-DSA over whole file bytes** — `openssl pkeyutl -sign -rawin`
  on the signing side, `EVP_DigestVerify` with a NULL digest on the verifying side.
  No pre-hashing, no CMS, no X.509 in the trust path.
- The `<binary>.sig` file name (its content is now an NTMSIG 2 bundle, §4) and the "always deploy the `.sig` with the binary"
  rule.
- `verifySignatureWithKey()` / `verifySignatureWithKeyBytes()` in `src/server_signing.hpp`
  are reused **unchanged** as the innermost primitive; they already take the public key
  as a parameter.

## 3. Trust anchor: the root keys

**Three ML-DSA-65 root keys, threshold 2.** All three public keys are compiled in
(5,922 bytes of `.rodata` — negligible). Any two may sign a delegation.

| Key | Role | Location |
|---|---|---|
| `r1` | Primary. Signs delegations. | macOS Keychain (iCloud-backed), seed form |
| `r2` | Co-signer. Signs delegations with `r1`. | Separate physical medium, offline |
| `r3` | **Stand-by.** Never used in normal operation. | Third location, offline, never on a networked machine |

`r3` is the stand-by key of RFC 6781 §4.2.4. NIST SP 800-57 Pt 1 Rev 5 App. B.3.1.1
recommends pre-distributing a second signature key **instead of** backing up the primary;
we do both, because a code-signing root is the documented exception where backup is
warranted (Table 7).

Three keys at threshold 2 means **losing any one key is a routine delegation update, not
an incident**. This is the structural fix for what happened in September 2026. TUF's own
guidance independently recommends the same shape ("at least 3 offline keys, threshold 2").

### Seeds, not PEM files

An ML-DSA private key is fully determined by a **32-byte seed**. Verified on
OpenSSL 3.5.8: regenerating from `-pkeyopt hexseed:<64 hex chars>` reproduces a
byte-identical public key.

So the durable secret for each root is **64 hex characters**, not a 5,604-byte PEM. That
is small enough to store in a keychain item, write on an index card, or stamp into steel.

> **Store the seed. Never store or transport the PEM.**

Confirm `ml-dsa.retain_seed` is not disabled in the OpenSSL provider config, or the seed
is discarded after generation.

## 4. The delegation document

**Strict line-based text**, not JSON (maintainer ruling 3: no JSON parser in the C++
trust path). ASCII, `\n` line endings, final newline, no empty lines. The roots sign
these exact bytes. `scripts/trust/make-delegation.sh` writes it; `src/trust.hpp`
parses it and rejects any deviation.

```
ntm-delegation 1
version: 1
expires: 2027-04-23T00:00:00Z
key: linux-build linux-amd64 ML-DSA-65 <base64 SPKI DER, unwrapped>
key: windows-build windows-amd64 ML-DSA-65 <base64 SPKI DER, unwrapped>
```

`version` is decimal without leading zeros; `expires` is exactly `YYYY-MM-DDTHH:MM:SSZ`;
1–8 `key:` lines with unique ids (`[a-z0-9-]{1,32}`) and a known platform.

**Distribution: bundled in every `.sig`** (maintainer ruling 1). There is no separate
`delegation.json`, no new endpoint and no API version change. Each `<binary>.sig` is a
self-contained **NTMSIG 2** bundle (~20 KB):

```
NTMSIG 2
delegation: <base64 of the delegation document>
root-sig: r1 <base64 ML-DSA-65 signature over the document>      (1..3, ids ascending)
root-sig: r2 <base64 ...>
key-id: linux-build
signature: <base64 raw ML-DSA-65 signature over the whole binary>
```

The committed files are `signing/delegation.txt` plus one `signing/delegation.txt.rN.sig`
per root that signed it. A new delegation reaches the fleet with the next binary signed
under it.

**Rules enforced by every verifier:**

- At least `threshold` (2) valid signatures from **distinct** compiled-in root keys.
  Unknown root ids do not count; repeated ids are a parse error.
- A build key is only valid for the `platform` it is scoped to. A compromised Windows
  build machine cannot sign a Linux server binary.
- **Expiry** and **rollback** apply when accepting a *new* artifact — see §5.

## 5. Verification algorithm

`src/trust.hpp`, pure logic, no new dependency. `verifyBundleWithRoots()`:

1. Parse the NTMSIG 2 bundle (size-capped, strict grammar; a legacy raw `.sig` fails
   with a clear message).
2. Count valid root signatures over the embedded document against the **compiled-in
   roots** (`src/trust_roots.hpp`). Reject below threshold.
3. Parse the document.
4. If the policy checks expiry: reject when `now >= expires`.
5. Reject if `version` is below the policy's rollback floor.
6. Select `key-id`; reject if absent or scoped to another platform.
7. Verify the binary with `verifySignatureWithKeyBytes(binary, sig, build_key)` —
   **existing primitive, unchanged**.

**Policy (maintainer ruling 2).**

| Path | Expiry | Rollback floor |
|---|---|---|
| Startup self-check (server, client) | **not checked** | none |
| Updater download, server/client push, `update_dir` scan | checked | delegation version of the running binary's **own** `.sig` |

The floor needs no extra state: the startup self-check records its own delegation
version, and nothing older is accepted afterwards. A binary already installed keeps
running past its delegation's expiry (no bricking of unattended hosts or hosts with a
bad clock); it simply cannot *accept* anything signed under an expired delegation.

**Push authentication uses the same resolution.** The pushed `.sig` is verified first;
the auth proof must then verify under the build key *that bundle's delegation* names for
the platform. Rotating a build key therefore rotates push auth for free. The auth
message format (`nonce || SHA3-256(binary)`, `src/server_upgrade.hpp`) is unchanged.
Consequence: a Windows client push is run on the Windows build host.

**Failure modes are unchanged:** a verification failure still means the binary refuses to
start, the update is discarded, or the push returns 403. A missing or unverifiable
delegation is a hard failure — never fall back to trusting an unsigned artifact.

## 6. Build keys: one per agent

Each agent generates its **own** build key and keeps it in its own OS keyring. The private
key never crosses a machine boundary.

This replaces the current arrangement, in which the same private key must be copied to the
Windows machine to sign Windows clients.

| Agent | Key id | Store (as implemented) |
|---|---|---|
| Fedora Linux Agent | `linux-build` | `systemd-creds encrypt --user --name=ntm-linux-build` → `~/.config/ntm/linux-build.cred` (host- and user-bound; the agent host runs no gnome-keyring) |
| Windows Agent | `windows-build` | DPAPI CurrentUser → `%USERPROFILE%\.ntm\windows-build.dpapi`, released by `scripts/trust/windows-build-seed.ps1` |
| Swift Agent (macOS) | — | none needed (iOS exception below) |

`scripts/trust/lib.sh` fetches the seed, refuses to sign if the derived public key does
not match the delegation, signs with the private key only ever in a pipe
(`openssl genpkey … | openssl pkeyutl -inkey /dev/stdin`), and self-verifies.

**Rules for every agent:**

- Generate the build key locally. Never transmit the private key or its seed.
- Store the **seed** in the keyring; materialise the key only for the duration of a build.
- Never write the private key to disk. Pipe it from the keyring in memory.
- Rotate on a fixed cadence of **180 days** (see §7), plus immediately on any suspected
  exposure or when the machine is rebuilt.
- Publish only the SPKI public key to the root holder for inclusion in a delegation.

**Exception: iOS.** NTMDashboard and NTMClient are signed through Apple's App Store chain
(`docs/project-rules.md §7`). That process is unchanged and out of scope here. The Swift
Agent only needs a build key if it ever signs a non-App-Store artifact.

## 7. Rotation procedures

### Rotating a build key (routine, every 180 days)

1. The agent generates a new key, stores the seed in its keyring, exports the SPKI.
2. The agent sends the **public** SPKI to the root holder (a PR or issue is fine — it is
   not secret).
3. The root holder signs `signing/delegation.txt` version N+1 with two root keys (`scripts/trust/root-sign.sh`).
4. The new delegation ships inside the `.sig` of the next binaries signed under it (§4).
5. **Nothing is recompiled.**

### Rotating a root key (rare)

Replace one root key: sign delegation N+1 with the two surviving roots, and issue an
updated compiled-in key set in the *next* release. Deployed binaries continue to work
because 2 of their 3 compiled-in roots remain valid.

Replacing **two or more** roots at once requires a new binary release, because the
compiled-in set is what anchors everything. Avoid this by never storing two roots in the
same place.

### Cadence summary

| Key | Lifetime | Where rotation is felt |
|---|---|---|
| Build keys | 180 days | Delegation update only |
| Delegation `expires` | 210 days | Grace window over the build key |
| Root keys | 10 years | New binary release |

180 days is a deliberate middle: every build-key rotation costs a root signature, which
means an offline ceremony on the machine holding `r1`. Shorten it only if that ceremony is
cheap enough to run quarterly.

## 8. Root seed handling rules

These rules are binding on all agents.

1. **The root seed is never written to disk, never committed, never pasted into a chat,
   an agent transcript, a commit message or an issue.** `rm -P` does not reliably erase on
   APFS/SSD or on any copy-on-write filesystem — the only safe wipe is never creating the
   file.
2. Retrieve it by piping from the keyring directly into the consuming command. Never
   materialise an intermediate file.
3. **Agents must not run commands that decrypt the seed into their tool output.** The
   project owner runs root ceremonies in their own terminal. An agent may prepare the
   commands and verify the *public* results.
4. To identify a key without exposing it, fingerprint the **public** half:
   `openssl pkey -pubout -outform DER | openssl dgst -sha256`. Never digest private
   material.
5. Back up `r1`'s seed as a 2-of-3 split using **SLIP-39** or `gfshare` — not raw Shamir,
   which silently reconstructs garbage from a corrupted share, and never by splitting the
   bytes (SP 800-57 §8.1.5.2.1: "A suitable combination function is not provided by simple
   concatenation"). Three physical locations. **Test recovery from two shares before
   deleting anything.**
6. Set a calendar reminder before any `expires` date. Silent expiry, not compromise, is
   the common failure mode (see Arch, Kali).

## 9. One-time migration

**The fleet-wide manual redeploy cannot be avoided.** Every deployed binary trusts exactly
one now-unavailable key, and no signature can be produced that it will accept. That is the
security property working as designed. Kali Linux hit this exact situation in April 2025
and every user had to fetch a new keyring by hand.

Done once, tracked on #133:

1. ✅ Owner generated `r1`, `r2`, `r3`; seeds stored per §3/§8; r1 SLIP-39 recovery and
   r2/r3 cards verified. Public keys in `signing/roots/`.
2. ✅ Each agent generated its build key (§6) and published its SPKI (`signing/keys/`).
3. Owner signs `signing/delegation.txt` v1 with r1 + r2 (`scripts/trust/root-sign.sh`).
4. ✅ §5 implemented; `src/build_pubkey.hpp` replaced by `src/trust_roots.hpp`;
   ntm-server 3.0.0.0, ntm-client 2.0.0.0.
5. Build and sign server + clients.
6. Install the new server by hand — `push-upgrade.sh` cannot work, because the live server
   still trusts the old key.
7. Reinstall each client by hand, binary **and** `.sig` together.
8. Publish the root fingerprints over more than one channel.

After this, both build-key and single-root-key rotation are routine.

## 10. Alternatives considered and rejected

| Alternative | Why rejected |
|---|---|
| **Derive the root from the App Store Connect `.p8`** | Fuses two trust domains: an ASC key leak would become a binary-signing compromise, turning a recoverable credential incident into a fleet-wide redeploy. Apple can force rotation of that key, and it is scoped for App Store Connect auth, not signing. Independently objected to by the Swift Agent. |
| **Bare trust-store file, no compiled-in anchor** | Reduces the entire authenticity guarantee to filesystem permissions. |
| **TOFU / key pinning** | This is HPKP, removed from browsers precisely because a lost pinned key had no recovery path — our exact failure. |
| **X.509 certificate chains** | Works with ML-DSA-65 on OpenSSL 3.5.8, but gives no thresholds and no rollback protection, costs ~2.7× the bytes, and puts ASN.1 parsing in the trust path. |
| **Adopt a TUF implementation** | No usable C/C++ implementation; ML-DSA support across TUF tooling is draft-stage. We take the two design rules instead. |
| **Sigstore / keyless** | ML-DSA is explicitly "not operational within Sigstore"; self-hosting means running Fulcio, Rekor, a CT log, TUF and a TSA. |
| **Android-style key-signs-successor lineage** | Requires the old private key, which is gone, and cannot be established retroactively. |
| **RFC 3161 timestamping** | Blocked: CMS signing with ML-DSA fails on OpenSSL 3.5.8. The upstream fix is merged but unreleased. `version` + `expires` cover most of the need. |
| **HSM / cloud KMS** | No consumer token supports ML-DSA (YubiKey PIV does not, as of fw 5.8). AWS KMS is the only FIPS-grade option and conflicts with keeping the root offline. Revisit for build keys later. |

## 11. Open items

- **Dual anchor (Sparkle's rule).** Sparkle lets you rotate either the Apple code-signing
  certificate or the EdDSA key, but not both, so losing one is recoverable. We should
  consider a second independent anchor for the Windows and iOS clients, which already have
  platform-rooted identities. It only helps if set up *before* a loss.
- **Per-artifact revocation list.** A root-signed list of binary SHA-256 hashes, checked
  before install — a kill switch for one bad build without revoking a key. With bundling
  it would ride in the NTMSIG envelope.
- **Expiry reminder.** Delegation v1 expires 2027-04-23. Re-sign (v2) before then or no
  new artifact will be accepted anywhere (§5). Build keys are due for rotation at 180 days.

*Resolved by the 2026-09-25 amendment:* the API-version item (no endpoint change with
bundling); the `manage-build-keys.sh` 3.3 gate (script removed; OpenSSL ≥ 3.5 is the
floor everywhere); the Windows OpenSSL floor (project-rules §9 lists 3.6.4 on A8).
