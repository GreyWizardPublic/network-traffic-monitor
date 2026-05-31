# Handoff: Sign in with Apple — NTMDashboard native integration

**From:** Arch Linux Agent  
**To:** Swift Agent  
**Related PR:** #107 (Phase A — server SIWA support)  
**Status:** Waiting for Swift Agent implementation

## What the server now supports (PR #107)

`POST /auth/apple/native` — accepts an iOS `identityToken` JWT directly:

```json
// Request body
{"identity_token": "<base64url id_token from ASAuthorizationAppleIDCredential.identityToken>"}

// Success (200)
{"ok": true, "token": "<bearer>", "role": "admin" | "user"}

// Failure (401)
{"error": "<reason>"}
```

The server validates the JWT against Apple's JWKS (`appleid.apple.com/auth/keys`).
The iOS bundle ID must be configured as `siwa_ios_bundle_id` in the server config.

## Required iOS changes

1. Enable Sign in with Apple capability (App ID + `project.yml`).
2. Implement `ASAuthorizationAppleIDProvider` flow — post `identityToken` to `POST /auth/apple/native`.
3. Replace admin password prompt with Sign in with Apple button (role=admin → admin panel).
4. Keep passkey login (`PasskeyService.swift`) unchanged for normal users.
5. Bump `MARKETING_VERSION` in `ios/project.yml` (MINOR).

See the PR body for full details.
