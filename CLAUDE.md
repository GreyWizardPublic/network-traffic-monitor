# network-traffic-monitor

## Versioning

**Single source of truth:** `src/version.hpp` — defines `kNtmVersion`.  
Both `ntm-client` and `ntm-server` include this header; the client sends it
in every `H` (health) line as `ver=X.Y.Z`; the server displays it in the
dashboard and highlights any client whose version differs from the server's.

### Format: `MAJOR.MINOR.PATCH`

| Change type | Which part to bump | Example trigger |
|---|---|---|
| Breaking wire-protocol or auth change | MAJOR | new auth handshake, incompatible line format |
| New feature, backward-compatible | MINOR | new optional H field, new dashboard section |
| Bug fix, no protocol or feature change | PATCH | crash fix, race condition, display glitch |

### Rules

1. **Update `src/version.hpp` before the commit that introduces the change.**
   Never bump the version in a separate follow-up commit.
2. **Never skip levels.** Go 1.0.0 → 1.0.1 → 1.1.0, not 1.0.0 → 1.2.0.
3. **PATCH resets on MINOR bump; MINOR resets on MAJOR bump.**
   1.2.3 + minor feature → 1.3.0 (not 1.2.4 or 1.3.3).
4. **Bug-fix-only commits** (like race fixes or display glitches) are PATCH bumps.
5. Current version is in `src/version.hpp`. Always read it before deciding the
   next version number — do not rely on memory or git log alone.
