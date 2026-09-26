# RPM packaging — ntm-server, ntm-client

Repackages the ML-DSA-signed release binaries from `build-linux/` into two
Fedora RPMs, published to **https://dl.code1one.com/rpm/ntm/** (separate from
Secure Vault's tree; same host and Code1One GPG key). dnf owns updates on RPM
hosts; the built-in self-update is for Windows and non-RPM installs.

| Step | Who | Command |
|---|---|---|
| Build + sign binaries | Linux Agent | `cmake --build build-linux` |
| Build RPMs (payload byte-identical gate) | Linux Agent | `packaging/rpm/build-rpms.sh` |
| Consumer rehearsal (throwaway key, clean container) | Linux Agent | `packaging/rpm/verify-install.sh --local [--release 45]` |
| GPG-sign + publish | **maintainer** (key passphrase) | `packaging/rpm/publish.sh` |
| Consumer gate on the live repo | Linux Agent | `packaging/rpm/verify-install.sh --public` |

Install on a Fedora host:

```bash
sudo curl -fsSL -o /etc/yum.repos.d/ntm.repo https://dl.code1one.com/ntm.repo
sudo dnf install ntm-server      # and/or ntm-client
# configure /etc/ntm-server/ (see /usr/share/doc/ntm-server/), then:
sudo systemctl enable --now ntm-server
```

⚠️ Never let rpmbuild strip or post-process the binaries: the `.sig` covers the
exact bytes and a modified binary refuses to start. The specs disable all brp
scripts, and `build-rpms.sh` re-extracts each payload and compares it with `cmp`.
