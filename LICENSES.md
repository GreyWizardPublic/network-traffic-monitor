# Third-Party Licenses

This document enumerates every external library, runtime component, and data
source that the `NetworkTrafficMonitor` binaries (`ntm-server`, `ntm-client`)
depend on, together with each item's SPDX identifier, upstream home page, and
the binary it is linked into.

All listed dependencies are open-source and OSI-approved. None require shipping
their source alongside this project's binaries.  Most are dynamically linked
system libraries; **miniz** is vendored source compiled directly into the
Windows binary.

The project's own source code is governed by the top-level [`LICENSE`](LICENSE)
file (**MIT**); this document only covers third-party material.

---

## 1. Explicit linked third-party libraries

These are the libraries declared in `CMakeLists.txt` via `find_package` /
`find_library` and linked with `target_link_libraries`.

| # | Library | SPDX | Upstream | Used by | Purpose |
|---|---------|------|----------|---------|---------|
| 1 | **OpenSSL** (`libssl` + `libcrypto`) | `Apache-2.0` (OpenSSL ≥ 3.0) <br/> `OpenSSL` (legacy dual BSD-style, OpenSSL ≤ 1.1.1) | <https://www.openssl.org/> | `ntm-server`, `ntm-client` | TLS 1.2+ transport; Ed25519 keygen / sign / verify; constant-time memcmp; SHA-256 cert pinning. |
| 2 | **libcurl** | `curl` (an MIT-style permissive license; the upstream SPDX identifier is `curl`) | <https://curl.se/libcurl/> | `ntm-server` | HTTPS download of the iptoasn.com IP-to-ASN database, with certificate verification, redirect following, and timeouts. |
| 3 | **zlib** | `Zlib` | <https://zlib.net/> | `ntm-server` | Transparent gzip decompression of the local `ip2asn-combined.tsv.gz` cache file via `gzopen`/`gzgets`. |
| 4 | **libpcap** | `BSD-3-Clause` | <https://www.tcpdump.org/> | `ntm-client` | Packet capture on the client side (`pcap_create`, `pcap_dispatch`, BPF filters). |
| 5 | **POSIX threads (`pthread`)** via CMake `Threads::Threads` | Inherits from libc. <br/> glibc: `LGPL-2.1-or-later WITH GCC-exception-2.0`. <br/> musl: `MIT`. <br/> bionic (Android): `Apache-2.0`. | <https://www.gnu.org/software/libc/> (glibc) <br/> <https://musl.libc.org/> (musl) | Both binaries | Threading primitives used by `std::thread`, `std::mutex`, `std::condition_variable`. |
| 6 | **cpp-httplib** (`src/httplib.h`) | `MIT` | <https://github.com/yhirose/cpp-httplib> (v0.20.0) | `ntm-server` | Single-header C++11 HTTP/HTTPS server and client library. Used to serve the embedded HTTPS web dashboard (`GET /` and `GET /api/summary`). TLS is provided by OpenSSL (already linked). Header is vendored at `src/httplib.h`; no additional system libraries are required. |
| 7 | **miniz** (`src/third_party/miniz/`) | `Unlicense` (public domain) | <https://github.com/richgel999/miniz> (v3.1.1) | `ntm-client` (Windows) | Vendored zlib-compatible deflate/inflate implementation. Provides the same `z_stream`, `deflate()`, `inflate()`, `Z_SYNC_FLUSH`, etc. API as system zlib via preprocessor aliases. Compiled into the Windows cross-compiled binary so the Windows client can negotiate and use zlib compression on the data phase without requiring a MinGW zlib package. Not used on Linux (system `zlib` is linked instead). |

### Notes on OpenSSL

- OpenSSL 3.x switched to plain `Apache-2.0`. If you build against an older
  system OpenSSL (1.1.1 LTS), the historical OpenSSL/SSLeay dual license
  applies — also OSI-approved and unambiguously open source.
- We use only public OpenSSL APIs: `EVP_*` (Ed25519 + SHA-256), `SSL_*` /
  `SSL_CTX_*` (TLS), `X509_*` (certificate verification + pinning),
  `CRYPTO_memcmp` (constant-time compare), `RAND_bytes` (nonce generation),
  `ERR_*` (diagnostic strings).

### Notes on libcurl

- We use libcurl's "easy" interface only (no multi-handle, no threads).
- We pass `CURLOPT_NOSIGNAL=1L` so libcurl never installs signal handlers in
  our address space.
- HTTPS verification is enabled by default
  (`CURLOPT_SSL_VERIFYPEER=1L`, `CURLOPT_SSL_VERIFYHOST=2L`); the system CA
  store is used.

### Notes on libpcap

- Linked into `ntm-client` only. The `find_library(PCAP_LIBRARY pcap REQUIRED)`
  declaration is scoped to the `ntm-client` target in `CMakeLists.txt`.

---

## 2. Toolchain / system runtime components

These are provided by the C++ compiler and the host operating system, not by
this project. They are listed for completeness.

| # | Component | SPDX | Upstream | Notes |
|---|-----------|------|----------|-------|
| 6 | **libstdc++** (when built with GCC) | `GPL-3.0-or-later WITH GCC-exception-3.1` | <https://gcc.gnu.org/onlinedocs/libstdc++/manual/license.html> | The [GCC Runtime Library Exception](https://www.gnu.org/licenses/gcc-exception-3.1.html) explicitly permits distributing binaries that link `libstdc++` under **any** license, copyleft or not. |
| 7 | **libc++** (when built with Clang) | `Apache-2.0 WITH LLVM-exception` | <https://libcxx.llvm.org/> | The LLVM exception is the Apache-2.0 variant used throughout the LLVM project. |
| 8 | **C library** (`libc`) | glibc: `LGPL-2.1-or-later WITH GCC-exception-2.0` <br/> musl: `MIT` <br/> bionic: `Apache-2.0` | varies | Used implicitly for `<cstdio>`, `<cstring>`, sockets, file I/O, etc. |
| 9 | **Linux kernel UAPI headers** (`<arpa/inet.h>`, `<sys/socket.h>`, `<sys/stat.h>`, `<poll.h>`, `<syslog.h>`, `<fcntl.h>`, `<netinet/in.h>`, `<unistd.h>`, `<sys/time.h>`, `<sys/types.h>`) | `GPL-2.0-only WITH Linux-syscall-note` | <https://www.kernel.org/> | The `Linux-syscall-note` exception explicitly states that using the kernel's syscall interface from user-space code does not make that code GPL. |

---

## 3. External data sources (not libraries)

| # | Asset | SPDX | Upstream | Used by | Purpose |
|---|-------|------|----------|---------|---------|
| 10 | **iptoasn.com IP-to-ASN/country database** (`ip2asn-combined.tsv.gz`) | `CC0-1.0` (public domain dedication) | <https://iptoasn.com/> | `ntm-server` | Translates source/destination IPs to ISO country codes and ASN/organization labels. Downloaded by the in-process `IPDataUpdater` every `ip_db_update_interval_days` (default 7). |

The dataset is **data**, not code, so it is not "linked" in the build sense.
It is fetched at runtime from the URL configured in `ip_db_url` and cached at
`ip_db_path`. The CC0 dedication means it can be redistributed, modified, or
mirrored without restriction.

---

## 4. Build-only tools (not redistributed)

These are required to **build** the project but are not part of any shipped
binary. No licensing obligation flows to the binaries.

| Tool | SPDX | Upstream |
|------|------|----------|
| **CMake** ≥ 3.16 | `BSD-3-Clause` | <https://cmake.org/> |
| **GCC** or **Clang** | GCC: `GPL-3.0-or-later WITH GCC-exception-3.1` <br/> Clang/LLVM: `Apache-2.0 WITH LLVM-exception` | <https://gcc.gnu.org/> <br/> <https://llvm.org/> |
| `make` / `ninja` | `GPL-3.0-or-later` (GNU make) <br/> `Apache-2.0` (Ninja) | varies |

---

## 5. License compatibility summary

This project is **MIT-licensed** (permissive, no copyleft). All dependencies
are compatible:

| Other party's license | Compatible? | Source of compatibility |
|---|---|---|
| `Apache-2.0` | ✅ Yes | OpenSSL ≥ 3.0, libstdc++ via LLVM, bionic libc |
| `BSD-2-Clause` / `BSD-3-Clause` | ✅ Yes | libpcap; libcurl is permissive in the same family |
| `MIT` / curl license / `Zlib` | ✅ Yes | libcurl, zlib, musl libc, cpp-httplib |
| `Unlicense` (public domain) | ✅ Yes | miniz — public domain carries zero restrictions |
| `LGPL-2.1+` (linked dynamically) | ✅ Yes | glibc — `WITH GCC-exception-2.0` covers the static-link edge case |
| `GPL-2.0` (kernel headers only) | ✅ Yes | `Linux-syscall-note` exception; user-space use of UAPI headers does not affect the calling code's license |

**Nothing in the dependency tree is non-open-source, "source-available", or
otherwise restricted.** Binaries may be redistributed with the usual obligation
to honour each dynamic library's attribution requirements (typically: include a
copy of the upstream `COPYING` / `LICENSE` file, which distro packages already do).

---

## 6. Previously-used dependency (removed)

For historical context — this dependency was **removed** in favour of the
self-contained `IPRangeResolver` + iptoasn.com data:

| Library | SPDX | Reason for removal |
|---------|------|--------------------|
| `libmaxminddb` (MaxMind, Inc.) | `Apache-2.0` (library) | Replaced by an embedded loader that reads CC0-licensed iptoasn.com TSV data. The library itself was open source; the *data files* (`GeoLite2-Country.mmdb`, `GeoLite2-ASN.mmdb`) ship under a [bespoke MaxMind EULA](https://www.maxmind.com/en/geolite2/eula) requiring attribution and forbidding certain redistributions. The new pipeline avoids both the library dependency and the data EULA. |

---

## 7. How to verify on your own system

```bash
# Show every dynamic library the binaries depend on:
ldd build/ntm-server
ldd build/ntm-client

# Show the upstream package each lib belongs to (Arch / pacman):
ldd build/ntm-server | awk '/=>/ {print $3}' | sort -u \
  | xargs -I{} pacman -Qo {} 2>/dev/null

# On Debian / Ubuntu:
ldd build/ntm-server | awk '/=>/ {print $3}' | sort -u \
  | xargs -I{} dpkg -S {} 2>/dev/null
```

Every package the above commands print should appear in the table in
section 1 or section 2.

---

*Last updated: 2026-05-23. If a new dependency is added (or removed), please
update this file in the same commit so packagers and auditors have a single
source of truth.*
