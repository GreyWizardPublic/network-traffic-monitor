#pragma once
// client_push.hpp — pure-logic helpers for client binary push validation.
// No I/O, no OpenSSL, no global state. Fully testable.

#include <string>

namespace ntm::client
{

struct ClientBinaryInfo
{
    std::string platform;   // e.g. "linux-amd64", "windows-amd64"
    std::string version;    // e.g. "1.15.0.0"
    std::string filename;   // original filename
    bool        isWindows{false};
    bool        valid{false};
};

// Parse an ntm-client binary filename into its components.
// Accepts:
//   ntm-client-linux-amd64-1.15.0.0          → platform=linux-amd64,  version=1.15.0.0
//   ntm-client-windows-amd64-1.15.0.0.exe    → platform=windows-amd64, version=1.15.0.0
// Returns ClientBinaryInfo with valid=false on any parse error.
inline ClientBinaryInfo parseClientBinaryFilename(const std::string &name)
{
    ClientBinaryInfo info;
    info.filename = name;

    const std::string prefix = "ntm-client-";
    if (name.size() <= prefix.size()) return info;
    if (name.substr(0, prefix.size()) != prefix) return info;

    std::string rest = name.substr(prefix.size());

    // Strip .exe suffix
    if (rest.size() > 4 && rest.substr(rest.size() - 4) == ".exe")
    {
        rest = rest.substr(0, rest.size() - 4);
        info.isWindows = true;
    }

    // rest = "<platform>-<version>" where platform is e.g. "linux-amd64"
    // Find the last '-' which separates platform from version
    auto lastHyp = rest.rfind('-');
    if (lastHyp == std::string::npos || lastHyp == 0) return info;

    info.platform = rest.substr(0, lastHyp);
    info.version  = rest.substr(lastHyp + 1);

    if (info.platform.empty() || info.version.empty()) return info;

    // Version must be all digits and dots, matching N.N.N or N.N.N.N
    unsigned dots = 0;
    bool lastWasDot = true; // start true to reject leading dot
    for (unsigned char c : info.version)
    {
        if (c == '.')      { if (lastWasDot) return info; ++dots; lastWasDot = true; }
        else if (c < '0' || c > '9') return info;
        else lastWasDot = false;
    }
    if (lastWasDot) return info; // trailing dot
    if (dots < 2 || dots > 3) return info; // must be 3-part or 4-part

    // Platform must contain at least one '-' (e.g. linux-amd64)
    if (info.platform.find('-') == std::string::npos) return info;

    info.valid = true;
    return info;
}

// Returns true for known ntm-client deployment platforms.
inline bool isKnownClientPlatform(const std::string &platform)
{
    return platform == "linux-amd64" || platform == "windows-amd64";
}

} // namespace ntm::client
