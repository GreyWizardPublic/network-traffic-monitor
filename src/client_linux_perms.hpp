#pragma once

// client_linux_perms.hpp — Pure POSIX permission-check logic for the identity
// key file, extracted as inline so it can be unit-tested without pulling in
// pcap or other client_linux.cpp dependencies.

#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#include <cerrno>
#include <iostream>
#include <string>

namespace ntm::platform {

// Returns true if the identity key at `path` has safe permissions (owner-only
// read/write, correct uid). Returns false and emits a FATAL log if either
// check fails. Returns true if the file does not exist (the subsequent fopen
// call in the caller will report the missing file).
inline bool checkIdentityKeyPermissionsImpl(const std::string &path, bool isDaemon)
{
    struct stat st;
    if (::stat(path.c_str(), &st) != 0) return true; // missing file; caller handles it

    auto fatal = [&](const std::string &msg) {
        if (isDaemon) ::syslog(LOG_ERR, "%s", msg.c_str());
        else          std::cerr << msg << "\n";
    };

    bool ok = true;
    if ((st.st_mode & (S_IRWXG | S_IRWXO)) != 0)
    {
        fatal("ntm-client: FATAL: identity key '" + path +
              "' has group/world-readable permissions.\n"
              "ntm-client: Fix with:  chmod 600 '" + path + "'");
        ok = false;
    }
    if (st.st_uid != ::geteuid())
    {
        fatal("ntm-client: FATAL: identity key '" + path +
              "' is not owned by the current user.\n"
              "ntm-client: Fix with:  chown $(whoami) '" + path + "'");
        ok = false;
    }
    return ok;
}

} // namespace ntm::platform
