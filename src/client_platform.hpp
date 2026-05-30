#pragma once

// Platform abstraction layer for ntm-client.
// Linux impl → client_linux.cpp
// Windows impl → client_windows.cpp
//
// All symbols live in ntm::platform::.

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <unordered_set>

// Forward-declare SSL so this header stays free of OpenSSL includes.
typedef struct ssl_st SSL;

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <unistd.h>
#endif

namespace ntm::platform
{

// ---------------------------------------------------------------------------
// Socket handle type
// ---------------------------------------------------------------------------

#ifdef _WIN32
using SockFd = SOCKET;
inline constexpr SockFd kInvalidSock = INVALID_SOCKET;
inline bool sockValid(SockFd fd) { return fd != INVALID_SOCKET; }
inline void closeSocket(SockFd fd) { if (fd != INVALID_SOCKET) ::closesocket(fd); }
#else
using SockFd = int;
inline constexpr SockFd kInvalidSock = -1;
inline bool sockValid(SockFd fd) { return fd >= 0; }
inline void closeSocket(SockFd fd) { if (fd >= 0) ::close(fd); }
#endif

// ---------------------------------------------------------------------------
// I/O helpers — implemented per-platform to use the right send/recv calls
// ---------------------------------------------------------------------------

// Read/write exactly n bytes via SSL (if non-null) or raw socket.
bool readExact (SSL *ssl, SockFd fd, void       *buf, std::size_t n);
bool writeExact(SSL *ssl, SockFd fd, const void *buf, std::size_t n);

// ---------------------------------------------------------------------------
// Network connection
// ---------------------------------------------------------------------------

// Create a connected TCP socket to host:port. Returns kInvalidSock on failure.
// Sets errOut to a short reason string on failure.
SockFd connectToServer(const std::string &host, std::uint16_t port,
                       std::string &errOut);

// Set the OS send-buffer size on a socket (best-effort, not fatal on failure).
void setSendBufferSize(SockFd fd, int bytes);

// ---------------------------------------------------------------------------
// LAN address enumeration
// ---------------------------------------------------------------------------

// Return all LAN IPv4/IPv6 address strings from all interfaces.
// Linux: getifaddrs.  Windows: GetAdaptersAddresses.
std::unordered_set<std::string> collectLanAddresses();

// ---------------------------------------------------------------------------
// External IP resolver (plain HTTP only)
// ---------------------------------------------------------------------------

// Fetch external/WAN IP from url. Returns validated IP string or "" on failure.
// Linux: POSIX sockets.  Windows: Winsock2.
std::string queryExternalIP(const std::string &url, unsigned timeoutMs);

// ---------------------------------------------------------------------------
// Pcap loopback detection
// ---------------------------------------------------------------------------

// Forward-declare pcap_if_t without pulling in pcap.h here.
struct pcap_if;
bool isLoopbackIface(const pcap_if *dev);

// ---------------------------------------------------------------------------
// Key-file permission check
// ---------------------------------------------------------------------------

// Verify the private identity key has safe permissions and is owner-only.
// Returns true if the check passes or the file does not exist (caller handles
// missing file). Returns false and logs a FATAL message if permissions or
// ownership are unsafe — caller must abort startup.
// Linux: stat() + mode bits.  Windows: ACL check (see client_windows.cpp).
bool checkIdentityFilePermissions(const std::string &path,
                                  bool isDaemon, bool verbose);

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

enum class LogLevel { Info, Warn, Err };

// Write msg to syslog (daemon mode) or stderr (foreground) AND to the
// global file logger (ntm::globalFileLogger()) if it has been initialised.
// Linux: syslog().  Windows: stderr always (no syslog on Windows).
void ntmLog(LogLevel level, bool isDaemon, const std::string &msg);

// Return the default directory for log files.
// Daemon / service: a system log directory (e.g. /var/log/ntm-client).
// User foreground:  a user-state directory (e.g. ~/.local/state/ntm-client/logs).
// Returns an empty string if no suitable directory can be determined.
std::string defaultLogDir(bool isDaemon);

// ---------------------------------------------------------------------------
// Signal / shutdown handling
// ---------------------------------------------------------------------------

// Install SIGINT/SIGTERM (Linux) or SetConsoleCtrlHandler (Windows) to set
// *running = false when the user requests shutdown.
void setupSignals(std::atomic<bool> &running);

// Signal the main loop to stop (sets the same flag as setupSignals).
// Called by the Windows SCM service control handler on SERVICE_CONTROL_STOP;
// no-op on Linux (signals go directly to the signal handler).
void requestStop();

// ---------------------------------------------------------------------------
// Daemon / background process
// ---------------------------------------------------------------------------

// Fork-based daemonize on Linux.  No-op on Windows (--daemon not supported).
void daemonize(bool isDaemon);

// ---------------------------------------------------------------------------
// Platform init / cleanup (WSAStartup / WSACleanup on Windows; no-op on Linux)
// ---------------------------------------------------------------------------

void initPlatform();
void cleanupPlatform();

// ---------------------------------------------------------------------------
// NetworkMonitor — watches for address/link changes and sets a changed flag
// ---------------------------------------------------------------------------

class NetworkMonitor
{
public:
    NetworkMonitor();
    ~NetworkMonitor();

    void start();
    void stop();

    // Returns true (and clears the flag) if a change was detected since last call.
    bool checkAndClear();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ntm::platform
