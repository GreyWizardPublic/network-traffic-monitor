#include "client.hpp"
#include "client_platform.hpp"
#include "client_signing.hpp"

#include <cstdio>
#include <iostream>
#include <stdexcept>
#include <string>

#ifndef _WIN32
#  include <syslog.h>
#endif

int main(int argc, char *argv[])
{
    // Step 0: ML-DSA-65 binary signature verification.
    // Runs before any other initialisation; refuses to start if the binary
    // is unsigned, tampered, or the .sig file is missing.
    {
        const std::string selfPath = ntm::signing::clientSelfPath();
        const std::string sigPath  = selfPath + ".sig";
        std::string sigErr;
        if (selfPath.empty())
        {
            std::fprintf(stderr,
                "ntm-client: FATAL — cannot resolve own binary path; "
                "cannot verify signature. Refusing to start.\n");
            return 1;
        }
        if (!ntm::signing::verifyClientSignature(selfPath, sigPath, sigErr))
        {
            std::fprintf(stderr,
                "ntm-client: FATAL — binary signature verification failed.\n"
                "  Error:     %s\n"
                "  Binary:    %s\n"
                "  Signature: %s\n"
                "  The binary may be tampered, unsigned, or the .sig file is missing.\n"
                "  Deploy both the binary and its matching .sig file.\n"
                "  Refusing to start.\n",
                sigErr.c_str(), selfPath.c_str(), sigPath.c_str());
            return 1;
        }
        std::fprintf(stderr, "ntm-client: binary signature verified OK (ML-DSA-65)\n");
    }

    // Defaults; then overridden by config file (if --config), then by CLI.
    ntm::ClientConfig opts;
    bool loadedConfig = false;
    std::string loadedConfigPath;

    for (int i = 1; i < argc; ++i)
    {
        std::string arg(argv[i]);
        if (arg == "--config" && i + 1 < argc)
        {
            std::string configPath = argv[++i];
            if (!ntm::loadClientConfig(configPath, opts))
            {
                std::cerr << "ntm-client: cannot open config file: " << configPath << "\n";
                return 1;
            }
            loadedConfig = true;
            loadedConfigPath = configPath;
            continue;
        }
        if (arg == "--help" || arg == "-h")
        {
            std::cout << "Usage: ntm-client [--config FILE] [--daemon] [--verbose]\n"
                         "                  [--server HOST] [--port N]\n"
                         "                  [--identity PEM_PATH] [--ca CA_FILE] [--server-cert SERVER_PEM]\n"
                         "                  [--reconnect-attempts N] [--reconnect-interval SECS]\n"
                         "                  [--no-compress] [--transport tcp|websocket]\n"
                         "  --daemon                  run as background daemon\n"
                         "  --verbose                 print detailed connection and authentication diagnostics\n"
                         "  --server HOST             server hostname or IP (default: 127.0.0.1)\n"
                         "  --port N                  server port (default: 5555)\n"
                         "  --identity PEM_PATH       Ed25519 private key for client authentication\n"
                         "  --ca CA_FILE              CA certificate bundle for TLS server verification\n"
                         "  --server-cert SERVER_PEM  pin server to a specific certificate (SHA-256 check)\n"
                         "  --reconnect-attempts N    max consecutive reconnect failures before exit (default 10)\n"
                         "  --reconnect-interval SECS seconds between reconnect attempts (default 60)\n"
                         "  --no-compress             disable zlib compression on the data phase\n"
                         "  --transport MODE          connection transport: tcp (default) or websocket\n"
                         "                            Use websocket to traverse Cloudflare tunnels\n"
                         "  All options can also be set in a config file (key=value); CLI overrides config.\n";
            return 0;
        }
    }

    bool daemonMode = false;
    std::string host = opts.server;
    std::uint16_t port = opts.port;
    std::string identityPath = opts.identityPath;
    std::string tlsCaPath = opts.tlsCaPath;
    std::string tlsServerCertPath = opts.tlsServerCertPath;

    for (int i = 1; i < argc; ++i)
    {
        std::string arg(argv[i]);
        if (arg == "--daemon")
            daemonMode = true;
        else if (arg == "--server" && i + 1 < argc)
            host = argv[++i];
        else if (arg == "--port" && i + 1 < argc)
        {
            try
            {
                unsigned long p = std::stoul(argv[++i]);
                if (p == 0 || p > 65535)
                {
                    std::cerr << "ntm-client: port must be 1-65535\n";
                    return 1;
                }
                port = static_cast<std::uint16_t>(p);
            }
            catch (const std::exception &)
            {
                std::cerr << "ntm-client: invalid port number\n";
                return 1;
            }
        }
        else if (arg == "--identity" && i + 1 < argc)
            identityPath = argv[++i];
        else if (arg == "--ca" && i + 1 < argc)
            tlsCaPath = argv[++i];
        else if (arg == "--server-cert" && i + 1 < argc)
            tlsServerCertPath = argv[++i];
        else if (arg == "--verbose")
            opts.verbose = true;
        else if (arg == "--no-compress")
            opts.useCompression = false;
        else if (arg == "--transport" && i + 1 < argc)
        {
            std::string mode(argv[++i]);
            if (mode == "websocket" || mode == "ws")
                opts.transport = ntm::TransportMode::WebSocket;
            else if (mode == "tcp")
                opts.transport = ntm::TransportMode::TcpTls;
            else
            {
                std::cerr << "ntm-client: unknown transport '" << mode
                          << "' — expected 'tcp' or 'websocket'\n";
                return 1;
            }
        }
        else if (arg == "--reconnect-attempts" && i + 1 < argc)
        {
            try
            {
                unsigned long n = std::stoul(argv[++i]);
                if (n < 1 || n > 1000)
                {
                    std::cerr << "ntm-client: reconnect-attempts must be 1-1000\n";
                    return 1;
                }
                opts.reconnectMaxAttempts = static_cast<unsigned>(n);
            }
            catch (const std::exception &)
            {
                std::cerr << "ntm-client: invalid reconnect-attempts value\n";
                return 1;
            }
        }
        else if (arg == "--reconnect-interval" && i + 1 < argc)
        {
            try
            {
                unsigned long n = std::stoul(argv[++i]);
                if (n < 1 || n > 3600)
                {
                    std::cerr << "ntm-client: reconnect-interval must be 1-3600\n";
                    return 1;
                }
                opts.reconnectIntervalSec = static_cast<unsigned>(n);
            }
            catch (const std::exception &)
            {
                std::cerr << "ntm-client: invalid reconnect-interval value\n";
                return 1;
            }
        }
        else if (arg == "--config" && i + 1 < argc)
            ++i;  // skip config path (already handled)
    }

    const char *id = identityPath.empty() ? "(none)" : identityPath.c_str();
    const char *ca = tlsCaPath.empty() ? "(none)" : tlsCaPath.c_str();
    const char *sc = tlsServerCertPath.empty() ? "(none)" : tlsServerCertPath.c_str();
#ifndef _WIN32
    if (daemonMode)
        openlog("ntm-client", LOG_PID, LOG_DAEMON);
#endif

    if (loadedConfig)
    {
        const char *cid = opts.identityPath.empty() ? "(none)" : opts.identityPath.c_str();
        const char *cca = opts.tlsCaPath.empty() ? "(none)" : opts.tlsCaPath.c_str();
        const char *csc = opts.tlsServerCertPath.empty() ? "(none)" : opts.tlsServerCertPath.c_str();
        char buf[512];
        std::snprintf(buf, sizeof(buf),
            "ntm-client: loaded config from %s (server=%s, port=%u, identity=%s, ca=%s, server-cert=%s, send_buffer_bytes=%zu)",
            loadedConfigPath.c_str(), opts.server.c_str(),
            static_cast<unsigned>(opts.port), cid, cca, csc, opts.sendBufferBytes);
        ntm::platform::ntmLog(ntm::platform::LogLevel::Info, daemonMode, buf);
    }
    else
    {
        ntm::platform::ntmLog(ntm::platform::LogLevel::Info, daemonMode,
            "ntm-client: no config file loaded; using built-in defaults/CLI only");
    }

    {
        char buf[512];
        std::snprintf(buf, sizeof(buf),
            "ntm-client: effective settings (server=%s, port=%u, identity=%s, ca=%s, server-cert=%s,"
            " reconnect_max=%u, reconnect_interval_sec=%u)",
            host.c_str(), static_cast<unsigned>(port), id, ca, sc,
            opts.reconnectMaxAttempts, opts.reconnectIntervalSec);
        ntm::platform::ntmLog(ntm::platform::LogLevel::Info, daemonMode, buf);
    }

    // Copy CLI overrides back into opts so runClient sees the merged final config.
    opts.server            = host;
    opts.port              = port;
    opts.identityPath      = identityPath;
    opts.tlsCaPath         = tlsCaPath;
    opts.tlsServerCertPath = tlsServerCertPath;
    return ntm::runClient(daemonMode, opts, argv);
}

