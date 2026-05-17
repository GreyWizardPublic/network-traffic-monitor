#include "client.hpp"

#include <iostream>
#include <stdexcept>
#include <string>
#include <syslog.h>

int main(int argc, char *argv[])
{
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
            std::cout << "Usage: ntm-client [--config FILE] [--daemon] [--server HOST] [--port N]\n"
                         "             [--identity PEM_PATH] [--ca CA_FILE] [--server-cert SERVER_PEM]\n"
                         "  All options can be set in the single config file (key=value); CLI overrides.\n";
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
        else if (arg == "--server-cert" && i + 1 < argc)
            tlsServerCertPath = argv[++i];
        else if (arg == "--verbose")
            opts.verbose = true;
        else if (arg == "--config" && i + 1 < argc)
            ++i;  // skip config path (already handled)
    }

    const char *id = identityPath.empty() ? "(none)" : identityPath.c_str();
    const char *ca = tlsCaPath.empty() ? "(none)" : tlsCaPath.c_str();
    const char *sc = tlsServerCertPath.empty() ? "(none)" : tlsServerCertPath.c_str();
    if (daemonMode)
        openlog("ntm-client", LOG_PID, LOG_DAEMON);

    if (loadedConfig)
    {
        const char *cid = opts.identityPath.empty() ? "(none)" : opts.identityPath.c_str();
        const char *cca = opts.tlsCaPath.empty() ? "(none)" : opts.tlsCaPath.c_str();
        const char *csc = opts.tlsServerCertPath.empty() ? "(none)" : opts.tlsServerCertPath.c_str();
        if (daemonMode)
        {
            syslog(LOG_INFO,
                   "loaded config from %s (server=%s, port=%u, identity=%s, ca=%s, server-cert=%s, send_buffer_bytes=%zu)",
                   loadedConfigPath.c_str(), opts.server.c_str(),
                   static_cast<unsigned>(opts.port), cid, cca, csc, opts.sendBufferBytes);
        }
        else
        {
            std::cerr << "ntm-client: loaded config from " << loadedConfigPath
                      << " (server=" << opts.server
                      << ", port=" << opts.port
                      << ", identity=" << cid
                      << ", ca=" << cca
                      << ", server-cert=" << csc
                      << ", send_buffer_bytes=" << opts.sendBufferBytes
                      << ")\n";
        }
    }
    else
    {
        if (daemonMode)
            syslog(LOG_INFO, "no config file loaded; using built-in defaults/CLI only");
        else
            std::cerr << "ntm-client: no config file loaded; using built-in defaults/CLI only\n";
    }

    if (daemonMode)
    {
        syslog(LOG_INFO,
               "effective settings after CLI override (server=%s, port=%u, identity=%s, ca=%s, server-cert=%s)",
               host.c_str(), static_cast<unsigned>(port), id, ca, sc);
    }
    else
    {
        std::cerr << "ntm-client: effective settings after CLI override (server=" << host
                  << ", port=" << port
                  << ", identity=" << id
                  << ", ca=" << ca
                  << ", server-cert=" << sc
                  << ")\n";
    }

    // Copy CLI overrides back into opts so runClient sees the merged final config.
    opts.server            = host;
    opts.port              = port;
    opts.identityPath      = identityPath;
    opts.tlsCaPath         = tlsCaPath;
    opts.tlsServerCertPath = tlsServerCertPath;
    return ntm::runClient(daemonMode, opts);
}

