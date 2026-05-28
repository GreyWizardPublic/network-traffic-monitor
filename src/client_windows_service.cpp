#ifndef _WIN32
#error "client_windows_service.cpp is only for Windows builds"
#endif

// Windows SCM (Service Control Manager) integration for ntm-client.
// Dispatch from client_main.cpp when --service is passed.

#include "client_windows_service.hpp"
#include "client.hpp"
#include "client_platform.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <atomic>
#include <cstdio>
#include <string>
#include <vector>

namespace ntm::service
{

// ---------------------------------------------------------------------------
// Module-level state shared between the service main and the control handler
// ---------------------------------------------------------------------------

static SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
static std::atomic<bool>     g_stopRequested{false};
static ClientConfig          g_config;
static std::vector<char *>   g_argv;

// ---------------------------------------------------------------------------
// Service status helpers
// ---------------------------------------------------------------------------

static void reportStatus(DWORD currentState, DWORD waitHint = 0)
{
    static DWORD checkPoint = 1;
    SERVICE_STATUS ss{};
    ss.dwServiceType             = SERVICE_WIN32_OWN_PROCESS;
    ss.dwCurrentState            = currentState;
    ss.dwControlsAccepted        = (currentState == SERVICE_RUNNING)
                                   ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN)
                                   : 0;
    ss.dwWin32ExitCode           = NO_ERROR;
    ss.dwServiceSpecificExitCode = 0;
    ss.dwCheckPoint = (currentState == SERVICE_RUNNING || currentState == SERVICE_STOPPED)
                      ? 0 : checkPoint++;
    ss.dwWaitHint                = waitHint;
    if (g_statusHandle)
        SetServiceStatus(g_statusHandle, &ss);
}

// ---------------------------------------------------------------------------
// Service control handler
// ---------------------------------------------------------------------------

static DWORD WINAPI serviceCtrlHandler(DWORD ctrl, DWORD /*eventType*/,
                                       LPVOID /*eventData*/, LPVOID /*context*/)
{
    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN)
    {
        reportStatus(SERVICE_STOP_PENDING, 30'000);
        g_stopRequested.store(true);
        platform::requestStop();   // signals the runClient() main loop to exit
        return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

// ---------------------------------------------------------------------------
// Register failure-actions restart policy with the SCM so a deliberate
// ExitProcess(0) from the auto-updater triggers a 5-second restart.
// ---------------------------------------------------------------------------

static void registerFailureActions()
{
    SC_HANDLE scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return;
    SC_HANDLE svc = OpenServiceW(scm, L"ntm-client", SERVICE_CHANGE_CONFIG);
    if (!svc) { CloseServiceHandle(scm); return; }

    SC_ACTION actions[3] = {
        { SC_ACTION_RESTART, 5'000  },
        { SC_ACTION_RESTART, 5'000  },
        { SC_ACTION_RESTART, 30'000 },
    };
    SERVICE_FAILURE_ACTIONSW fa{};
    fa.dwResetPeriod = 86400;  // 24 hours
    fa.cActions      = 3;
    fa.lpsaActions   = actions;
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
}

// ---------------------------------------------------------------------------
// Service main — called by the SCM dispatcher thread
// ---------------------------------------------------------------------------

static VOID WINAPI serviceMain(DWORD /*argc*/, LPWSTR * /*argv*/)
{
    g_statusHandle = RegisterServiceCtrlHandlerExW(L"ntm-client",
                                                   serviceCtrlHandler,
                                                   nullptr);
    if (!g_statusHandle) return;

    reportStatus(SERVICE_START_PENDING, 5'000);
    registerFailureActions();
    reportStatus(SERVICE_RUNNING);

    // Build a raw argv for runClient (service mode passes no CLI args beyond config).
    std::vector<char *> argvRaw = g_argv;
    int argcRaw = static_cast<int>(argvRaw.size());
    runClient(true /*daemonMode*/, g_config, argvRaw.data());

    reportStatus(SERVICE_STOPPED);
}

// ---------------------------------------------------------------------------
// Public entry point — called from client_main.cpp when --service is detected
// ---------------------------------------------------------------------------

int runAsService(const ClientConfig &config, int argc, char **argv)
{
    g_config = config;
    g_argv.assign(argv, argv + argc);

    SERVICE_TABLE_ENTRYW table[] = {
        { const_cast<LPWSTR>(L"ntm-client"), serviceMain },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcherW(table))
    {
        DWORD err = GetLastError();
        if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
        {
            std::fprintf(stderr,
                "ntm-client: --service must be run by the Windows Service Control Manager.\n"
                "  Use: sc start ntm-client\n"
                "  Or run the install script: scripts\\install-service-windows.ps1\n");
        }
        else
        {
            std::fprintf(stderr,
                "ntm-client: StartServiceCtrlDispatcher failed (error %lu)\n", err);
        }
        return 1;
    }
    return 0;
}

}  // namespace ntm::service
