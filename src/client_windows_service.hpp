#pragma once
#ifdef _WIN32

#include "client.hpp"

namespace ntm::service
{

// Dispatch ntm-client as a Windows SCM service.
// Called from client_main.cpp when --service is detected.
// Does not return until the service is stopped.
int runAsService(const ClientConfig &config, int argc, char **argv);

}  // namespace ntm::service

#endif  // _WIN32
