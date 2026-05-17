cmake_minimum_required(VERSION 3.16)
project(NetworkTrafficMonitor LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(Threads REQUIRED)
find_library(PCAP_LIBRARY pcap REQUIRED)

add_executable(ntm-server
    src/server_core.cpp
    src/web_dashboard.cpp
)

add_executable(ntm-client
    src/client_main.cpp
    src/client_linux.cpp
)

target_link_libraries(ntm-server
    PRIVATE
        OpenSSL::SSL
        CURL::libcurl
        ZLIB::ZLIB
        Threads::Threads
)

# CPPHTTPLIB_OPENSSL_SUPPORT enables TLS in the vendored cpp-httplib header.
# OpenSSL is already linked above; no extra library needed.
target_compile_definitions(ntm-server PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)

target_link_libraries(ntm-client
    PRIVATE
        OpenSSL::SSL
        ${PCAP_LIBRARY}
        Threads::Threads
)
