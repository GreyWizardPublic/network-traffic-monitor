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
    src/main.cpp
)

add_executable(ntm-client
    src/client_main.cpp
    src/client_linux.cpp
)

add_executable(ntm-monitor
    src/monitor_main.cpp
)

target_link_libraries(ntm-server
    PRIVATE
        OpenSSL::SSL
        ${PCAP_LIBRARY}
        CURL::libcurl
        ZLIB::ZLIB
        Threads::Threads
)

target_link_libraries(ntm-client
    PRIVATE
        OpenSSL::SSL
        ${PCAP_LIBRARY}
        Threads::Threads
)

target_link_libraries(ntm-monitor
    PRIVATE
        OpenSSL::SSL
        Threads::Threads
)
