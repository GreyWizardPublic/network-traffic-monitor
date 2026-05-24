cmake_minimum_required(VERSION 3.16)
project(NetworkTrafficMonitor LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# ---------------------------------------------------------------------------
# ntm-server (Linux only)
# ---------------------------------------------------------------------------

if(NOT WIN32)
    find_package(CURL REQUIRED)
    find_package(ZLIB REQUIRED)

    add_executable(ntm-server
        src/server_core.cpp
        src/web_dashboard.cpp
        src/webauthn.cpp
    )
    target_compile_definitions(ntm-server PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
    target_link_libraries(ntm-server
        PRIVATE OpenSSL::SSL CURL::libcurl ZLIB::ZLIB Threads::Threads)
endif()

# ---------------------------------------------------------------------------
# ntm-client (Linux + Windows)
# ---------------------------------------------------------------------------

set(NTM_CLIENT_COMMON_SOURCES
    src/client_main.cpp
    src/client_core.cpp
    src/client_impl.cpp
    src/client_transport_tcptls.cpp
    src/client_transport_websocket.cpp
    src/updater.cpp
)

if(WIN32)
    # ---------- Windows build ----------
    # Npcap SDK: set NPCAP_SDK to the extracted SDK root, e.g.:
    #   cmake -DNPCAP_SDK=C:/npcap-sdk ...
    # or via the toolchain file CACHE variable.
    if(NOT DEFINED NPCAP_SDK)
        set(NPCAP_SDK "$ENV{NPCAP_SDK}" CACHE PATH "Path to the Npcap SDK root")
    endif()
    if(NOT NPCAP_SDK)
        message(FATAL_ERROR
            "NPCAP_SDK is not set. Download the Npcap SDK from https://npcap.com/#download "
            "and pass -DNPCAP_SDK=/path/to/npcap-sdk to cmake.")
    endif()

    # miniz — vendored zlib-compatible library for Windows compression support.
    # miniz.c is a C file; set_source_files_properties ensures it is compiled as C,
    # not C++ (the rest of the project uses C++17).
    set_source_files_properties(src/third_party/miniz/miniz.c PROPERTIES LANGUAGE C)

    add_executable(ntm-client
        ${NTM_CLIENT_COMMON_SOURCES}
        src/client_windows.cpp
        src/third_party/miniz/miniz.c
    )
    target_include_directories(ntm-client PRIVATE "${NPCAP_SDK}/Include" src)
    target_link_directories(ntm-client PRIVATE "${NPCAP_SDK}/Lib/x64")
    target_link_libraries(ntm-client
        PRIVATE
            OpenSSL::SSL
            OpenSSL::Crypto
            wpcap          # Npcap import library (runtime — requires npcap.sys kernel driver)
            ws2_32
            iphlpapi
            crypt32        # Windows certificate store (required by OpenSSL)
            bcrypt         # Windows CNG (required by OpenSSL 3.x)
            Threads::Threads
    )
    # Statically link MinGW runtime (libgcc, libstdc++, libwinpthread) so they
    # are not required as DLLs on the target machine. -static makes MinGW prefer
    # .a over .dll.so where available; wpcap has no static .a so it stays dynamic.
    target_link_options(ntm-client PRIVATE
        -static
        -static-libgcc
        -static-libstdc++
    )
    # Needed for Npcap's wpcap.dll (load-time linked)
    target_compile_definitions(ntm-client PRIVATE HAVE_REMOTE)

    # ---------------------------------------------------------------------------
    # ntm-tests-windows — Windows unit test binary
    # ---------------------------------------------------------------------------
    # Tests pure-logic paths and the Windows platform abstraction layer.
    # Does NOT require a live server, Npcap kernel driver, or network access.
    # Does NOT link wpcap (no pcap functions are called in the test paths).
    #
    # Run with:
    #   cmake --build build-windows --target ntm-tests-windows
    #   build-windows\ntm-tests-windows.exe
    # ---------------------------------------------------------------------------
    add_executable(ntm-tests-windows
        tests/test_main.cpp
        tests/test_flow_aggregator.cpp
        tests/test_windows_client.cpp
        tests/test_parse_data_line.cpp      # pure logic, no POSIX deps — shared with Linux suite
        tests/test_proto_constants.cpp      # pure logic, no POSIX deps — shared with Linux suite
        tests/test_client_http_util.cpp     # pure logic, no POSIX deps — shared with Linux suite
        tests/test_client_websocket.cpp     # pure logic, no POSIX deps — shared with Linux suite
        tests/test_client_config.cpp        # pure logic, no POSIX deps — shared with Linux suite
        src/client_core.cpp
        src/client_windows.cpp
    )
    target_include_directories(ntm-tests-windows PRIVATE src tests "${NPCAP_SDK}/Include")
    target_link_libraries(ntm-tests-windows
        PRIVATE
            OpenSSL::SSL
            OpenSSL::Crypto
            ws2_32
            iphlpapi
            crypt32
            bcrypt
            Threads::Threads
    )
    target_compile_definitions(ntm-tests-windows PRIVATE HAVE_REMOTE)
    target_link_options(ntm-tests-windows PRIVATE
        -static
        -static-libgcc
        -static-libstdc++
    )
    set_target_properties(ntm-tests-windows PROPERTIES OUTPUT_NAME "ntm-tests-windows")

    enable_testing()
    add_test(NAME ntm-windows-unit-tests COMMAND ntm-tests-windows)

else()
    # ---------- Linux build ----------
    find_library(PCAP_LIBRARY pcap REQUIRED)

    add_executable(ntm-client
        ${NTM_CLIENT_COMMON_SOURCES}
        src/client_linux.cpp
    )
    target_link_libraries(ntm-client
        PRIVATE
            OpenSSL::SSL
            ${PCAP_LIBRARY}
            ZLIB::ZLIB        # zlib stream compression on the data phase
            Threads::Threads
    )
endif()

# ---------------------------------------------------------------------------
# ntm-client output name — must match the auto-update manifest naming convention:
#   ntm-client-{platform}-{version}[.exe]
# The version is read directly from client_version.hpp so CMakeLists.txt never
# needs a manual bump. CMAKE automatically appends .exe on Windows.
# ---------------------------------------------------------------------------

file(STRINGS "src/client_version.hpp" _ver_line
     REGEX "kClientVersion\\[\\]")
string(REGEX MATCH "\"([0-9]+\\.[0-9]+\\.[0-9]+)\"" _ "${_ver_line}")
set(NTM_CLIENT_VERSION "${CMAKE_MATCH_1}")
if(NOT NTM_CLIENT_VERSION)
    message(FATAL_ERROR "Could not parse kClientVersion from src/client_version.hpp")
endif()

if(WIN32)
    set(NTM_CLIENT_PLATFORM "windows-amd64")
else()
    set(NTM_CLIENT_PLATFORM "linux-amd64")
endif()

set_target_properties(ntm-client PROPERTIES
    OUTPUT_NAME "ntm-client-${NTM_CLIENT_PLATFORM}-${NTM_CLIENT_VERSION}"
)

# ---------------------------------------------------------------------------
# ntm-tests — unit test binary (Linux only; pure logic, no platform I/O)
# ---------------------------------------------------------------------------

if(NOT WIN32)
    add_executable(ntm-tests
        tests/test_main.cpp
        tests/test_flow_aggregator.cpp
        tests/test_health_stats.cpp
        tests/test_zlib_stream.cpp
        tests/test_alpn.cpp
        tests/test_lan_ip.cpp
        tests/test_parse_data_line.cpp
        tests/test_proto_constants.cpp
        tests/test_web_auth.cpp
        tests/test_client_http_util.cpp
        tests/test_client_websocket.cpp
        tests/test_client_config.cpp
    )
    target_include_directories(ntm-tests PRIVATE src tests)
    # ntm_types.hpp uses POSIX socket headers for isLanIP(); no extra libs needed.
    # test_zlib_stream.cpp uses zlib_stream.hpp which needs ZLIB::ZLIB.
    target_link_libraries(ntm-tests PRIVATE ZLIB::ZLIB)
    target_compile_options(ntm-tests PRIVATE -Wall -Wextra -Wpedantic)
    set_target_properties(ntm-tests PROPERTIES OUTPUT_NAME "ntm-tests")

    # Register with CTest so `ctest` or `cmake --build build-linux --target test` works.
    enable_testing()
    add_test(NAME ntm-unit-tests COMMAND ntm-tests)
endif()
