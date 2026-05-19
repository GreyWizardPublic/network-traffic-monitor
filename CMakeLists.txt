cmake_minimum_required(VERSION 3.16)
project(NetworkTrafficMonitor LANGUAGES CXX)

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

    add_executable(ntm-client
        ${NTM_CLIENT_COMMON_SOURCES}
        src/client_windows.cpp
    )
    target_include_directories(ntm-client PRIVATE "${NPCAP_SDK}/Include")
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
            Threads::Threads
    )
endif()
