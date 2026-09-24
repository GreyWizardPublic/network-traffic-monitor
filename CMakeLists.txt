cmake_minimum_required(VERSION 3.16)
project(NetworkTrafficMonitor LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Install git pre-commit hook on configure so a fresh clone self-activates.
if(EXISTS "${CMAKE_SOURCE_DIR}/.git")
    execute_process(
        COMMAND git config core.hooksPath scripts/hooks
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        RESULT_VARIABLE _hooks_result
        OUTPUT_QUIET ERROR_QUIET
    )
    if(_hooks_result EQUAL 0)
        message(STATUS "git pre-commit hook active (scripts/hooks/)")
    else()
        message(WARNING "Could not set git core.hooksPath — version-bump hook not installed")
    endif()
endif()

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# ---------------------------------------------------------------------------
# ntm-server (Linux only)
# ---------------------------------------------------------------------------

if(NOT WIN32)
    # WSL2: PATH leaks Windows/MSYS2 dirs into CMake's package search, causing
    # find_package(CURL) to pick up /mnt/c/msys64 instead of /usr.
    # Strip /mnt/* from PATH temporarily — compilers are already found by now.
    string(REGEX REPLACE "(^|:)[^:]*/mnt/[^:]*" "" _wsl_filtered_path "$ENV{PATH}")
    set(ENV{PATH} "${_wsl_filtered_path}")
    find_package(CURL REQUIRED)
    find_package(ZLIB REQUIRED)

    add_executable(ntm-server
        src/server_core.cpp
        src/web_dashboard.cpp
        src/webauthn.cpp
        src/siwa.cpp
    )
    target_compile_definitions(ntm-server PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
    target_link_libraries(ntm-server
        PRIVATE OpenSSL::SSL OpenSSL::Crypto CURL::libcurl ZLIB::ZLIB Threads::Threads)

    # ---------------------------------------------------------------------------
    # ntm-server output name — ntm-server-linux-amd64-{version}
    # Mirrors the ntm-client naming convention so the binary can be dropped
    # directly into the deployment directory without renaming.
    # Version is read from src/server_version.hpp at configure time.
    # ---------------------------------------------------------------------------
    file(STRINGS "src/server_version.hpp" _sver_line
         REGEX "kServerVersion\\[\\]")
    string(REGEX MATCH "\"([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)\"" _ "${_sver_line}")
    set(NTM_SERVER_VERSION "${CMAKE_MATCH_1}")
    if(NOT NTM_SERVER_VERSION)
        message(FATAL_ERROR "Could not parse kServerVersion from src/server_version.hpp (expected MAJOR.MINOR.PATCH.REVISION)")
    endif()

    set_target_properties(ntm-server PROPERTIES
        OUTPUT_NAME "ntm-server-linux-amd64-${NTM_SERVER_VERSION}"
    )

    # ---------------------------------------------------------------------------
    # POST_BUILD: sign the server binary with ML-DSA-65.
    # Requires the private key at ~/.ntm/privatebuildkey.secret.
    # If the key is absent, the build FAILS with a clear error message.
    # Unsigned server binaries are never produced — this step is mandatory.
    # ---------------------------------------------------------------------------
    if(NOT EXISTS "$ENV{HOME}/.ntm/privatebuildkey.secret")
        message(WARNING
            "\n*** ntm-server signing key NOT FOUND at ~/.ntm/privatebuildkey.secret ***\n"
            "    The build will FAIL at the signing step.\n"
            "    Run:  ./scripts/manage-build-keys.sh\n"
            "    Then re-run cmake --build.\n")
    endif()

    add_custom_command(TARGET ntm-server POST_BUILD
        COMMAND "${CMAKE_SOURCE_DIR}/scripts/sign-server.sh"
                "$<TARGET_FILE:ntm-server>"
        COMMENT "Signing ntm-server with ML-DSA-65 (scripts/sign-server.sh)"
        VERBATIM
    )
endif()

# ---------------------------------------------------------------------------
# ntm-client (Linux + Windows)
# ---------------------------------------------------------------------------

set(NTM_CLIENT_COMMON_SOURCES
    src/client_main.cpp
    src/client_core.cpp
    src/client_filelog.cpp
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
        src/client_windows_service.cpp
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
            advapi32       # Windows SCM APIs (service mode)
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
    # Optional: Authenticode verification of downloaded update binaries.
    # Off by default. Enable with:
    #   cmake -DNTM_REQUIRE_AUTHENTICODE=ON -DNTM_AUTHENTICODE_SUBJECT="CN=Example Inc" ...
    # When ON, the updater refuses to apply any download whose Authenticode signature
    # does not verify (or does not match NTM_AUTHENTICODE_SUBJECT once that check lands).
    # ---------------------------------------------------------------------------
    option(NTM_REQUIRE_AUTHENTICODE
        "Verify Authenticode signature on downloaded update binaries (Windows only)" OFF)
    if(NTM_REQUIRE_AUTHENTICODE)
        if(NOT NTM_AUTHENTICODE_SUBJECT)
            message(FATAL_ERROR
                "NTM_REQUIRE_AUTHENTICODE=ON requires "
                "-DNTM_AUTHENTICODE_SUBJECT=\"<publisher subject string>\"")
        endif()
        target_compile_definitions(ntm-client PRIVATE
            NTM_REQUIRE_AUTHENTICODE
            NTM_AUTHENTICODE_SUBJECT="${NTM_AUTHENTICODE_SUBJECT}")
        target_link_libraries(ntm-client PRIVATE wintrust)
    endif()

    # Configure-time key existence check — same policy as the Linux build block below.
    # cmake is normally invoked from PowerShell on Windows (HOME may not be set);
    # try USERPROFILE first (native Windows), then HOME (MSYS2 bash invocation).
    # NTM_SIGN_HOME records which one won, so POST_BUILD signs from the same file.
    # Trust v2 (#133): the Windows build key is a DPAPI-held ML-DSA-65 seed,
    # released at sign time by scripts/trust/windows-build-seed.ps1.
    if(DEFINED ENV{USERPROFILE} AND EXISTS "$ENV{USERPROFILE}/.ntm/windows-build.dpapi")
        # key found via USERPROFILE
        file(TO_CMAKE_PATH "$ENV{USERPROFILE}" NTM_SIGN_HOME)
    elseif(DEFINED ENV{HOME} AND EXISTS "$ENV{HOME}/.ntm/windows-build.dpapi")
        # key found via HOME (MSYS2 environment)
        file(TO_CMAKE_PATH "$ENV{HOME}" NTM_SIGN_HOME)
    else()
        message(WARNING
            "\n*** ntm-client Windows build key NOT FOUND at %USERPROFILE%\\.ntm\\windows-build.dpapi ***\n"
            "    The build will FAIL at the POST_BUILD signing step.\n"
            "    The key is a DPAPI-encrypted seed generated once per host (#135).\n"
            "    Do NOT run manage-build-keys.sh; ask the Architect.\n")
        file(TO_CMAKE_PATH "$ENV{USERPROFILE}" NTM_SIGN_HOME)
    endif()

    # sign-client.sh must run under MSYS2 bash, invoked explicitly. cmd.exe cannot
    # execute a .sh: it dispatches via the file association, which on a typical
    # dev box is Git-for-Windows' git-bash.exe — a GUI launcher that returns 0
    # immediately, so signing was a silent no-op (#129/#132).
    #
    # NO_DEFAULT_PATH is deliberate: on a stock Windows PATH the first bash.exe is
    # usually C:\Windows\System32\bash.exe (WSL — signs inside Linux against a
    # different $HOME) or Git-for-Windows bash, neither of which is the toolchain.
    # Override with -DNTM_BASH=<path> if MSYS2 lives elsewhere.
    find_program(NTM_BASH bash PATHS "C:/msys64/usr/bin" NO_DEFAULT_PATH)
    if(NOT NTM_BASH)
        message(FATAL_ERROR
            "MSYS2 bash not found at C:/msys64/usr/bin — required for POST_BUILD signing.\n"
            "Install MSYS2 (winget install MSYS2.MSYS2) or pass -DNTM_BASH=<path-to-msys2-bash.exe>.")
    endif()
    get_filename_component(NTM_BASH_DIR "${NTM_BASH}" DIRECTORY)

    # POST_BUILD: sign the Windows client binary with ML-DSA-65.
    # HOME is pinned because MSYS2 otherwise defaults it to /home/<user> under
    # C:\msys64, not the USERPROFILE the configure check above looked in.
    # PATH is pinned to the MSYS2 bin dir so openssl/grep/wc resolve to the
    # toolchain's own copies — a non-login bash inherits no /usr/bin.
    add_custom_command(TARGET ntm-client POST_BUILD
        COMMAND "${CMAKE_COMMAND}" -E env
                "HOME=${NTM_SIGN_HOME}"
                "PATH=${NTM_BASH_DIR}"
                "${NTM_BASH}" "${CMAKE_SOURCE_DIR}/scripts/sign-client.sh"
                "$<TARGET_FILE:ntm-client>"
        COMMENT "Signing ntm-client (Windows) with ML-DSA-65 (scripts/sign-client.sh)"
        VERBATIM
    )

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
        tests/test_client_config_health.cpp # pure logic, no POSIX deps — shared with Linux suite
        tests/test_alpn.cpp                 # pure logic, no POSIX deps — shared with Linux suite
        tests/test_zlib_stream.cpp          # uses zlib_stream.hpp → miniz on Windows
        tests/test_client_signing.cpp
        tests/test_client_push.cpp
        src/client_core.cpp
        src/client_windows.cpp
        src/client_filelog.cpp              # required by client_windows.cpp (dual-sink ntmLog)
        src/third_party/miniz/miniz.c       # required by zlib_stream.hpp on Windows
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
            advapi32   # required by aclapi.h (GetEffectiveRightsFromAclW etc.)
            Threads::Threads
    )
    target_compile_definitions(ntm-tests-windows PRIVATE HAVE_REMOTE)
    target_compile_options(ntm-tests-windows PRIVATE -Wall -Wextra -Wpedantic)
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

    # POST_BUILD: sign the client binary with ML-DSA-65.
    if(NOT EXISTS "$ENV{HOME}/.ntm/privatebuildkey.secret")
        message(WARNING
            "\n*** ntm-client signing key NOT FOUND at ~/.ntm/privatebuildkey.secret ***\n"
            "    The build will FAIL at the signing step.\n"
            "    Run:  ./scripts/manage-build-keys.sh\n"
            "    Then re-run cmake --build.\n")
    endif()

    add_custom_command(TARGET ntm-client POST_BUILD
        COMMAND "${CMAKE_SOURCE_DIR}/scripts/sign-client.sh"
                "$<TARGET_FILE:ntm-client>"
        COMMENT "Signing ntm-client with ML-DSA-65 (scripts/sign-client.sh)"
        VERBATIM
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
string(REGEX MATCH "\"([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)\"" _ "${_ver_line}")
set(NTM_CLIENT_VERSION "${CMAKE_MATCH_1}")
if(NOT NTM_CLIENT_VERSION)
    message(FATAL_ERROR "Could not parse kClientVersion from src/client_version.hpp (expected MAJOR.MINOR.PATCH.REVISION)")
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
        tests/test_siwa.cpp
        tests/test_traffic_stats.cpp
        src/siwa.cpp
        src/webauthn.cpp
        tests/test_client_http_util.cpp
        tests/test_client_websocket.cpp
        tests/test_client_config.cpp
        tests/test_server_signing.cpp
        tests/test_server_upgrade.cpp
        tests/test_client_signing.cpp
        tests/test_client_push.cpp
        tests/test_client_history.cpp
        tests/test_hidden_entities.cpp
        tests/test_client_config_health.cpp
        tests/test_client_identity_perms.cpp  # H-4: POSIX-only permission check
        tests/test_client_filelog.cpp
        src/client_filelog.cpp              # filelog impl for test binary (POSIX-only)
        tests/test_update_push.cpp
    )
    target_include_directories(ntm-tests PRIVATE src tests)
    target_compile_definitions(ntm-tests PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
    # ntm_types.hpp uses POSIX socket headers for isLanIP(); no extra libs needed.
    # test_zlib_stream.cpp uses zlib_stream.hpp which needs ZLIB::ZLIB.
    # test_server_signing.cpp uses OpenSSL EVP for ML-DSA-65 key generation + verification.
    # test_siwa.cpp uses siwa.cpp (JWKS + RSA verify) which needs OpenSSL::SSL and CURL.
    # test_client_filelog.cpp uses client_filelog.cpp which needs std::filesystem (C++17).
    target_link_libraries(ntm-tests PRIVATE ZLIB::ZLIB OpenSSL::SSL OpenSSL::Crypto CURL::libcurl)
    target_compile_options(ntm-tests PRIVATE -Wall -Wextra -Wpedantic)
    set_target_properties(ntm-tests PROPERTIES OUTPUT_NAME "ntm-tests")

    # Register with CTest so `ctest` or `cmake --build build-linux --target test` works.
    enable_testing()
    add_test(NAME ntm-unit-tests COMMAND ntm-tests)
endif()
