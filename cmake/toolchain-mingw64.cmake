# MinGW-w64 cross-compilation toolchain for Windows x86-64
# Usage:
#   cmake -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-mingw64.cmake \
#         -DNPCAP_SDK=/opt/npcap-sdk \
#         -B build-windows

set(CMAKE_SYSTEM_NAME    Windows)
set(CMAKE_SYSTEM_VERSION 10)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Compiler prefix — adjust if your distro uses a different triple
set(CROSS x86_64-w64-mingw32)

find_program(CMAKE_C_COMPILER   ${CROSS}-gcc)
find_program(CMAKE_CXX_COMPILER ${CROSS}-g++)
find_program(CMAKE_RC_COMPILER  ${CROSS}-windres)

if(NOT CMAKE_C_COMPILER OR NOT CMAKE_CXX_COMPILER)
    message(FATAL_ERROR
        "MinGW-w64 cross-compiler not found. Install with:\n"
        "  sudo pacman -S mingw-w64-gcc")
endif()

# Where to look for Windows libraries/headers (sysroot)
set(CMAKE_FIND_ROOT_PATH /usr/${CROSS})

# Use only the cross-compiled sysroot for libraries/headers;
# but allow CMake's own modules to come from the host.
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Npcap SDK path — can also be passed via -DNPCAP_SDK=...
if(NOT DEFINED NPCAP_SDK AND DEFINED ENV{NPCAP_SDK})
    set(NPCAP_SDK "$ENV{NPCAP_SDK}" CACHE PATH "Npcap SDK root")
endif()

# Help FindOpenSSL locate the MinGW-w64 build of OpenSSL
# (installed by mingw-w64-openssl or mingw-w64-openssl-static)
set(OPENSSL_ROOT_DIR /usr/${CROSS} CACHE PATH "OpenSSL root for MinGW-w64")

message(STATUS "Cross-compiling for Windows x86-64 with ${CROSS}-g++")
message(STATUS "  Sysroot : /usr/${CROSS}")
message(STATUS "  OpenSSL : ${OPENSSL_ROOT_DIR}")
if(NPCAP_SDK)
    message(STATUS "  Npcap   : ${NPCAP_SDK}")
endif()
