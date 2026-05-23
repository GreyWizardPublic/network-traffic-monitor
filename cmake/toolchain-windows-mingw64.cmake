# Native Windows MinGW-w64 toolchain (MSYS2 mingw64 environment)
#
# Usage (from PowerShell, repo root):
#   cmake -B build-windows -G "Ninja" `
#         -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-windows-mingw64.cmake `
#         -DNPCAP_SDK="C:/npcap-sdk" `
#         -DCMAKE_BUILD_TYPE=Release
#   cmake --build build-windows -j $env:NUMBER_OF_PROCESSORS
#
# Prerequisites (one-time setup — run scripts/setup-toolchain-windows.ps1):
#   - MSYS2 installed at C:\msys64
#   - mingw-w64-x86_64-gcc, cmake, ninja, openssl installed via pacman
#   - Npcap SDK extracted to C:\npcap-sdk

set(MSYS2_MINGW64 "C:/msys64/mingw64")

# ---------- Compilers ----------
set(CMAKE_C_COMPILER   "${MSYS2_MINGW64}/bin/gcc.exe"     CACHE FILEPATH "C compiler")
set(CMAKE_CXX_COMPILER "${MSYS2_MINGW64}/bin/g++.exe"     CACHE FILEPATH "C++ compiler")
set(CMAKE_RC_COMPILER  "${MSYS2_MINGW64}/bin/windres.exe" CACHE FILEPATH "RC compiler")

# Prefer Ninja (faster); fall back to mingw32-make
find_program(_NINJA "${MSYS2_MINGW64}/bin/ninja.exe")
if(_NINJA)
    set(CMAKE_MAKE_PROGRAM "${MSYS2_MINGW64}/bin/ninja.exe" CACHE FILEPATH "Build tool")
else()
    set(CMAKE_MAKE_PROGRAM "${MSYS2_MINGW64}/bin/mingw32-make.exe" CACHE FILEPATH "Build tool")
endif()

# ---------- OpenSSL (static libs from MSYS2 mingw64) ----------
set(OPENSSL_ROOT_DIR        "${MSYS2_MINGW64}"                         CACHE PATH     "OpenSSL root")
set(OPENSSL_USE_STATIC_LIBS TRUE                                        CACHE BOOL     "Link OpenSSL statically")
set(OPENSSL_CRYPTO_LIBRARY  "${MSYS2_MINGW64}/lib/libcrypto.a"         CACHE FILEPATH "OpenSSL crypto lib")
set(OPENSSL_SSL_LIBRARY     "${MSYS2_MINGW64}/lib/libssl.a"            CACHE FILEPATH "OpenSSL ssl lib")
set(OPENSSL_INCLUDE_DIR     "${MSYS2_MINGW64}/include"                 CACHE PATH     "OpenSSL include dir")

# ---------- Search paths ----------
# Look for headers/libs only inside the mingw64 sysroot so CMake doesn't
# accidentally pick up MSVC or Cygwin artefacts from elsewhere on the system.
list(APPEND CMAKE_PREFIX_PATH "${MSYS2_MINGW64}")
set(CMAKE_FIND_ROOT_PATH "${MSYS2_MINGW64}")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)   # cmake modules come from host
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

message(STATUS "[toolchain-windows-mingw64] Compiler : ${CMAKE_CXX_COMPILER}")
message(STATUS "[toolchain-windows-mingw64] OpenSSL  : ${OPENSSL_ROOT_DIR}")
if(NPCAP_SDK)
    message(STATUS "[toolchain-windows-mingw64] Npcap    : ${NPCAP_SDK}")
endif()
