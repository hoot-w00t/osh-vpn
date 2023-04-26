cmake_minimum_required(VERSION 3.3.0)
project(osh-vpn
    VERSION 0.0.1
    DESCRIPTION "Experimental mesh VPN"
    HOMEPAGE_URL "https://github.com/hoot-w00t/osh-vpn"
    LANGUAGES "C")

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Local modules
include(compiler_flags)
include(linker_flags)

# System modules
include(CheckIncludeFile)
include(CTest)
include(GNUInstallDirs)

enable_testing()

# Libraries to link with
set(OSH_LINK_LIBRARIES "")

# Source/header files configured by CMake
set(OSH_BINARY_SOURCEDIR "${CMAKE_CURRENT_BINARY_DIR}/src")
set(OSH_BINARY_INCLUDEDIR "${CMAKE_CURRENT_BINARY_DIR}/include")
include_directories(${OSH_BINARY_INCLUDEDIR})

# Osh version files
set(OSH_VERSION_FILE_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/src/version.c.in")
set(OSH_VERSION_FILE_DEST "${OSH_BINARY_SOURCEDIR}/version.c")
set(VERSION_GIT_FILE_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/include/version_git.h.in")
set(VERSION_GIT_FILE_DEST "${OSH_BINARY_INCLUDEDIR}/version_git.h")

# Git revision information
add_custom_target(version_git
    COMMAND ${CMAKE_COMMAND} -Droot_dir=${CMAKE_CURRENT_SOURCE_DIR}
                             -Dsrc_file=${VERSION_GIT_FILE_SOURCE}
                             -Ddest_file=${VERSION_GIT_FILE_DEST}
                             -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/version_git.cmake
    DEPENDS ${VERSION_GIT_FILE_SOURCE}
    BYPRODUCTS ${VERSION_GIT_FILE_DEST}
    VERBATIM)

# Osh version definitions and configuration
set(OSH_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(OSH_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(OSH_VERSION_PATCH ${PROJECT_VERSION_PATCH})

set(OSH_VERSION_STR "${OSH_VERSION_MAJOR}.${OSH_VERSION_MINOR}.${OSH_VERSION_PATCH}")

if (OSH_VERSION_COMMENT)
    set(OSH_VERSION_HAS_COMMENT 1)
else()
    set(OSH_VERSION_HAS_COMMENT 0)
endif()

message(STATUS "Configuring ${OSH_VERSION_FILE_DEST} with version ${OSH_VERSION_STR} ${OSH_VERSION_COMMENT}")
configure_file("${OSH_VERSION_FILE_SOURCE}" "${OSH_VERSION_FILE_DEST}" @ONLY)

# Package variables
set(CPACK_VERBATIM_VARIABLES TRUE)

set(CPACK_PACKAGE_NAME "osh-vpn")
set(CPACK_PACKAGE_VENDOR "akrocynova")
set(CPACK_PACKAGE_CONTACT "${CPACK_PACKAGE_VENDOR}")
set(CPACK_PACKAGE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/packages")

# Debian packages
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "${CPACK_PACKAGE_CONTACT}")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libssl1.1")

# Libraries
# Winsock2 and bcrypt
if (WIN32)
    list(APPEND OSH_LINK_LIBRARIES wsock32)
    list(APPEND OSH_LINK_LIBRARIES ws2_32)
    list(APPEND OSH_LINK_LIBRARIES bcrypt)
endif()

# OpenSSL
find_package(OpenSSL 1.1.0 REQUIRED COMPONENTS Crypto)
include_directories(${OPENSSL_INCLUDE_DIR})
list(APPEND OSH_LINK_LIBRARIES ${OPENSSL_CRYPTO_LIBRARIES})

# easyconf (from the submodule)
set(EASYCONF_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/easyconf")
set(EASYCONF_BUILD "easyconf")
set(EASYCONF_INCLUDEDIR "${EASYCONF_SOURCE}/include")

set(EASYCONF_MSG "Configuring '${CMAKE_CURRENT_BINARY_DIR}/${EASYCONF_BUILD}' from '${EASYCONF_SOURCE}'")

message(STATUS "${EASYCONF_MSG}")
add_subdirectory("${EASYCONF_SOURCE}" "${EASYCONF_BUILD}" EXCLUDE_FROM_ALL)
message(STATUS "${EASYCONF_MSG} - done")

link_directories(${EASYCONF_BUILD})
include_directories(${EASYCONF_INCLUDEDIR})
list(APPEND OSH_LINK_LIBRARIES easyconf)

# Header directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# systemd service
option(ENABLE_SYSTEMD "Configure and install systemd service" OFF)

set(SYSTEMD_SERVICE_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/systemd/osh@.service.in")
set(SYSTEMD_SERVICE_DEST "${CMAKE_CURRENT_BINARY_DIR}/osh@.service")

if (ENABLE_SYSTEMD)
    configure_file("${SYSTEMD_SERVICE_SOURCE}" "${SYSTEMD_SERVICE_DEST}" @ONLY)
    install(FILES "${SYSTEMD_SERVICE_DEST}"
            DESTINATION "${CMAKE_INSTALL_LIBDIR}/systemd/system")
endif()

# TUN/TAP sources
option(TUNTAP_DISABLE_EMULATION "Disable TUN/TAP emulation layers" OFF)

set(OSH_TUNTAP_SOURCES src/tuntap/common.c)
set(OSH_TUNTAP_EMU_SOURCES src/tuntap/tun_emu.c)

if (NOT TUNTAP_DISABLE_EMULATION)
    set(OSH_TUNTAP_SOURCES ${OSH_TUNTAP_SOURCES} ${OSH_TUNTAP_EMU_SOURCES})
endif()

if (CYGWIN OR MSYS OR WIN32)
    set(OSH_TUNTAP_SOURCES ${OSH_TUNTAP_SOURCES} src/tuntap/windows.c "src/tuntap/tap-windows.c")
else()
    set(OSH_TUNTAP_SOURCES ${OSH_TUNTAP_SOURCES} src/tuntap/linux.c)
endif()

# Async I/O sources
set(AIO_BACKEND_CONFIGURED "unknown")
if (NOT AIO_BACKEND)
    set(AIO_BACKEND "auto")
endif()

if (AIO_BACKEND STREQUAL "auto")
    check_include_file("poll.h"  poll_available)
    check_include_file("sys/epoll.h" epoll_available)

    if (WIN32)
        set(AIO_BACKEND_CONFIGURED "windows")
    elseif (epoll_available)
        set(AIO_BACKEND_CONFIGURED "epoll")
    elseif (poll_available)
        set(AIO_BACKEND_CONFIGURED "poll")
    endif()

    if (AIO_BACKEND_CONFIGURED STREQUAL "unknown")
        message(FATAL_ERROR "Failed to automatically configure AIO backend")
    endif()
else()
    set(AIO_BACKEND_CONFIGURED "${AIO_BACKEND}")
endif()

# Configure AIO sources using configured backend
set(OSH_AIO_SOURCES src/aio/aio.c)
if (AIO_BACKEND_CONFIGURED STREQUAL "epoll")
    set(OSH_AIO_SOURCES ${OSH_AIO_SOURCES} src/aio/epoll.c)
elseif (AIO_BACKEND_CONFIGURED STREQUAL "poll")
    set(OSH_AIO_SOURCES ${OSH_AIO_SOURCES} src/aio/poll.c)
elseif (AIO_BACKEND_CONFIGURED STREQUAL "windows")
    set(OSH_AIO_SOURCES ${OSH_AIO_SOURCES} src/aio/windows.c)
else()
    message(FATAL_ERROR "Invalid configured AIO backend: ${AIO_BACKEND_CONFIGURED}")
endif()

message(STATUS "AIO backend: ${AIO_BACKEND_CONFIGURED} (${AIO_BACKEND})")

# All sources for oshd
set(OSHD_SOURCES
    ${OSH_AIO_SOURCES}
    src/crypto/cipher.c
    src/crypto/hash.c
    src/crypto/hkdf.c
    src/crypto/pkey.c
    src/events/automatic_connections.c
    src/events/connect.c
    src/events/dynamic_ip_conflict.c
    src/events/expire_endpoints.c
    src/events/expire_routes.c
    src/events/expire_seen_brd_ids.c
    src/events/handshake_renew.c
    src/events/handshake_timeout.c
    src/events/keepalive.c
    src/netutil/arp.c
    src/netutil/icmp_nd.c
    src/netutil/icmp.c
    src/oshpacket_handlers/data.c
    src/oshpacket_handlers/devmode.c
    src/oshpacket_handlers/edge.c
    src/oshpacket_handlers/endpoint.c
    src/oshpacket_handlers/goodbye.c
    src/oshpacket_handlers/handshake_end.c
    src/oshpacket_handlers/handshake_sig.c
    src/oshpacket_handlers/handshake.c
    src/oshpacket_handlers/hello.c
    src/oshpacket_handlers/ping_pong.c
    src/oshpacket_handlers/pubkey.c
    src/oshpacket_handlers/route.c
    ${OSH_TUNTAP_SOURCES}
    src/base64.c
    src/client_state_exchange.c
    src/client.c
    src/device_mode.c
    src/device.c
    src/endpoints.c
    src/events.c
    src/hashtable_murmur3_32.c
    src/hashtable.c
    src/logger.c
    src/murmurhash.c
    src/netaddr.c
    src/netbuffer.c
    src/netroute.c
    src/node.c
    src/oshd_clock.c
    src/oshd_cmd.c
    src/oshd_conf.c
    src/oshd_process_packet.c
    src/oshd_socket.c
    src/oshd.c
    src/oshpacket.c
    src/random_xoshiro256.c
    src/random.c
    src/sock.c
    src/tcp.c
    src/xalloc.c
    ${OSH_VERSION_FILE_DEST}
)

if (CYGWIN OR MSYS OR WIN32)
    # Windows-specific utility functions
    list(APPEND OSHD_SOURCES "src/macros_windows.c")
endif()

# All sources for oshd_tests
set(OSHD_TESTS_SOURCES
    ${OSHD_SOURCES}
    tests/base64_tests.c
    tests/device_mode_tests.c
    tests/hashtable_tests.c
    tests/macros_bitfield_tests.c
    tests/netaddr_tests.c
    tests/netbuffer_tests.c
    tests/netroute_tests.c
    tests/node_id_tests.c
    tests/oshpacket_tests.c
    tests/random_tests.c)

# Osh daemon
add_executable(oshd ${OSHD_SOURCES} src/main.c)
target_link_libraries(oshd ${OSH_LINK_LIBRARIES})
add_dependencies(oshd version_git)

# Criterion unit tests
option(ENABLE_UNIT_TESTS "Enable unit testing with Criterion" OFF)
if (ENABLE_UNIT_TESTS)
    message(STATUS "Unit tests enabled")

    find_library(CRITERION_FOUND criterion REQUIRED)
    add_executable(oshd_tests ${OSHD_SOURCES} ${OSHD_TESTS_SOURCES})
    target_link_libraries(oshd_tests ${OSH_LINK_LIBRARIES} criterion)
    add_dependencies(oshd_tests version_git)

    add_test(NAME unit_tests COMMAND ./oshd_tests)

    # CTest will try to run easyconf's tests too but they are excluded from all
    add_dependencies(oshd_tests easyconf_tests)
else()
    message(STATUS "Unit tests disabled")
endif()

# Installation rules
install(TARGETS oshd RUNTIME)

# Global compiler flags
add_compiler_flag(CMAKE_C_FLAGS -pipe)
add_compiler_flags(CMAKE_C_FLAGS -Wall -Wextra -Wshadow)
add_compiler_flags(CMAKE_C_FLAGS -Wformat-security -Wformat-signedness)
add_compiler_flags(CMAKE_C_FLAGS -Wcast-qual -Wpointer-arith -Wwrite-strings)
add_compiler_flags(CMAKE_C_FLAGS -Wduplicated-branches -Wduplicated-cond)

if (CYGWIN)
    add_compiler_flag_nocheck(CMAKE_C_FLAGS "-D_GNU_SOURCE")
endif()

if (MINGW)
    add_compiler_flag_nocheck(CMAKE_C_FLAGS "-D__USE_MINGW_ANSI_STDIO=1")
endif()

if (WIN32)
    add_compiler_flag_nocheck(CMAKE_C_FLAGS "-DWIN32_LEAN_AND_MEAN")
endif()

option(DISABLE_EVENTS_TIMERFD "Don't use timerfd for timed events even if it is available" OFF)
check_include_file("sys/timerfd.h" timerfd_available)
if (timerfd_available AND NOT DISABLE_EVENTS_TIMERFD)
    add_compiler_flag_nocheck(CMAKE_C_FLAGS "-DEVENTS_USE_TIMERFD")
endif()

if (TUNTAP_DISABLE_EMULATION)
    add_compiler_flag_nocheck(CMAKE_C_FLAGS -DTUNTAP_DISABLE_EMULATION)
endif()

# If no build type was specified we will use the default
set(default_build_type "Debug")
if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "No build type was specified, defaulting to '${default_build_type}'")
    set(CMAKE_BUILD_TYPE "${default_build_type}")
endif()

# Build hardening flags
option(ENABLE_HARDENING "Enable compiler and linker hardening flags" ON)
if (NOT HARDENING_C_FLAGS)
    set(HARDENING_C_FLAGS "")
endif()
if (NOT HARDENING_LINKER_FLAGS)
    set(HARDENING_LINKER_FLAGS "")
endif()

if (ENABLE_HARDENING)
    add_compiler_flag_nocheck(HARDENING_C_FLAGS "-D_FORTIFY_SOURCE=2")
    add_compiler_flags(HARDENING_C_FLAGS -fstack-protector-strong -Wstack-protector)

    if (NOT MINGW)
        add_compiler_flag(HARDENING_C_FLAGS -fstack-clash-protection)
    endif()

    check_c_compiler_flag(-fPIE cflag_fpie)
    if (cflag_fpie)
        add_compiler_flag_nocheck(HARDENING_C_FLAGS -fPIE)
        add_linker_flag_nocheck(HARDENING_LINKER_FLAGS -pie)
    endif()

    add_linker_flag(HARDENING_LINKER_FLAGS "-Wl,-z,relro")
    add_linker_flag(HARDENING_LINKER_FLAGS "-Wl,-z,now")
    add_linker_flag(HARDENING_LINKER_FLAGS "-Wl,-z,noexecstack")
endif()

# Build type flags
set(CMAKE_C_FLAGS_DEBUG                     "-O0 -g3")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG            "")

set(CMAKE_C_FLAGS_RELEASE                   "-O2 ${HARDENING_C_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS_RELEASE          "${HARDENING_LINKER_FLAGS}")

set(CMAKE_C_FLAGS_MINSIZEREL                "-Os ${HARDENING_C_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS_MINSIZEREL       "${HARDENING_LINKER_FLAGS}")

set(CMAKE_C_FLAGS_RELWITHDEBINFO            "${CMAKE_C_FLAGS_RELEASE} -g")
set(CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO   "${CMAKE_EXE_LINKER_FLAGS_RELEASE}")

set(CMAKE_C_FLAGS_NATIVERELEASE             "-O2 -march=native ${HARDENING_C_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS_NATIVERELEASE    "${HARDENING_LINKER_FLAGS}")

# Format and display the compiler and linker flags
string(TOUPPER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_UPPER)
string(STRIP "${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}" OSH_COMPILER_FLAGS)
string(STRIP "${CMAKE_EXE_LINKER_FLAGS} ${CMAKE_EXE_LINKER_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}" OSH_LINKER_FLAGS)

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Enable hardening: ${ENABLE_HARDENING}")
if (ENABLE_HARDENING)
    message(STATUS "Hardening compiler flags: ${HARDENING_C_FLAGS}")
    message(STATUS "Hardening linker flags: ${HARDENING_LINKER_FLAGS}")
endif()
message(STATUS "Compiler flags: ${OSH_COMPILER_FLAGS}")
message(STATUS "Linker flags: ${OSH_LINKER_FLAGS}")
message(STATUS "Link libraries: ${OSH_LINK_LIBRARIES}")

# CPack variables must be set before including it
include(CPack)
