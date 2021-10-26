cmake_minimum_required(VERSION 3.18.0)
project(osh-vpn
    VERSION 0.0.1
    DESCRIPTION "Experimental mesh VPN"
    HOMEPAGE_URL "https://github.com/hoot-w00t/osh-vpn"
    LANGUAGES "C")

include(CheckCCompilerFlag)
include(CheckLinkerFlag)
include(CTest)

enable_testing()

# Package variables
set(CPACK_PACKAGE_VENDOR "akrocynova")
set(CPACK_VERBATIM_VARIABLES TRUE)

set(CPACK_DEBIAN_PACKAGE_MAINTAINER "${CPACK_PACKAGE_VENDOR}")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libssl1.1")

# Libraries
find_package(OpenSSL REQUIRED)

# easyconf (from the submodule)
set(EASYCONF_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/easyconf")
set(EASYCONF_INCLUDE "${EASYCONF_ROOT}/include")
set(EASYCONF_LIBRARIES "${EASYCONF_ROOT}/libeasyconf.a")

add_custom_target(easyconf
    COMMAND make -C ${EASYCONF_ROOT}
    VERBATIM)

# Header directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include ${EASYCONF_INCLUDE})

# All sources for oshd
set(OSHD_SOURCES
    src/crypto/cipher.c
    src/crypto/hash.c
    src/crypto/pkey.c
    src/events/automatic_connections.c
    src/events/connect.c
    src/events/expire_endpoints.c
    src/events/expire_routes_refresh.c
    src/events/node_auth_timeout.c
    src/events/periodic_ping.c
    src/aio.c
    src/endpoints.c
    src/events.c
    src/logger.c
    src/main.c
    src/netaddr.c
    src/netbuffer.c
    src/netpacket.c
    src/node.c
    src/oshd_clock.c
    src/oshd_cmd.c
    src/oshd_conf.c
    src/oshd_device.c
    src/oshd_discovery.c
    src/oshd_process_packet.c
    src/oshd_resolver.c
    src/oshd_route.c
    src/oshd_socket.c
    src/oshd.c
    src/oshpacket.c
    src/random.c
    src/tcp.c
    src/tuntap.c
    src/xalloc.c
)

# All sources for oshd_tests
set(OSHD_TESTS_SOURCES
    src/logger.c
    src/xalloc.c
    src/netaddr.c
    src/netbuffer.c
    src/random.c
    tests/netaddr_tests.c
    tests/netbuffer_tests.c
    tests/random_tests.c)

# Osh daemon
add_executable(oshd ${OSHD_SOURCES})
add_dependencies(oshd easyconf)
target_link_libraries(oshd ${EASYCONF_LIBRARIES} ${OPENSSL_LIBRARIES})

# Criterion unit tests
if (ENABLE_UNIT_TESTS)
    message(STATUS "Unit tests enabled")

    find_library(CRITERION_FOUND criterion REQUIRED)
    add_executable(oshd_tests ${OSHD_TESTS_SOURCES})
    target_link_libraries(oshd_tests criterion)

    add_test(NAME unit_tests COMMAND ./oshd_tests)
else()
    message(STATUS "Unit tests disabled")
endif()

# Always keep the git version up to date
set(VERSION_GIT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/include/version_git.h")
add_custom_target(version_git
    COMMAND ${CMAKE_COMMAND} -Droot_dir=${CMAKE_CURRENT_SOURCE_DIR}
                             -Ddest_file=${VERSION_GIT_FILE}
                             -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/version_git.cmake
    DEPENDS ${VERSION_GIT_FILE}.in
    BYPRODUCTS ${VERSION_GIT_FILE}
    VERBATIM)
add_dependencies(oshd version_git)

# Installation rules
install(TARGETS oshd RUNTIME)

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wshadow -Wformat-security")

check_c_compiler_flag("-Wformat-signedness" cc_warn_format_signedness)
if (cc_warn_format_signedness)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wformat-signedness")
endif()

check_c_compiler_flag("-pipe" cc_pipe)
if (cc_pipe)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pipe")
endif()

if (CYGWIN)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE")
endif()

# Linker flags
check_linker_flag(C "-z relro" ld_z_relro)
if (ld_z_relro)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -z relro")
endif()

check_linker_flag(C "-z now" ld_z_now)
if (ld_z_now)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -z now")
endif()

# If no build type was specified we will use the default
set(default_build_type "Debug")
if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "No build type was specified, defaulting to '${default_build_type}'")
    set(CMAKE_BUILD_TYPE "${default_build_type}")
endif()

# Build type flags
set(CMAKE_C_FLAGS_DEBUG "-O0 -g3")
set(CMAKE_C_FLAGS_MINSIZEREL "-Os")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g")
set(CMAKE_C_FLAGS_RELEASE "-O2")
set(CMAKE_C_FLAGS_HARDENED "-O2 -g -fstack-protector-strong -D_FORTIFY_SOURCE=2")

# Format and display the compiler and linker flags
string(TOUPPER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_UPPER)
string(STRIP "${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}" OSH_COMPILER_FLAGS)
string(STRIP "${CMAKE_EXE_LINKER_FLAGS} ${CMAKE_EXE_LINKER_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}" OSH_LINKER_FLAGS)

message(STATUS "Compiler flags: ${OSH_COMPILER_FLAGS}")
message(STATUS "Linker flags: ${OSH_LINKER_FLAGS}")

# CPack variables must be set before including it
include(CPack)