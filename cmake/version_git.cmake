cmake_minimum_required(VERSION 3.10.0)

find_package(Git QUIET)

# Default values if we cannot fetch those
set(GIT_COMMIT_HASH "unknown")
set(GIT_REV_COUNT "unknown")
set(GIT_BRANCH "unknown")
set(GIT_UNKNOWN 1)

# Fetch revision information from git
if (GIT_FOUND AND EXISTS "${root_dir}/.git")
    # Fetch head commit hash
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" rev-parse --short=10 HEAD
        WORKING_DIRECTORY "${root_dir}"
        OUTPUT_VARIABLE GIT_COMMIT_HASH
        OUTPUT_STRIP_TRAILING_WHITESPACE)

    # Fetch head revision count
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" rev-list --count HEAD
        WORKING_DIRECTORY "${root_dir}"
        OUTPUT_VARIABLE GIT_REV_COUNT
        OUTPUT_STRIP_TRAILING_WHITESPACE)

    # Fetch the current branch
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" rev-parse --abbrev-ref HEAD
        WORKING_DIRECTORY "${root_dir}"
        OUTPUT_VARIABLE GIT_BRANCH
        OUTPUT_STRIP_TRAILING_WHITESPACE)

    # Git revision information is not unknown
    set(GIT_UNKNOWN 0)
endif()

# Define the cache string
# This string has to be in the destination file, it is used to know when to
# reconfigure the destination file (only after changing branches or committing)
set(GIT_CACHE_STR "gitcache-${GIT_BRANCH}.r${GIT_REV_COUNT}.${GIT_COMMIT_HASH}")

# If this is 0, the destination file is already up to date
# If this is 1, the destination file either doesn't exist or is outdated and
# has to be (re)generated
set(GIT_UPDATE_FILE 0)

# Read the destination file if it exists, otherwise force the configuration to
# create it
if (EXISTS "${dest_file}")
    message(VERBOSE "${dest_file}: reading its contents")
    file(READ "${dest_file}" GIT_DEST_FILE_CONTENTS)

    # Try to find the cache string in the file
    message(VERBOSE "${dest_file}: searching for the cache string (${GIT_CACHE_STR})")
    string(FIND "${GIT_DEST_FILE_CONTENTS}" "${GIT_CACHE_STR}" GIT_CACHE_FOUND)

    # If the cache string was not found we need to update the file
    if (${GIT_CACHE_FOUND} EQUAL -1)
        message(VERBOSE "Cache string was not found, forcing update")
        set(GIT_UPDATE_FILE 1)
    else ()
        message(VERBOSE "Cache string was found, no update is necessary")
    endif ()
else ()
    message(VERBOSE "${dest_file} does not exist, forcing update")
    set(GIT_UPDATE_FILE 1)
endif ()

if (${GIT_UPDATE_FILE} EQUAL 1)
    message(STATUS "Updating ${dest_file} with commit ${GIT_COMMIT_HASH}")
    configure_file(${src_file} ${dest_file} @ONLY)
endif ()
