cmake_minimum_required(VERSION 3.10.0)

include(CheckCCompilerFlag)

# Add ${flag} to ${destvar}
function(add_compiler_flag_nocheck destvar flag)
    set(${destvar} "${${destvar}} ${flag}" PARENT_SCOPE)
endfunction()

# Add ${ARGN} flags to ${destvar}
function(add_compiler_flags_nocheck destvar)
    foreach(flag ${ARGN})
        add_compiler_flag_nocheck(${destvar} "${flag}")
    endforeach()
    set(${destvar} "${${destvar}}" PARENT_SCOPE)
endfunction()

# Add ${flag} to ${destvar} if the flag is supported by the compiler
function(add_compiler_flag destvar flag)
    string(REPLACE "-" "_" checkvar "cflag${flag}")
    string(REPLACE "=" "_" checkvar "${checkvar}")
    string(REPLACE "," "_" checkvar "${checkvar}")
    string(REPLACE " " "_" checkvar "${checkvar}")
    string(TOLOWER "${checkvar}" checkvar)

    set(CMAKE_REQUIRED_FLAGS "-Werror")
    check_c_compiler_flag("${flag}" ${checkvar})
    if (${checkvar})
        add_compiler_flag_nocheck(${destvar} "${flag}")
    endif()
    set(${destvar} "${${destvar}}" PARENT_SCOPE)
endfunction()

# Add ${ARGN} flags to ${destvar} if the flags are supported by the compiler
function(add_compiler_flags destvar)
    foreach(flag ${ARGN})
        add_compiler_flag(${destvar} "${flag}")
    endforeach()
    set(${destvar} "${${destvar}}" PARENT_SCOPE)
endfunction()
