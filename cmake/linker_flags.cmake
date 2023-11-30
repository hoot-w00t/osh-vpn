cmake_minimum_required(VERSION 3.10.0)

include(CheckLinkerFlag OPTIONAL RESULT_VARIABLE CheckLinkerFlagPath)

if (CheckLinkerFlagPath STREQUAL "NOTFOUND")
    message(WARNING "CheckLinkerFlag was not found")
endif()

# Add ${flag} to ${destvar}
function(add_linker_flag_nocheck destvar flag)
    set(${destvar} "${${destvar}} ${flag}" PARENT_SCOPE)
endfunction()

# Add ${flag} to ${destvar} if the flag is supported by the linker
# All linker flags are considered unsupported if CheckLinkerFlag is not available
function(add_linker_flag destvar flag)
    string(REPLACE "-" "_" checkvar "c_linker${flag}")
    string(REPLACE "=" "_" checkvar "${checkvar}")
    string(REPLACE "," "_" checkvar "${checkvar}")
    string(REPLACE " " "_" checkvar "${checkvar}")
    string(TOLOWER "${checkvar}" checkvar)

    if (CheckLinkerFlagPath STREQUAL "NOTFOUND")
        message(WARNING "Ignoring linker flag ${checkvar}")
    else()
        set(CMAKE_REQUIRED_FLAGS "-Werror")
        check_linker_flag(C "${flag}" ${checkvar})
        if (${checkvar})
            add_linker_flag_nocheck(${destvar} "${flag}")
        endif()
        set(${destvar} "${${destvar}}" PARENT_SCOPE)
    endif()
endfunction()
