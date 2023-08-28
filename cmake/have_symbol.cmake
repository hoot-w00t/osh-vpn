cmake_minimum_required(VERSION 3.10.0)

include(CheckSymbolExists)

# Define ${variable} as compiler flag in ${cflag} if symbol exists in files
# Checks using check_symbol_exists()
function(add_have_symbol cflag symbol files variable)
    check_symbol_exists(${symbol} ${files} ${variable})
    if (${variable})
        set(${cflag} "${${cflag}} -D${variable}" PARENT_SCOPE)
    endif()
endfunction()
