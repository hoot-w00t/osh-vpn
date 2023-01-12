#ifndef _OSH_MACROS_WINDOWS_H
#define _OSH_MACROS_WINDOWS_H

#include "macros.h"

#if PLATFORM_IS_WINDOWS
#include <windows.h>
#include <winerror.h>

const char *win_strerror(DWORD errcode);
#define win_strerror_last() win_strerror(GetLastError())
#endif

#endif
