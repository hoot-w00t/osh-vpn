#include "macros_windows.h"
#include <stdio.h>

// Equivalent to strerror()
// The returned pointer is a static char array
const char *win_strerror(DWORD errcode)
{
    static char errstr[256];

    if (!FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, errcode, 0,
        errstr, sizeof(errstr), NULL))
    {
        snprintf(errstr, sizeof(errstr), "Error code %u (FormatMessage failed with %u)",
            errcode, GetLastError());
    } else {
        // Remove the newline at the end of the error string
        // TODO: There could be a better way of doing this, this is very ugly
        size_t errstr_len = strlen(errstr);

        if (   errstr_len > 0
            && (errstr[errstr_len - 1] == '\n' || errstr[errstr_len - 1] == '\r'))
        {
            errstr[errstr_len - 1] = '\0';
            errstr_len -= 1;
            if (   errstr_len > 0
                && (errstr[errstr_len - 1] == '\n' || errstr[errstr_len - 1] == '\r'))
            {
                errstr[errstr_len - 1] = '\0';
                errstr_len -= 1;
            }
        }
    }
    return errstr;
}
