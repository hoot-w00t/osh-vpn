#include "macros_windows.h"
#include <stdio.h>

// Equivalent to strerror()
// The returned pointer is a static char array
const char *win_strerror(DWORD errcode)
{
    static char errfmt[256];
    static char errstr[sizeof(errfmt) + 32];
    DWORD fmterr;

    fmterr = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, errcode, 0,
        errfmt, sizeof(errfmt), NULL);

    if (fmterr) {
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

    if (fmterr) {
        snprintf(errstr, sizeof(errstr), "%s (code %lu)", errfmt, errcode);
    } else {
        snprintf(errstr, sizeof(errstr), "Error code %lu (FormatMessage failed with %lu)",
            errcode, GetLastError());
    }
    return errstr;
}
