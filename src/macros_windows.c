#include "macros_windows.h"
#include <stdio.h>

#define is_newline(x) ((x) == '\n' || (x) == '\r')
#define errfmt_maxlen 256

// Equivalent to strerror()
// The returned pointer is a static char array, this function is not thread-safe
const char *win_strerror(DWORD errcode)
{
    static char errstr[errfmt_maxlen + 32];
    char errfmt[errfmt_maxlen];
    DWORD fmterr;

    fmterr = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, errcode, 0,
        errfmt, sizeof(errfmt), NULL);

    if (fmterr) {
        // Remove all newlines at the end of the error string
        size_t errfmt_len = strlen(errfmt);

        while (errfmt_len > 0 && is_newline(errfmt[errfmt_len - 1])) {
            errfmt_len -= 1;
            errfmt[errfmt_len] = '\0';
        }
    }

    if (fmterr) {
        snprintf(errstr, sizeof(errstr), "%s (code %lu)", errfmt, errcode);
    } else {
        snprintf(errstr, sizeof(errstr), "Error code %lu (FormatMessageA failed with %lu)",
            errcode, GetLastError());
    }
    return errstr;
}
