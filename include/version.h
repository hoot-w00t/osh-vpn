#ifndef _OSH_VERSION_H
#define _OSH_VERSION_H

#include <stdbool.h>
#include <stddef.h>

extern const unsigned int osh_version_major;
extern const unsigned int osh_version_minor;
extern const unsigned int osh_version_patch;

extern const char *osh_version_str;
extern const char *osh_version_comment;

static inline bool osh_version_has_comment(void)
{
    return osh_version_comment != NULL;
}

#endif