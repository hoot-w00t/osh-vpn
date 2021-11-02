#ifndef _OSH_VERSION_H
#define _OSH_VERSION_H

#ifndef OSH_VERSION_STR
#include "version_git.h"

#define OSH_VERSION_STR "git-" GIT_BRANCH "." GIT_REV_COUNT "." GIT_COMMIT_HASH
#endif

#define OSH_VERSION_MAJOR (0)
#define OSH_VERSION_MINOR (0)
#define OSH_VERSION_PATCH (1)

#define OSH_VERSION_FMT "oshd %i.%i.%i (" OSH_VERSION_STR ")"
#define OSH_VERSION_FMT_ARGS \
    OSH_VERSION_MAJOR, OSH_VERSION_MINOR, OSH_VERSION_PATCH

#endif