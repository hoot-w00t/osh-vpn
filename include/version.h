#ifndef _OSH_VERSION_H
#define _OSH_VERSION_H

#ifndef OSH_COMMIT_HASH
#include "version_git.h"
#endif

#ifndef OSH_VERSION_STR
#define OSH_VERSION_STR "git-" OSH_COMMIT_HASH
#endif

#define OSH_VERSION_MAJOR (0)
#define OSH_VERSION_MINOR (0)
#define OSH_VERSION_PATCH (1)

#endif