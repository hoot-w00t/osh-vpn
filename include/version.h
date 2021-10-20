#ifndef _OSH_VERSION_H
#define _OSH_VERSION_H

#ifndef OSH_VERSION_STR
#include "version_git.h"

#define OSH_VERSION_STR "git-" GIT_BRANCH "." GIT_REV_COUNT "." GIT_COMMIT_HASH
#endif

#define OSH_VERSION_MAJOR (0)
#define OSH_VERSION_MINOR (0)
#define OSH_VERSION_PATCH (1)

#endif