#ifndef _OSH_MACROS_H
#define _OSH_MACROS_H

#include <errno.h>

#define IO_WOULDBLOCK(err) ((err) == EAGAIN || (err) == EWOULDBLOCK)

#endif