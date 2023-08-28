#ifndef _OSH_CRYPTO_COMMON_H
#define _OSH_CRYPTO_COMMON_H

#include "memzero.h"
#include <openssl/err.h>

#ifndef osh_openssl_strerror
#define osh_openssl_strerror ERR_error_string(ERR_get_error(), NULL)
#endif

#endif
