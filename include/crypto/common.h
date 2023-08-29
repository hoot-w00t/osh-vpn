#ifndef _OSH_CRYPTO_COMMON_H
#define _OSH_CRYPTO_COMMON_H

#include "memzero.h"
#include "logger.h"
#include <openssl/err.h>

#define osh_openssl_strerror \
    ERR_error_string(ERR_get_error(), NULL)

#define osh_openssl_log_error(ossl_funcname) \
    logger(LOG_ERR, "%s: %s: %s", __func__, ossl_funcname, osh_openssl_strerror)

#endif
