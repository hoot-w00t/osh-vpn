#ifndef OSH_NOISE_CRYPTO_TABLE_H_
#define OSH_NOISE_CRYPTO_TABLE_H_

#include "crypto/cipher.h"
#include "crypto/hash.h"
#include "crypto/keypair.h"
#include <stdbool.h>

// Some crypto functions are supported and were implemented for testing but are
// not actually used by Osh
// Their support can be enabled by defining NOISE_SUPPORT_UNUSED_CRYPTO to 1

struct noise_cipher_def {
    const char *ciph_name;
    cipher_type_t ciph_type;
};

struct noise_hash_def {
    const char *hash_name;
    hash_type_t hash_type;
};

struct noise_dh_def {
    const char *dh_name;
    keypair_type_t dh_type;
};

#ifndef OSH_NOISE_CRYPTO_TABLE_C_
    extern const struct noise_cipher_def *noise_cipher_table;
    extern const struct noise_hash_def *noise_hash_table;
    extern const struct noise_dh_def *noise_dh_table;
#endif

bool noise_get_cipher_type(const char *ciph_name, cipher_type_t *ciph_type);
bool noise_get_hash_type(const char *hash_name, hash_type_t *hash_type);
bool noise_get_dh_type(const char *dh_name, keypair_type_t *dh_type);

#endif
