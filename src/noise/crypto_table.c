#define OSH_NOISE_CRYPTO_TABLE_C_
#include "noise/crypto_table.h"
#include <string.h>

// Don't compile crypto definitions unused by Osh (unless NOISE_SUPPORT_UNUSED_CRYPTO is true)

static const struct noise_cipher_def noise_cipher_table_array[] = {
    {
        .ciph_name = "ChaChaPoly",
        .ciph_type = CIPHER_TYPE_CHACHA20_POLY1305
    },
    {
        .ciph_name = "AESGCM",
        .ciph_type = CIPHER_TYPE_AES_256_GCM
    },

    // array terminator, invalid
    {
        .ciph_name = NULL,
        .ciph_type = _LAST_CIPHER_TYPE
    }
};

static const struct noise_hash_def noise_hash_table_array[] = {
    {
        .hash_name = "SHA256",
        .hash_type = HASH_SHA2_256
    },
    {
        .hash_name = "SHA512",
        .hash_type = HASH_SHA2_512
    },
    {
        .hash_name = "BLAKE2s",
        .hash_type = HASH_BLAKE2S
    },
    {
        .hash_name = "BLAKE2b",
        .hash_type = HASH_BLAKE2B
    },

    // array terminator, invalid
    {
        .hash_name = NULL,
        .hash_type = _HASH_TYPE_LAST
    }
};

static const struct noise_dh_def noise_dh_table_array[] = {
    {
        .dh_name = "25519",
        .dh_type = KEYPAIR_X25519
    },

    // array terminator, invalid
    {
        .dh_name = NULL,
        .dh_type = _KEYPAIR_LAST
    }
};

const struct noise_cipher_def *noise_cipher_table = noise_cipher_table_array;
const struct noise_hash_def *noise_hash_table = noise_hash_table_array;
const struct noise_dh_def *noise_dh_table = noise_dh_table_array;

bool noise_get_cipher_type(const char *ciph_name, cipher_type_t *ciph_type)
{
    for (unsigned int i = 0; noise_cipher_table[i].ciph_name != NULL; ++i) {
        if (!strcmp(ciph_name, noise_cipher_table[i].ciph_name)) {
            *ciph_type = noise_cipher_table[i].ciph_type;
            return true;
        }
    }
    return false;
}

bool noise_get_hash_type(const char *hash_name, hash_type_t *hash_type)
{
    for (unsigned int i = 0; noise_hash_table[i].hash_name != NULL; ++i) {
        if (!strcmp(hash_name, noise_hash_table[i].hash_name)) {
            *hash_type = noise_hash_table[i].hash_type;
            return true;
        }
    }
    return false;
}

bool noise_get_dh_type(const char *dh_name, keypair_type_t *dh_type)
{
    for (unsigned int i = 0; noise_dh_table[i].dh_name != NULL; ++i) {
        if (!strcmp(dh_name, noise_dh_table[i].dh_name)) {
            *dh_type = noise_dh_table[i].dh_type;
            return true;
        }
    }
    return false;
}
