#include "base64.h"
#include "memzero.h"
#include <string.h>

static const char b64_table[64] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/'
};

static const uint8_t b64_dtable[256] = {
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x3E, 0x80, 0x80, 0x80, 0x3F,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
    0x3C, 0x3D, 0x80, 0x80, 0x80, 0x40, 0x80, 0x80,
    0x80, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
    0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
    0x31, 0x32, 0x33, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
};

static const uint8_t b64_pad_table[3] = {0, 2, 1};

// Encodes input_size bytes from input to output in Base64
// The output buffer must be able to hold at least BASE64_ENCODE_OUTSIZE bytes
// The exact size of the output buffer can be calculated with the
// BASE64_ENCODE_EXACTSIZE macro
void base64_encode(char *output, const void *input, size_t input_size)
{
    uint8_t b[3];
    uint32_t word;
    size_t i = 0, j = 0;

    while (i < input_size) {
        // Copy the next 3 bytes (we don't need to check the index for the
        // first byte because it's tested in the loop condition)
        b[0] = ((const uint8_t *) input)[i++];
        b[1] = (i < input_size) ? ((const uint8_t *) input)[i++] : 0;
        b[2] = (i < input_size) ? ((const uint8_t *) input)[i++] : 0;

        // Merge the 3 bytes into a 24-bit word
        word = (b[0] << 16) | (b[1] << 8) | (b[2] << 0);

        // Write the encoded characters               // Groups of 6 bits
        output[j++] = b64_table[(word >> 18) & 0x3F]; // x___
        output[j++] = b64_table[(word >> 12) & 0x3F]; // _x__
        output[j++] = b64_table[(word >>  6) & 0x3F]; // __x_
        output[j++] = b64_table[(word >>  0) & 0x3F]; // ___x
    }

    // Don't forget the terminating NUL byte
    output[j] = 0;

    // Write padded characters when input size is not a multiple of 3
    for (size_t k = b64_pad_table[input_size % 3]; k > 0; --k)
        output[--j] = '=';

    // Zero temporary buffers securely (they could contain parts of sensitive
    // data like private keys)
    memzero(b, sizeof(b));
    memzero(&word, sizeof(word));
}

// Decodes Base64 input to output, returns true on success
// *output_size is set to the number of bytes written to output
// The output buffer must be able to hold at least BASE64_DECODE_OUTSIZE bytes
// The input size does not include the terminating NUL byte
bool base64_decode(void *output, size_t *output_size, const char *input,
    size_t input_size)
{
    uint8_t b[4];
    size_t i, j;

    // Base64 strings must be aligned on 4 bytes
    if ((input_size % 4) != 0)
        return false;

    // Decode Base64 string in blocks of 4 characters
    for (i = 0, j = 0; i < input_size; i += 4) {
        // Get the 6 bit values for the 4 characters
        for (int k = 0; k < 4; ++k)
            b[k] = b64_dtable[(unsigned) input[i + k]];

        // Invalid characters (padding is invalid for the first two characters)
        if ((b[0] & 0xC0) || (b[1] & 0xC0) || (b[2] & 0x80) || (b[3] & 0x80))
            return false;

        // First byte (cannot be padded)
        ((uint8_t *) output)[j++] =   ((b[0] & 0x3F) << 2)
                                    | ((b[1] & 0x30) >> 4);

        // Second byte
        // If the third character is padded we've reached the end
        if (b[2] & 0x40)
            break;
        ((uint8_t *) output)[j++] =   ((b[1] & 0x0F) << 4)
                                    | ((b[2] & 0x3C) >> 2);

        // Third byte
        // If the fourth character is padded we've reached the end
        if (b[3] & 0x40)
            break;
        ((uint8_t *) output)[j++] =   ((b[2] & 0x03) << 6)
                                    | ((b[3] & 0x3F) >> 0);
    }
    *output_size = j;

    // Zero temporary buffers securely (they could contain parts of sensitive
    // data like private keys)
    memzero(b, sizeof(b));

    return true;
}
