#include "base64.h"
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

static const uint8_t b64_pad_table[3] = {0, 2, 1};

// Encodes input_size bytes from input to output in Base64
// The output buffer must be able to hold at least BASE64_ENCODE_OUTSIZE bytes
// The exact size of the output buffer can be calculated with the
// BASE64_ENCODE_EXACTSIZE macro
void base64_encode(char *output, const void *input, size_t input_size)
{
    uint8_t b0, b1, b2;
    uint32_t word;
    size_t i = 0, j = 0;

    while (i < input_size) {
        // Copy the next 3 bytes (we don't need to check the index for the
        // first byte because it's tested in the loop condition)
        b0 = ((uint8_t *) input)[i++];
        b1 = (i < input_size) ? ((uint8_t *) input)[i++] : 0;
        b2 = (i < input_size) ? ((uint8_t *) input)[i++] : 0;

        // Merge the 3 bytes into a 24-bit word
        word = (b0 << 16) | (b1 << 8) | (b2 << 0);

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
}

// Decodes Base64 input to output, returns true on success
// *output_size is set to the number of bytes written to output
// The output buffer must be able to hold at least BASE64_DECODE_OUTSIZE bytes
// The input size does not include the terminating NUL byte
bool base64_decode(void *output, size_t *output_size, const char *input,
    size_t input_size)
{
    uint8_t b64_dtable[256], b[4];
    size_t i, j;

    // Base64 strings must be aligned on 4 bytes
    if ((input_size % 4) != 0)
        return false;

    // Create the decoding table
    memset(b64_dtable, 0x80, sizeof(b64_dtable));
    for (i = 0; i < sizeof(b64_table); ++i)
        b64_dtable[(unsigned) b64_table[i]] = i;
    b64_dtable[(unsigned) '='] = 0x40;

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
    return true;
}