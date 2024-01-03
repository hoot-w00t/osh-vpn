#ifndef OSH_BUFFER_FIXEDBUF_H_
#define OSH_BUFFER_FIXEDBUF_H_

#include "macros_assert.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Simple data structure that just holds a pointer along with its current and
// maximum lengths
// Pointer allocation and lifetime must be checked by the user
struct fixedbuf {
    void *ptr;
    size_t len;
    size_t maxlen;
};

// Initialize struct fixedbuf
static inline void fixedbuf_init(
    struct fixedbuf *buf,
    void *ptr,
    size_t len,
    size_t maxlen)
{
    assert(buf != NULL);
    buf->ptr = ptr;
    buf->len = len;
    buf->maxlen = maxlen;
    assert(buf->maxlen >= buf->len);
}

#define fixedbuf_init_ref(dst, src)             fixedbuf_init(dst, src->ptr, src->len, src->maxlen)
#define fixedbuf_init_empty(buf)                fixedbuf_init(buf, NULL, 0, 0)
#define fixedbuf_init_output(buf, ptr, maxlen)  fixedbuf_init(buf, ptr, 0, maxlen)
#define fixedbuf_init_input(buf, ptr, len)      fixedbuf_init(buf, ptr, len, len)

// Copy len bytes from data pointer to the end of the buffer
// If the buffer doesn't have enough space it is left unchanged and this returns false
__attribute__((warn_unused_result))
static inline bool fixedbuf_append(struct fixedbuf *buf, const void *data, size_t len)
{
    if ((buf->len + len) > buf->maxlen)
        return false;

    assert(buf->ptr != NULL);
    memcpy(((uint8_t *) buf->ptr) + buf->len, data, len);
    buf->len += len;
    return true;
}

// Get next n bytes from buffer pointer starting at *offset
// *offset is incremented by n bytes on success
// This returns NULL if the offset is out of bounds or there is less than n bytes available after
__attribute__((warn_unused_result))
static inline void *fixedbuf_get(struct fixedbuf *buf, size_t *offset, size_t n)
{
    void *retptr;

    assert(offset != NULL);
    if ((*offset + n) > buf->len)
        return NULL;

    assert(buf->ptr != NULL);
    retptr = ((uint8_t *) buf->ptr) + *offset;
    *offset += n;
    return retptr;
}

// Return the remaining bytes from the input buffer starting at offset
// This returns 0 on error
static inline size_t fixedbuf_get_input_remaining_length(const struct fixedbuf *buf, const size_t offset)
{
    return (offset <= buf->len) ? (buf->len - offset) : 0;
}

// Return true if the fixed buffer contains at least 1 byte of data
__attribute__((warn_unused_result))
static inline bool fixedbuf_has_data(const struct fixedbuf *buf)
{
    return buf != NULL
        && buf->ptr != NULL
        && buf->len > 0
        && buf->maxlen >= buf->len;
}

#endif
