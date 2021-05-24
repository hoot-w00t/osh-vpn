#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#ifndef EC_GETLINE_SIZE
#define EC_GETLINE_SIZE (256)
#endif

char *ec_getline(FILE *stream)
{
    int c;
    char *line;
    char *new_ptr;
    size_t line_len;
    size_t ptr_size;

    if (!stream) return NULL;

    if ((c = fgetc(stream)) == EOF)
        return NULL;

    ptr_size = sizeof(char) * EC_GETLINE_SIZE;
    if (!(line = malloc(ptr_size)))
        return NULL;
    memset(line, 0, ptr_size);

    line_len = 0;
    while (c != EOF) {
        ++line_len;
        if (ptr_size <= line_len) {
            ptr_size += sizeof(char) * EC_GETLINE_SIZE;
            if (!(new_ptr = realloc(line, ptr_size)))
                goto fail;
            line = new_ptr;
            memset(line + line_len, 0, ptr_size - line_len);
        }
        line[line_len - 1] = (char) c;

        if (c == '\n') break;
        c = fgetc(stream);
    }
    line[line_len] = '\0';
    return line;

fail:
    free(line);
    return NULL;
}