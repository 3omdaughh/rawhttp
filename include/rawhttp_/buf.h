#ifndef RAWHTTP_BUF_H
#define RAWHTTP_BUF_H

#include <stddef.h>
#include "rawhttp_/error.h"

/*
 * Growable byte buffer. Not null-terminated by convention - callers must use
 * `len`, never strlen()/assume a trailing NUL. This matters because HTTP
 * bodies and raw request bytes can legitimately contain '\0'.
 */

typedef struct
{
    char *data;
    size_t len; /* bytes currently held */
    size_t cap; /* allocated capacity  */
} rh_buf;

rh_err rh_buf_init(rh_buf *b, size_t initial_cap);

rh_err rh_buf_append(rh_buf *b, const char *data, size_t n);

void rh_buf_free(rh_buf *b);

#endif /* RAWHTTP_BUF_H */
