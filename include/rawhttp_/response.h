#ifndef RAWHTTP_RESPONSE_H
#define RAWHTTP_RESPONSE_H

#include <stddef.h>

#include "rawhttp_/buf.h"
#include "rawhttp_/error.h"
#include "rawhttp_/transport.h"

typedef struct
{
    char *name;
    char *value;
} rh_header;

typedef struct 
{
    int status;
    char *reason;

    int http_major;
    int http_minor;

    rh_header *headers;
    size_t header_count;
    size_t header_cap;

    rh_buf body;
} rh_response;

/* Max bytes buffered while searching for the header terminator (\r\n\r\n)
 * before giving up - caps memory use if a server never sends one. */
#define RH_MAX_HEADER_BYTES ((size_t)64 * 1024)

/* Max bytes buffered while searching for the header terminator (\r\n\r\n)
 * before giving up - caps memory use if a server never sends one. */
#define RH_MAX_BODY_BYTES ((size_t)512 * 1024 * 1024)

rh_err rh_response_read_headers(rh_transport *t, rh_buf *raw, rh_response *out, size_t *header_end);

/* Case-insensitive header lookup. Returns NULL if not present. if the 
 * header appers more than once, returns the first occurrence. */
const char *rh_header_get(const rh_response *resp, const char *name);

rh_err rh_response_read_body_length(rh_transport *t, rh_buf *raw, size_t header_end,
                                    rh_response *out, size_t content_length);


rh_err rh_response_read_body_until_close(rh_transport *t, rh_buf *raw, size_t header_end, 
                                        rh_response *out);
void rh_response_free(rh_response *resp);

#endif /* RAWHTTP_RESPONSE_H */
