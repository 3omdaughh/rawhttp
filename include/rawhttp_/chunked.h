#ifndef RAWHTTP_CHUNKED_H
#define RAWHTTP_CHUNKED_H

#include <stddef.h>

#include "buf.h"
#include "error.h"
#include "response.h"

#define RH_MAX_CHUNK_LINE_BYTES ((size_t)1024)
#define RH_MAX_CHUNK_SIZE ((size_t)64*1024*1024)

/* On any failure, out->body is freed before returning so the caller 
 * never has to guess whether cleanup is needed.
 */

rh_err rh_chunked_decode(rh_transport *t, rh_buf *raw, size_t *cursor, rh_response *out);

#endif /* RAWHTTP_CHUNKED_H  */
