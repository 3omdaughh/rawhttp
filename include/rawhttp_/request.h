#ifndef RAWHTTP_REQUEST_H
#define RAWHTTP_REQUEST_H

#include <stddef.h>

#include "rawhttp_/buf.h"
#include "rawhttp_/error.h"
#include "rawhttp_/url.h"

/*
 * A single request header, as supplied by the caller (e.g. one -H flag).
 * Not owned by request.c - the caller's strings just need to outlive the 
 * rh_request_build() call.
 */

typedef struct
{
    const char *name;
    const char *value;
} rh_request_header;

/*
 * Builds a byte-exact HTTP/1.1 request line + header + body into `out` 
 * (must already be rh_buf_init'd; this function only appends).
 * 
 * Produces:
 * {method} {path} HTTP/1.1\r\n
 * Host: {host}\r\n            (auto-added UNLESS `headers` already has one)
 * Connection: close\r\n       (auto-added UNLESS `headers` already has one)
 * User-Agent: rawhttp/0.1\r\n (auto-added UNLESS `headers` already has one)
 * {each of headers[], verbatim, in the order given}\r\n
 * Content-Length: {body_len}\r\n   (see auto_content_length below)
 * \r\n
 * {body, verbatim}
 *
 * The three auto-added headers are skipped (not duplicated) if the
 * caller already supplied one with the same name (case-insensitive) in
 * `headers` - matching curl's "last one wins by omission" convenience,
 * while still letting the caller fully control the wire bytes by
 * supplying their own.
 *
 * auto_content_length: if true AND body_len > 0 AND the caller hasn't
 * already supplied their own Content-Length header, one is added
 * automatically (normal client convenience). If false, Content-Length
 * is never auto-added regardless of body_len - this is the escape
 * hatch smuggling research needs: pass auto_content_length=0 and supply
 * your own (possibly wrong, possibly duplicated via two entries in
 * `headers`) Content-Length value(s) verbatim. Either way, this
 * function never "fixes" a Content-Length value the caller supplied -
 * it trusts the caller completely, on purpose.
 *
 * `method` is used verbatim, unvalidated - HTTP allows extension
 * methods, and rejecting anything that doesn't look like a "real" verb
 * would get in the way of exactly the kind of testing this tool exists
 * for. Only a NULL/empty method is rejected (RH_ERR_INVAL).
 *
 * The result is NOT null-terminated - use out->data and out->len, never
 * strlen(out->data). This matters later: Phase 3's raw mode 
 * intentionally builds non-standard byte sequences that a 
 * NUL-terminated assumption would silently corrupt/
 */

rh_err rh_request_build(const char *method, const rh_url *url, const rh_request_header *header, size_t header_count, const void *body, size_t body_len, int auto_content_length, rh_buf *out);

/* Convenience wrapper: rh_request_build("GET", url, NULL, 0, NULL, 0, 0, out). */

rh_err rh_request_build_get(const rh_url *url, rh_buf *out);

#endif /* RAWHTTP_REQUEST_H */
