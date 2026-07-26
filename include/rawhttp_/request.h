#ifndef RAWHTTP_REQUEST_H
#define RAWHTTP_REQUEST_H

#include "rawhttp_/buf.h"
#include "rawhttp_/error.h"
#include "rawhttp_/url.h"

/*
 * Builds a minimal, byte-exact HTTP/1.1 GET request into `out` (must
 * already be rh_buf_init'd by the caller; this function only appends).
 *
 * Produces exactly:
 *   GET {path} HTTP/1.1\r\n
 *   Host: {host}\r\n
 *   Connection: close\r\n
 *   User-Agent: rawhttp/0.1\r\n
 *   \r\n
 *
 * The result is NOT null-terminated - use out->data and out->len, never
 * strlen(out->data). This matters later: Phase 3's raw/custom-header modes
 * intentionally build non-standard byte sequences that a NUL-terminated
 * assumption would silently corrupt.
 */

rh_err rh_request_build_get(const rh_url *url, rh_buf *out);

#endif /* RAWHTTP_REQUEST_H */
