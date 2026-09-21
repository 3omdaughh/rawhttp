#ifndef RAWHTTP_CLIENT_H
#define RAWHTTP_CLIENT_H

#include <stddef.h>

#include "rawhttp_/request.h"
#include "rawhttp_/response.h"
#include "rawhttp_/transport.h"
#include "rawhttp_/url.h"

/*
 * One full protocol-aware request/response round trip against `url`:
 * connect (TLS iff url->scheme == https, honoring socket-layer timeout/proxy
 * config), build + send the request, then read and frame the response body
 * (chunked > Content-Length > read-until-close, the same precedence a real
 * client uses).
 *
 * On RH_OK, *out_resp is fully populated and owned by the caller
 * (rh_response_free it). `out_timing` is optional (NULL to skip). On any
 * error the return code says what failed and *out_resp is left freed/zeroed.
 *
 * This is the shared engine behind both single-URL normal mode and the
 * concurrent scanner, so their behavior can't drift apart.
 */
rh_err rh_client_request(const rh_url *url, const char *method,
                         const rh_request_header *headers, size_t header_count,
                         const void *body, size_t body_len, int insecure,
                         rh_response *out_resp, rh_timing *out_timing);

#endif /* RAWHTTP_CLIENT_H */
