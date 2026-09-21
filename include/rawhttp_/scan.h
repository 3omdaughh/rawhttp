#ifndef RAWHTTP_SCAN_H
#define RAWHTTP_SCAN_H

#include <stddef.h>

#include "rawhttp_/error.h"

/*
 * One target's outcome. `url` is borrowed from the caller's array (not
 * owned). When `err != RH_OK` the request failed and status/len/timing are
 * meaningless; otherwise they carry the parsed result.
 */
typedef struct
{
    const char *url;
    rh_err  err;
    int     status;
    size_t  body_len;
    double  ttfb_ms;
    double  total_ms;
} rh_scan_result;

/*
 * Fetches every URL in `urls[0..count)` concurrently with up to
 * `concurrency` worker threads (clamped to [1, count]), each doing a plain
 * GET via rh_client_request(). Honors the socket-layer timeout/proxy config.
 *
 * `results_out` must point to `count` writable entries; entry i corresponds
 * to urls[i] regardless of completion order, so the caller can print in
 * input order. Returns RH_OK once all workers have joined (individual target
 * failures are recorded per-entry, not returned), or RH_ERR_* if the thread
 * pool itself could not be set up.
 */
rh_err rh_scan_run(char **urls, size_t count, int insecure, int concurrency,
                   rh_scan_result *results_out);

#endif /* RAWHTTP_SCAN_H */
