#ifndef RAWHTTP_FUZZ_H
#define RAWHTTP_FUZZ_H

#include <stddef.h>

#include "rawhttp_/buf.h"
#include "rawhttp_/error.h"

/*
 * One fuzz payload: a short human-readable label plus the raw bytes to substitute in.
 * Not necessarily printable/text - see the built-in corpus below.
 * */

typedef struct 
{
    const char *label;
    const char *data;
    size_t len;
} rh_fuzz_payload;

/*
 * Built-in default corpus covering the "long values" and "control characters" categories
 * named in this project's spec, plus a few other broadly useful HTTP-fuzzing primitives -
 * CRLF injection is especially relevant given this project's smuggling focus, since a 
 * field that's supposed to be a single header value but isn't properly bounds-checked is
 * exactly the kind of buf that enables request splitting.
 *
 * Returns the number of payloads and sets *out to a pointer with static storage duration 
 * (do not free, do not modify).
 * */
size_t rh_fuzz_default_payloads(const rh_fuzz_payload **out);

/*
 * Replaces every occurrence of `marker` (a NUL-terminated string) in `tmpl` with `payload`/
 * `payload_len`, writing the result to `out` (this function calls rh_buf_init on it).
 * Byte-exact everywhere else - only the marker itself is touched, and it's a plain 
 * byte-substring search, not a regex or template engine, so there's no risk of the marker's
 * replacement being reinterpreted.
 *
 * If `marker` doesn't occur in `tmpl` at all, `out` is just a copy of `tmpl` - not an error
 * since a caller might legitimately want to confirm that (e.g. sanity-checking their own 
 * template).
 * */

rh_err rh_fuzz_apply(const rh_buf *tmpl, const char *marker, const void *payload, size_t payload_len,
        rh_buf *out);

#endif /* RAWHTTP_FUZZ_H */
