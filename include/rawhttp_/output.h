#ifndef RAWHTTP_OUTPUT_H
#define RAWHTTP_OUTPUT_H

#include <stddef.h>

#include "rawhttp_/buf.h"
#include "rawhttp_/error.h"

/*
 * Output-format primitives for T4.3. Kept as pure byte->byte transforms on
 * rh_buf so they're trivially unit-testable and reusable by any mode's
 * renderer (normal client --output json, scan results, etc).
 */

/*
 * Appends `data`/`len` to `out` as the CONTENTS of a JSON string (the
 * surrounding quotes are the caller's job). Escapes per RFC 8259: '"' and
 * '\' are backslash-escaped, the shorthands \b \f \n \r \t are used where
 * they apply, and every other control byte < 0x20 becomes \u00XX. Bytes
 * >= 0x20 (including raw UTF-8 and high bytes) pass through verbatim, which
 * keeps the transform byte-exact and binary-safe for a pentest tool.
 * `out` must already be rh_buf_init'd; this appends, never resets it.
 */
rh_err rh_json_escape(const void *data, size_t len, rh_buf *out);

/*
 * Appends the standard base64 (RFC 4648, '+' '/' alphabet, '=' padding)
 * encoding of `data`/`len` to `out`. No line wrapping. `out` must already
 * be rh_buf_init'd.
 */
rh_err rh_base64_encode(const void *data, size_t len, rh_buf *out);

#endif /* RAWHTTP_OUTPUT_H */
