/*
 * libFuzzer target for the full response read path: status line + header
 * block parsing (response.c) followed by body framing - chunked (chunked.c),
 * Content-Length, or read-until-close - exactly as the real client picks it.
 *
 * Build: `make fuzz` (clang + libFuzzer). Replay a corpus without clang:
 * `make fuzz-replay && ./build/fuzz/fuzz_response tests/fuzz/corpus/response/*`
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "rawhttp_/chunked.h"
#include "rawhttp_/response.h"
#include "rawhttp_/io.h"

#include "fuzz_mem_transport.h"

static int header_is(const char *v, const char *want)
{
    if (!v) return 0;
    for (; *v && *want; v++, want++)
    {
        char a = *v, b = *want;
        if (a >= 'A' && a <= 'Z') a += 32;
        if (b >= 'A' && b <= 'Z') b += 32;
        if (a != b) return 0;
    }
    return *v == '\0' && *want == '\0';
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    rh_transport t;
    mem_ctx c;
    mem_transport_init(&t, &c, data, size);

    rh_buf raw;
    if (rh_buf_init(&raw, 0) != RH_OK) return 0;

    rh_response resp;
    size_t header_end;
    rh_err e = rh_response_read_headers(&t, &raw, &resp, &header_end);
    if (e != RH_OK)
    {
        rh_buf_free(&raw);
        return 0;
    }

    const char *te = rh_header_get(&resp, "Transfer-Encoding");
    const char *cl = rh_header_get(&resp, "Content-Length");

    if (te && header_is(te, "chunked"))
    {
        size_t cursor = header_end;
        rh_chunked_decode(&t, &raw, &cursor, &resp);
    }
    else if (cl)
    {
        /* trust the parser's own numeric handling downstream; cap via strtoull */
        char *end = NULL;
        unsigned long long n = strtoull(cl, &end, 10);
        if (end && *end == '\0' && end != cl)
            rh_response_read_body_content_length(&t, &raw, header_end, &resp, (size_t)n);
    }
    else
    {
        rh_response_read_body_until_close(&t, &raw, header_end, &resp);
    }

    rh_response_free(&resp);
    rh_buf_free(&raw);
    return 0;
}
