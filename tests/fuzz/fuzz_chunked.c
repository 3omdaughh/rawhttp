/*
 * libFuzzer target for the chunked transfer-encoding decoder in isolation
 * (chunked.c): the whole fuzzer input is treated as a chunk stream - size
 * lines, chunk data, the terminating 0-chunk, and trailers.
 *
 * Build: `make fuzz` (clang + libFuzzer). Replay without clang:
 * `make fuzz-replay && ./build/fuzz/fuzz_chunked tests/fuzz/corpus/chunked/*`
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "rawhttp_/chunked.h"
#include "rawhttp_/response.h"

#include "fuzz_mem_transport.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    rh_transport t;
    mem_ctx c;
    mem_transport_init(&t, &c, data, size);

    rh_buf raw;
    if (rh_buf_init(&raw, 0) != RH_OK) return 0;

    rh_response resp;
    memset(&resp, 0, sizeof(resp));

    size_t cursor = 0;
    rh_chunked_decode(&t, &raw, &cursor, &resp);
    /* free unconditionally: rh_response_free is safe on a zeroed/partial resp
     * and reclaims any trailer headers pushed before a mid-stream failure. */
    rh_response_free(&resp);

    rh_buf_free(&raw);
    return 0;
}
