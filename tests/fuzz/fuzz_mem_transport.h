#ifndef RAWHTTP_FUZZ_MEM_TRANSPORT_H
#define RAWHTTP_FUZZ_MEM_TRANSPORT_H

/*
 * A rh_transport backed by a fixed in-memory buffer, for driving the wire
 * parsers (response/chunked) off fuzzer input instead of a real socket.
 *
 * read() hands back the buffer in small slices (<= MEM_SLICE bytes) so the
 * incremental reassembly paths - the ones that loop on rh_recv_some() waiting
 * for a CRLF or N more bytes - are exercised, not bypassed by one giant read.
 * write() is a sink, close()/get_fd() are inert.
 */

#include <string.h>

#include "rawhttp_/transport.h"

#define MEM_SLICE 13

typedef struct
{
    const unsigned char *data;
    size_t len;
    size_t pos;
} mem_ctx;

static rh_err mem_read(rh_transport *t, void *buf, size_t len, size_t *out_n)
{
    mem_ctx *c = (mem_ctx *)t->ctx;
    if (c->pos >= c->len) { *out_n = 0; return RH_OK; } /* EOF */

    size_t avail = c->len - c->pos;
    size_t n = len < avail ? len : avail;
    if (n > MEM_SLICE) n = MEM_SLICE;

    memcpy(buf, c->data + c->pos, n);
    c->pos += n;
    *out_n = n;
    return RH_OK;
}

static rh_err mem_write(rh_transport *t, const void *buf, size_t len, size_t *out_n)
{
    (void)t; (void)buf;
    *out_n = len;
    return RH_OK;
}

static void mem_close(rh_transport *t) { (void)t; }

static void mem_transport_init(rh_transport *t, mem_ctx *c,
                               const unsigned char *data, size_t len)
{
    memset(t, 0, sizeof(*t));
    c->data = data;
    c->len  = len;
    c->pos  = 0;
    t->ctx   = c;
    t->read  = mem_read;
    t->write = mem_write;
    t->close = mem_close;
    t->get_fd = NULL; /* forces recv_until_idle's single-read fallback; unused here */
}

#endif /* RAWHTTP_FUZZ_MEM_TRANSPORT_H */
