#include "rawhttp_/chunked.h"
#include "rawhttp_/internal.h"
#include "rawhttp_/io.h"

static rh_err ensure_line(rh_transport *t, rh_buf *raw, size_t line_start, size_t max_scan, size_t *line_end_out)
{
    for (;;)
    {
        size_t found = (size_t)-1;
        if (raw->len >= line_start+2)
            for (size_t i = line_start; i+1 < raw->len; i++)
                if (raw->data[i] == '\r' && raw->data[i+1] == '\n')
                {
                    found = i;
                    break;
                }
        if (found != (size_t)-1)
        {
            *line_end_out = found;
            return RH_OK;
        }
        if (raw->len - line_start > max_scan) return RH_ERR_LIMIT;
        int eof = 0;
        rh_err e = rh_recv_some(t, raw, &eof);
        if (e != RH_OK) return e;
        if (eof) return RH_ERR_PARSE;
    }
}

static rh_err ensure_bytes(rh_transport *t, rh_buf *raw, size_t need_total_len)
{
    while (raw->len < need_total_len)
    {
        int eof = 0;
        rh_err e = rh_recv_some(t, raw, &eof);
        if (e != RH_OK) return e;
        if (eof) return RH_ERR_IO;
    }
    return RH_OK;
}

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

rh_err rh_chunked_decode(rh_transport *t, rh_buf *raw, size_t *cursor, rh_response *out)
{
    if (!raw || !cursor || !out) return RH_ERR_INVAL;

    rh_err e = rh_buf_init(&out->body, 0);
    if (e != RH_OK) return e;

    size_t total_body = 0;

    /* -- chunk loop: size-line, data, CRLF, repeat until size 9 -- */

    for (;;)
    {
        size_t line_start = *cursor;
        size_t line_end;
        e = ensure_line(t, raw, line_start, RH_MAX_CHUNK_LINE_BYTES, &line_end);
        if(e != RH_OK) goto fail;

        size_t i = line_start;
        if (i >= line_end || hex_val(raw->data[i]) < 0)
        {
            LOG_DEBUG("[!] chunked: chunk size line has no leading hex digit");
            e = RH_ERR_PARSE;
            goto fail;
        }

        size_t chunk_size = 0;
        size_t digit_count = 0;
        while (i < line_end && hex_val(raw->data[i]) >= 0)
        {
            if (digit_count >= 16)
            {
                LOG_DEBUG("[!] chunked: chunk size has absurd digit count");
                e = RH_ERR_LIMIT;
                goto fail;
            }
            chunk_size = chunk_size*16+(size_t)hex_val(raw->data[i]);
            digit_count++;
            i++;
        }

        if (i < line_end && raw->data[i] != ';')
        {
            LOG_DEBUG("[!] chunked: junk after chunk-size, not a ';' chunk-ext");
            e = RH_ERR_PARSE;
            goto fail;
        }

        if (chunk_size > RH_MAX_CHUNK_SIZE)
        {
             LOG_DEBUG("[!] chunked: chunk size %zu exceeds RH_MAX_CHUNK_SIZE", chunk_size);
             e = RH_ERR_LIMIT;
             goto fail;
        }

        size_t data_start = line_end + 2; /* skip the size-line's CRLF */

        if (chunk_size == 0) 
        {
            *cursor = data_start; 
            break;
        }

        total_body += chunk_size;
        if (total_body > RH_MAX_BODY_BYTES)
        {
            LOG_DEBUG("[!] chunked: running total %zu exceeds RH_MAX_BODY_BYTES", total_body);
            e = RH_ERR_LIMIT;
            goto fail;
        }

        size_t need_end = data_start+chunk_size+2;
        e = ensure_bytes(t, raw, need_end);
        if (e != RH_OK) goto fail;

        if (raw->data[data_start+chunk_size] != '\r' || 
            raw->data[data_start+chunk_size+1] != '\n')
        {
            LOG_DEBUG("[!] chunked: missing CRLF after chunk data (bad length?)");
            e = RH_ERR_PARSE;
            goto fail;
        }

        e = rh_buf_append(&out->body, raw->data+data_start, chunk_size);
        if (e != RH_OK) goto fail;

        *cursor = need_end;
    }

    /* -- trailer section: zero or more header lines then a blank line -- */

    for (;;)
    {
        size_t line_start = *cursor;
        size_t line_end;
        e = ensure_line(t, raw, line_start, RH_MAX_HEADER_BYTES, &line_end);
        if (e != RH_OK) goto fail;

        if (line_end == line_start)
        {
            *cursor = line_end+2; // blank line - trailer section done
            break;
        }

        e = rh__parse_header_line(raw->data+line_start, line_end-line_start, out);
        if (e != RH_OK) goto fail;

        *cursor = line_end+2;
    }

    return RH_OK;

fail:
    rh_buf_free(&out->body);
    return e;
}
