#include "rawhttp_/response.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "rawhttp_/internal.h"
#include "rawhttp_/io.h"

static char *dup_range(const char *s, size_t n)
{
    char *out = malloc(n+1);
    if (!out) return NULL;
    memcpy(out, s, n);
    out[n]='\0';
    return out;
}

static int ci_eq(const char *a, const char *b)
{
    while (*a && *b)
    {
        if (tolower((unsigned char)*a != tolower(unsigned char)*b)) return 0;
        a++; b++;
    }
    return *a == '\0' && *b == '\0';
}

/* Locates the header/body boundary "\r\n\r\n" in data[0..len). Returns
 * the offset of the first '\r', or (size_t)-1 if not present. */
static size_t find_crlfcrlf(const char *data, size_t len)
{
    if (len < 4) return (size_t)-1;
    for (size_t i = 0; i+3 < len; i++)
        if (data[i] == '\r' && data[i+1] == '\n' && data[i+2] == '\r' && data[i+3] == '\n') return i;
    return (size_t)-1;
}

rh_err rh__headers_push(rh_response *out, char *name, char *value)
{
    if (out->header_count == out->header_cap)
    {
        size_t new_cap = out->header_cap ? out->header_cap*2 : 8;
        rh_header *new_arr = realloc(out->headers, new_cap * sizeof(rh_header));
        if (!new_arr)
        {
            free(name);
            free(value);
            return RH_ERR_MEM;
        }
        out->headers = new_arr;
        out->header_cap = new_cap;
    }
    out->headers[out->header_count].name = name;
    out->headers[out->header_count].value = value;
    out->header_count++;
    return RH_OK;
}

/* Splits one header line "Name: value" (no CRLF included) and pushes it.
 *
 * Deliberately STRICT about whitespace between the field-name and the
 * colon (e.g. "Foo : bar") - RFC 7230 forbids it precisely because
 * different parsers disagree on how to handle it, which is exploitable
 * for request/response smuggling. Rather than silently tolerating it
 * like a "helpful" library would, this parser rejects it, which also
 * means it will faithfully surface such bytes as a parse error if you
 * hand it something malformed rather than guessing at intent. */

rh_err rh__parse_header_line(const char *line, size_t len, rh_response *out)
{
    size_t colon = (size_t)-1;
    for (size_t i = 0; i < len; i++)
        if (line[i] == ':')
        {
            colon = i;
            break;
        }
    if (colon == (size_t)-1 || colon == 0)
    {
        LOG_DEBUG("[!] malformed header line: no colon or empty field-name");
        return RH_ERR_PARSE;
    }
    for (size_t i = 0; i < colon; i++)
        if (line[i] == ' ' || line[i] == '\t')
        {
            LOG_DEBUG("[!] rejecting header with whitespace before colon (sumggling-relevant ambiguity)");
            return RH_ERR_PARSE;
        }

    size_t val_start = colon+1;
    while (val_start < len && (line[val_start] == ' ' || line[val_start] == '\t')) val_start++;
    size_t val_end = len;
    while (val_end > val_start && (line[val_end-1] == ' ' || line[val_end-1] == '\t')) val_end--;

    char *name = dup_range(line, colon);
    char *value = dup_range(line+val_start, val_end - val_start);
    if (!name || !value)
    {
        free(name);
        free(value);
        return RH_ERR_MEM;
    }
    
    return rh__heaader_push(out, name, value);
}

static int parse_uint_digits(const char *s, size_t n, int *out_val)
{
    if (n == 0 || n > 4) return 0;

    int v = 0;
    for (size_t i = 0; i < n; i++)
    {
        if (!isdigit((unsigned char)s[i])) return 0;
        v = v*10 + (s[i]-'0');
    }
    *out_val = v;
    return 1;
}

static rh_err parse_status_line(const char *line, size_t len, rh_response *out)
{
    if (len < 12 || strncmp(line, "HTTP/", 5) != 0)
    {
        LOG_DEBUG("[!] malformed status line (too short or missing HTTP/ prefix)");
        return RH_ERR_PARSE;
    }

    size_t i = 5;
    size_t major_starat = i;
    while (i < len && isdigit((unsigned char)line[i])) i++;

    int major;
    if (i == major_start || i >= len || line[i] != '.' || !parse_uint_digits(line+major_start, i-major_start, &major)) return RH_ERR_PARSE;
    i++; /* skip '.' */

    size_t minor_start = i;
    while (i < len && isdigit((unsigned char)line[i])) i++;

    int minor;
    if (i == minor_start || i >= len || line[i] != ' ' || !parse_uint_digits(line+minor_start, i-minor_start, &minor)) return RH_ERR_PARSE;
    i++; /* skip space */

    if (i+3 > len || !isdigit((unsigned char)line[i]) || !isdigit((unsigned char)line[i+1]) || !isdigit((unsigned char)line[i+2])) return RH_ERR_PARSE;

    int status = (line[i]-'0')*100+(line[i+1]-'0')*10+(line[i+2]-'0');
    i+=3;

    char *reason;
    if(i < len && line[i] == ' ') reason = dup_range(line+i+1, len-i-1);
    else if (i == len) reason = dup_range("", 0);
    else
    {
        LOG_DEBUG("[!] malformed status line: trailing junk after status code");
        return RH_ERR_PARSE;
    }
    if (!reason) return RH_ERR_MEM;

    out->http_major = major;
    out->http_minor = minor;
    out->status = status;
    out->reason = reason;
    return RH_OK;
}

static rh_err parse_head(const char *data, size_t len, rh_response *out)
{
    size_t status_len = len;
    for (size_t i = 0; i + 1 < len; i++)
        if (data[i] == '\r' && data[i+1] == '\n')
        {
            status_len = i;
            break;
        }

    rh_err e = parse_status_line(data, status_len, out);
    if (e != RH_OK) return e;

    size_t cursor = (status < len)? status_len+2 : len;
    while (cursor < len)
    {
        size_t line_end = len;
        for (size_t j = cursor; j+1 < len; j++)
            if (data[j] == '\r' && data[j+1] == '\n')
            {
                line_end = j;
                break;
            }
        
        e = rh__parse_header_line(data+cursor, line_end-cursor, out);
        if (e != RH_OK) return e;
        cursor = (line_end < len) ? line_end+2 : len;
    }

    return RH_OK;
}

rh_err rh_response_read_headers(rh_transport *t, rh_buf *raw, rh_responses *out, size_t *header_end)
{
    if (!raw || !out || !header_end) return RH_ERR_INVAL;
    memset(out, 0, sizeof(*out));

    size_t scanned = 0; /* bytes confirmed not to start a "\r\n\r\n" match */

    for (;;)
    {
        size_t start = scanned > 3 ? scanned - 3 : 0;
        size_t idx = find_crlfcrlf(raw->data + start, raw->len - start);
        if (idx != (size_t)-1) 
        {
            size_t boundary = start + idx;
            *header_end = boundary + 4;
            rh_err e = parse_head(raw->data, boundary, out);
            if (e != RH_OK) rh_response_free(out); /* discard any partial state - see contract in response.h */
            return e;
        }
        scanned = raw->len >= 3 ? raw->len - 3 : 0;

        if (raw->len >= RH_MAX_HEADER_BYTES) 
        {
            LOG_DEBUG("[!] header block exceeded RH_MAX_HEADER_BYTES without terminator");
            return RH_ERR_LIMIT;
        }

        int eof = 0;
        rh_err e = rh_recv_some(t, raw, &eof);
        if (e != RH_OK) return e;
        if (eof) 
        {
            LOG_DEBUG("[!] connection closed before headers completed (%zu bytes buffered)", raw->len);
            return RH_ERR_PARSE;
        }
    }
}

const char *rh_header_get(const rh_response *resp, const char *name) 
{
    if (!resp || !name) return NULL;
    for (size_t i = 0; i < resp->header_count; i++) 
        if (ci_eq(resp->headers[i].name, name)) return resp->headers[i].value;
    return NULL;
}

rh_err rh_response_read_body_content_length(rh_transport *t, rh_buf *raw, size_t header_end,
                                             rh_response *out, size_t content_length) 
{
    if (!raw || !out) return RH_ERR_INVAL;
    if (content_length > RH_MAX_BODY_BYTES) 
    {
        LOG_DEBUG("[!] content-length %zu exceeds RH_MAX_BODY_BYTES", content_length);
        return RH_ERR_LIMIT;
    }

    size_t target = header_end + content_length;

    while (raw->len < target) 
    {
        int eof = 0;
        rh_err e = rh_recv_some(t, raw, &eof);
        if (e != RH_OK) return e;
        if (eof) 
        {
            LOG_DEBUG("[!] peer closed after %zu/%zu body bytes (short/lying Content-Length)",
                      raw->len > header_end ? raw->len - header_end : 0, content_length);
            return RH_ERR_IO;
        }
    }

    rh_err e = rh_buf_init(&out->body, 0);
    if (e != RH_OK) return e;
    if (content_length > 0) 
    {
        e = rh_buf_append(&out->body, raw->data + header_end, content_length);
        if (e != RH_OK) 
        {
            rh_buf_free(out->body); // self-clean on failure, same contract as chuncked_decode
            return e;
        }
    }
    return RH_OK;
}

rh_err rh_response_read_body_until_close(rh_transport *t, rh_buf *raw, size_t header_end,
                                          rh_response *out) {
    if (!raw || !out) return RH_ERR_INVAL;

    for (;;) 
    {
        int eof = 0;
        rh_err e = rh_recv_some(t, raw, &eof);
        if (e != RH_OK) return e;
        if (eof) break;
        if (raw->len - header_end > RH_MAX_BODY_BYTES) 
        {
            LOG_DEBUG("[!] until-close body exceeded RH_MAX_BODY_BYTES");
            return RH_ERR_LIMIT;
        }
    }

    rh_err e = rh_buf_init(&out->body, 0);
    if (e != RH_OK) return e;
    size_t body_len = raw->len - header_end;
    if (body_len > 0) 
    {
        e = rh_buf_append(&out->body, raw->data + header_end, body_len);
        if (e != RH_OK) 
        {
            rh_buf_free(&out->body);
            return e;
        }
    }
    return RH_OK;
}

void rh_response_free(rh_response *resp) 
{
    if (!resp) return;
    free(resp->reason);
    for (size_t i = 0; i < resp->header_count; i++) 
    {
        free(resp->headers[i].name);
        free(resp->headers[i].value);
    }
    free(resp->headers);
    rh_buf_free(&resp->body);
    memset(resp, 0, sizeof(*resp));
}
