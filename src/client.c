#define _POSIX_C_SOURCE 200809L

#include "rawhttp_/client.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "rawhttp_/buf.h"
#include "rawhttp_/chunked.h"
#include "rawhttp_/io.h"
#include "rawhttp_/socket.h"

static int header_equals_ci(const char *value, const char *want)
{
    if (!value) return 0;
    size_t i = 0;
    for (; value[i] && want[i]; i++)
    {
        char a = value[i], b = want[i];
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b) return 0;
    }
    return value[i] == '\0' && want[i] == '\0';
}

rh_err rh_client_request(const rh_url *url, const char *method,
                         const rh_request_header *headers, size_t header_count,
                         const void *body, size_t body_len, int insecure,
                         rh_response *out_resp, rh_timing *out_timing)
{
    if (!url || !method || !out_resp) return RH_ERR_INVAL;
    if (out_timing)
    {
        out_timing->ttfb_ms  = -1.0;
        out_timing->total_ms = -1.0;
    }

    int is_https = strcmp(url->scheme, "https") == 0;

    int fd = -1;
    rh_err err = rh_tcp_connect(url->host, url->port, &fd);
    if (err != RH_OK) return err;

    struct timespec t_connect;
    clock_gettime(CLOCK_MONOTONIC, &t_connect);

    rh_transport t;
    if (is_https) err = rh_transport_tls_init(&t, fd, url->host, insecure);
    else          err = rh_transport_tcp_init(&t, fd);
    if (err != RH_OK)
    {
        close(fd);
        return err;
    }

    rh_buf req;
    err = rh_buf_init(&req, 0);
    if (err != RH_OK) goto done_transport;

    err = rh_request_build(method, url, headers, header_count, body, body_len, 1, &req);
    if (err != RH_OK) { rh_buf_free(&req); goto done_transport; }

    err = rh_send_all(&t, req.data, req.len);
    rh_buf_free(&req);
    if (err != RH_OK) goto done_transport;

    rh_buf raw;
    err = rh_buf_init(&raw, 0);
    if (err != RH_OK) goto done_transport;

    size_t header_end;
    err = rh_response_read_headers(&t, &raw, out_resp, &header_end);
    if (err != RH_OK) { rh_buf_free(&raw); goto done_transport; }

    const char *te = rh_header_get(out_resp, "Transfer-Encoding");
    const char *cl = rh_header_get(out_resp, "Content-Length");

    if (te && header_equals_ci(te, "chunked"))
    {
        size_t cursor = header_end;
        err = rh_chunked_decode(&t, &raw, &cursor, out_resp);
    }
    else if (cl)
    {
        char *endptr = NULL;
        unsigned long long len = strtoull(cl, &endptr, 10);
        if (!endptr || *endptr != '\0' || endptr == cl) err = RH_ERR_PARSE;
        else err = rh_response_read_body_content_length(&t, &raw, header_end, out_resp, (size_t)len);
    }
    else err = rh_response_read_body_until_close(&t, &raw, header_end, out_resp);

    rh_buf_free(&raw);
    if (err != RH_OK) goto done_transport;

    if (out_timing)
    {
        struct timespec t_end;
        clock_gettime(CLOCK_MONOTONIC, &t_end);
        out_timing->ttfb_ms  = t.first_byte_recorded
                             ? rh_timespec_diff_ms(&t_connect, &t.first_byte_at) : -1.0;
        out_timing->total_ms = rh_timespec_diff_ms(&t_connect, &t_end);
    }

    t.close(&t);
    return RH_OK;

done_transport:
    t.close(&t);
    rh_response_free(out_resp);
    return err;
}
