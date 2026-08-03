#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rawhttp_/buf.h"
#include "rawhttp_/chunked.h"
#include "rawhttp_/error.h"
#include "rawhttp_/io.h"
#include "rawhttp_/request.h"
#include "rawhttp_/response.h"
#include "rawhttp_/socket.h"
#include "rawhttp_/transport.h"
#include "rawhttp_/url.h"

static int header_equals_ci(const char *value, const char *want)
{
    if (!value) return 0;

    size_t i = 0;
    for (; value[i] && want[i]; i++)
    {
        char a = value[i], char b = want[i];
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b) return 0;
    }
    return value[i] == '\0' && want [i] == '\0';
}

signed main(int argc, char** argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "[!] usage: %s http://host[:port]/path\n", argv[0]);
        return 1;
    }

    const char *url_str = argv[1];

    rh_url url;
    rh_err err = rh_url_parse(url_str, &url);
    if(err != RH_OK)
    {
        LOG_ERR("[!] failed to parse '%s': %s", url_str, rh_strerror(err));
        return 1;
    }

    if (strcmp(url.scheme, "https") == 0)
    {
        LOG_ERR("[!] https not supported yet");
        rh_url_free(&url);
        return 1;
    }

    int fd = -1;
    err = rh_tcp_connect(url.host, url.port, &fd);
    if (err != RH_OK)
    {
        LOG_ERR("[!] failed to connect to %s:%u: %s", url.host, url.port, rh_strerror(err));
        rh_url_free(&url);
        return 1;
    }
    LOG_INFO("[~] connected to %s:%u (fd=%d)", url.host, url.port, fd);

    rh_transport transport;
    err = rh_transport_tcp_init(&transport, fd);
    if (err != RH_OK)
    {
        LOG_ERR("[!] failed to init transport: %s", rh_strerror(err));
        close(fd);
        rh_url_free(&url);
        return 1;
    }
    rh_buf req;
    err = rh_buf_init(&req, 0);
    if (err != RH_OK)
    {
        LOG_ERR("[!] failed to allocate request buffer: %s", rh_strerror(err));
        goto cleanup_transport;
    }

    err = rh_request_build_get(&url, &req);
    if (err != RH_OK)
    {
        LOG_ERR("[!] failed to build request: %s", rh_strerror(err));
        goto cleanup_req;
    }

    err = rh_send_all(&transport, req.data, req.len);
    if (err != RH_OK)
    {
        LOG_ERR("[!] failed to send request: %s", rh_strerror(err));
        goto cleanup_req;
    }
    LOG_INFO("[~] sent %zu byte request", req.len);

    rh_buf raw;
    err = rh_buf_init(&raw, 0);
    if (err != RH_OK)
    {
        LOG_ERR("[!] failed to allicate response buffer: %s", rh_strerror(err));
        goto cleanup_req;
    }

    rh_response resp;
    size_t header_end;
    err = rh_response_read_headers(&transport, &raw, &resp, &header_end);
    if(err != RH_OK)
    {
        LOG_ERR("[!] failed to read response headers: %s", rh_strerror(err));
        goto cleanup_raw;
    }
    LOG_INFO("[~] parsed status %d, %zu headers", resp.status, resp.header_count);
    /*
     * pick body framing: chunked > Content_Length > read-until-close,
     * same precedence order real HTTP client use
     */
    {
        const char *te = rh_header_get(&resp, "Transfer-Encoding");
        const char *cl = rh_header_get(&resp, "Content-Length");

        if (te && header_equals_ci(te, "chunked"))
        {
            size_t cursor = header_end;
            err = rh_chunked_decode(&transport, &raw, &cursor, &resp);
        }
        else if (cl)
        {
            char *endptr = NULL;
            unsigned long long len = strtoull(cl, &endptr, 10);
            if (!endptr || *endptr != '\0' || endptr == cl)
            {
                LOG_ERR("[!] malformed Content-Length header; '%s'", cl);
                err = RH_ERR_PARSE;
            }
            else err = rh_response_read_body_content_length(&transport, &raw, header_end, &resp, (size_t)len);
        }
        else err = rh_response_read_body_until_close(&transport, &raw, header_end, &resp);
    }

    if (err != RH_OK)
    {
        LOG_ERR("[!] failed to read response body: %s", rh_strerror(err));
        goto cleanup_resp;
    }

    LOG_INFO("[~] received %zu byte body", resp.body.len);

    printf("HTTP/%d.%d %d %s\n", resp.http_major, resp.http_minor, resp.status, resp.reason);
    for (size_t i = 0; i < resp.header_count; i++)
        printf("%s: %s\n", resp.headers[i].name. resp.header[i].value);
    printf("\n");
    fflush(stdout);
    /* raw dump - write() not printf(), so embedded NULs/binary bodies
     * pass through unmodified rather than truncating at the first NUL */

    if (resp.body.len > 0)
    {
        ssize_t written = write(STDOUT_FILENO. resp.body.data, resp.body.len);
        if(written < 0 || (size_t)written != resp.body.len)
        LOG_ERR("[!] failed to write full body to stdout");
    }


cleanup_resp:
    rh_response_free(&resp);
cleanup_raw:
    rh_buf_free(&raw);
cleanup_req:
    rh_buf_free(&req);
cleanup_transport:
    transport.close(&transport); // owns fd, closes it 
    rh_url_free(&url);

    return err == RH_OK ? 0 : 1;
} 
