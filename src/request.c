#include "rawhttp_/request.h"

#include <stdio.h>
#include <string.h>

#define RH_APPEND_LIT(out, lit)                                 \
do                                                              \
{                                                               \
    rh_err _e = rh_buf_append((out), (lit), sizeof(lit)-1);     \
    if (_e != RH_OK) return _e;                                 \
} while (0)                                                     \

#define RH_APPEND_STR(out, str)                                 \
do                                                              \
{                                                               \
    rh_err _e = rh_buf_append((out), (str), strlen(str));       \
    if (_e != RH_OK) return _e;                                 \
} while (0)                                                     \

static int ci_eq(const char *a, const char *b) 
{
    while (*a && *b) 
    {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
        if (ca != cb) return 0;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

static int headers_has(const rh_request_header *headers, size_t count, const char *name) 
{
    for (size_t i = 0; i < count; i++) 
        if (ci_eq(headers[i].name, name)) return 1;
    return 0;
}

rh_err rh_request_build(const char *method, const rh_url *url, const rh_request_header *headers,
                         size_t header_count, const void *body, size_t body_len,
                         int auto_content_length, rh_buf *out) 
{
    if (!method || !*method || !url || !out || !url->host || !url->path || !url->scheme) return RH_ERR_INVAL;
    if (header_count > 0 && !headers) return RH_ERR_INVAL;
    if (body_len > 0 && !body) return RH_ERR_INVAL;

    RH_APPEND_STR(out, method);
    RH_APPEND_LIT(out, " ");
    RH_APPEND_STR(out, url->path);
    RH_APPEND_LIT(out, " HTTP/1.1\r\n");

    if (!headers_has(headers, header_count, "Host")) 
    {
        RH_APPEND_LIT(out, "Host: ");
        RH_APPEND_STR(out, url->host);

        /* RFC 7230 - Host must carry a non-default port explicitly */
        uint16_t default_port = (strcmp(url->scheme, "https") == 0) ? 443 : 80;
        if (url->port != default_port) 
        {
            char port_buf[8];
            int n = snprintf(port_buf, sizeof(port_buf), ":%u", url->port);
            if (n < 0 || (size_t)n >= sizeof(port_buf)) return RH_ERR_INVAL;
            rh_err e = rh_buf_append(out, port_buf, (size_t)n);
            if (e != RH_OK) return e;
        }
        RH_APPEND_LIT(out, "\r\n");
    }

    if (!headers_has(headers, header_count, "Connection")) RH_APPEND_LIT(out, "Connection: close\r\n");
    if (!headers_has(headers, header_count, "User-Agent")) RH_APPEND_LIT(out, "User-Agent: rawhttp/0.1\r\n");

    /* caller-supplied headers, verbatim, in the order given - no
     * validation, no reordering. This is the control surface that
     * makes smuggling/desync testing possible later. */

    for (size_t i = 0; i < header_count; i++) 
    {
        RH_APPEND_STR(out, headers[i].name);
        RH_APPEND_LIT(out, ": ");
        RH_APPEND_STR(out, headers[i].value);
        RH_APPEND_LIT(out, "\r\n");
    }

    if (auto_content_length && body_len > 0 &&
        !headers_has(headers, header_count, "Content-Length")) 
    {
        char cl_buf[32];
        int n = snprintf(cl_buf, sizeof(cl_buf), "Content-Length: %zu\r\n", body_len);
        if (n < 0 || (size_t)n >= sizeof(cl_buf)) return RH_ERR_INVAL;
        rh_err e = rh_buf_append(out, cl_buf, (size_t)n);
        if (e != RH_OK) return e;
    }

    /* auto_content_length == 0: never auto-add, regardless of body_len.
     * This is the manual-override escape hatch smuggling research
     * needs - the caller is trusted completely to supply their own
     * (possibly wrong, possibly duplicated) Content-Length via
     * `headers` instead. We never "fix" what they asked for. */

    RH_APPEND_LIT(out, "\r\n");

    if (body_len > 0) 
    {
        rh_err e = rh_buf_append(out, body, body_len);
        if (e != RH_OK) return e;
    }

    return RH_OK;
}

rh_err rh_request_build_get(const rh_url *url, rh_buf *out) 
{
    return rh_request_build("GET", url, NULL, 0, NULL, 0, 0, out);
}

#undef RH_APPEND_LIT
#undef RH_APPEND_STR
