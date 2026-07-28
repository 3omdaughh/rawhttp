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

rh_err rh_request_build_get(const rh_url *url, rh_buf *out)
{
    if (!url || !out || !url->host || !url->path || !url->scheme) 
        return RH_ERR_INVAL;

    RH_APPEND_LIT(out, "GET ");
    RH_APPEND_STR(out, url->path);
    RH_APPEND_LIT(out, " HTTP/1.1\r\n");
    RH_APPEND_LIT(out, "HOST: ");
    RH_APPEND_STR(out, url->host);


/* 
 * RFC 7230 §5.4 - If the request-target contains a port,
 * the Host header field-value must include that port.
 */
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
    RH_APPEND_LIT(out, "Connection: close\r\n");
    RH_APPEND_LIT(out, "User-Agent: rawhttp/0.1\r\n");
    RH_APPEND_LIT(out, "\r\n");

    return RH_OK;
}

#undef RH_APPEND_LIT
#undef RH_APPEND_STR
