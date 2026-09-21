#include "rawhttp_/output.h"

#include <stdio.h>
#include <string.h>

rh_err rh_json_escape(const void *data, size_t len, rh_buf *out)
{
    if ((!data && len > 0) || !out) return RH_ERR_INVAL;

    const unsigned char *p = (const unsigned char *)data;
    for (size_t i = 0; i < len; i++)
    {
        unsigned char c = p[i];
        const char *esc = NULL;
        char ubuf[7]; /* \u00XX + NUL */

        switch (c)
        {
            case '"':  esc = "\\\""; break;
            case '\\': esc = "\\\\"; break;
            case '\b': esc = "\\b";  break;
            case '\f': esc = "\\f";  break;
            case '\n': esc = "\\n";  break;
            case '\r': esc = "\\r";  break;
            case '\t': esc = "\\t";  break;
            default:
                if (c < 0x20)
                {
                    snprintf(ubuf, sizeof(ubuf), "\\u%04x", c);
                    esc = ubuf;
                }
                break;
        }

        rh_err e;
        if (esc) e = rh_buf_append(out, esc, strlen(esc));
        else     e = rh_buf_append(out, &c, 1);
        if (e != RH_OK) return e;
    }
    return RH_OK;
}

static const char b64_alpha[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

rh_err rh_base64_encode(const void *data, size_t len, rh_buf *out)
{
    if ((!data && len > 0) || !out) return RH_ERR_INVAL;

    const unsigned char *p = (const unsigned char *)data;
    size_t i = 0;

    /* full 3-byte groups -> 4 output chars */
    for (; i + 3 <= len; i += 3)
    {
        unsigned v = ((unsigned)p[i] << 16) | ((unsigned)p[i+1] << 8) | p[i+2];
        char q[4] = {
            b64_alpha[(v >> 18) & 0x3f],
            b64_alpha[(v >> 12) & 0x3f],
            b64_alpha[(v >> 6)  & 0x3f],
            b64_alpha[v & 0x3f],
        };
        rh_err e = rh_buf_append(out, q, 4);
        if (e != RH_OK) return e;
    }

    /* trailing 1 or 2 bytes, '=' padded */
    size_t rem = len - i;
    if (rem > 0)
    {
        unsigned b0 = p[i];
        unsigned b1 = rem == 2 ? p[i+1] : 0;
        unsigned v = (b0 << 16) | (b1 << 8);
        char q[4];
        q[0] = b64_alpha[(v >> 18) & 0x3f];
        q[1] = b64_alpha[(v >> 12) & 0x3f];
        q[2] = rem == 2 ? b64_alpha[(v >> 6) & 0x3f] : '=';
        q[3] = '=';
        rh_err e = rh_buf_append(out, q, 4);
        if (e != RH_OK) return e;
    }
    return RH_OK;
}
