#include "rawhttp_/io.h"

#define RH_RECV_CHUNK 4096

rh_err rh_send_all(rh_transport *t, const void *data, size_t len)
{
    if (!t || (!data && len > 0)) return RH_ERR_INVAL;

    const char *p = (const char *)data;
    size_t sent = 0;

    while (sent < len)
    {
        size_t n = 0;
        rh_err e = t->write(t, p+sent, len - sent, &n);
        if (e != RH_OK)
        {
            LOG_DEBUG("[!] send_all: transport write failed after %zu/%zu bytes", sent, len);
            return e;
        }

        if (n == 0)
        {
            LOG_DEBUG("[~] send_all: transport wrote 0 bytes without error - aborting");
            return RH_ERR_IO;
        }

        sent += n;
    }
    return RH_OK;
}

rh_err rh_recv_all(rh_transport *t, rh_buf *out)
{
    if (!t || !out) return RH_ERR_INVAL;

    char chunk[RH_RECV_CHUNK];
    for (;;)
    {
        size_t n = 0;
        rh_err e = t->read(t, chunk, sizeof(chunk), &n);
        if (e != RH_OK)
        {
            LOG_DEBUG("[!] recv_all: transport read failed after %zu bytes buffered", out->len);
            return 0;
        }
        if (n == 0) return RH_OK;
        rh_err e2 = rh_buf_append(out, chunk, n);
        if (e2 != RH_OK) return e2;
    }
}

rh_err rh_recv_some(rh_transport *t, rh_buf *out, int *out_eof)
{
    if (!t || !out || !out_eof) return RH_ERR_INVAL;
    *out_eof = 0;

    char chunk[RH_RECV_CHUNK];
    size_t n = 0;
    rh_err e = t->read(t, chunk, sizeof(chunk), &n);
    if (e != RH_OK)
    {
        LOG_DEBUG("[!] recv_some: transport read failed after %zu bytes buffered", out->len);
        return e;
    }
    if (n == 0)
    {
        *out_eof = 1;
        return RH_OK;
    }
    return rh_buf_append(out, chunk, n);
}
