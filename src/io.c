#include "rawhttp_/io.h"

#include <errno.h>
#include <sys/socket.h>

#define RH_RECV_CHUNK 4096

rh_err rh_send_all(int fd, const void *data, size_t len)
{
    if (!data && len > 0) return RH_ERR_INVAL;

    const char *p = (const char *)data;
    size_t sent = 0;

    while (sent < len)
    {
        ssize_t n = send(fd, p + sent, len - sent, MSG_NOSIGNAL);
        if (n > 0)
        {
            sent+=(size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) continue; // ignore interruption and tryagain

        /* n == 0 shouldn't happen for send(), and any other n < 0 is a
         * real failure (peer reset, broken pipe caught via MSG_NOSIGNAL,
         * etc). Either way, this send is unrecoverable. */

        LOG_DEBUG("[!] send_all: failed after %zu/%zu bytes (errno=%d)", sent, len, errno);
        return RH_ERR_IO;
    }
    return RH_OK;
}

rh_err rh_recv_all(int fd, rh_buf *out)
{
    if (!out) return RH_ERR_INVAL;

    char chunk[RH_RECV_CHUNK];
    for (;;)
    {
        ssize_t n = recv(fd, chunk, sizeof(chunk), 0);
        if (n > 0)
        {
            rh_err e = rh_buf_append(out, chunk, (size_t)n);
            if (e != RH_OK) return e;
            continue;
        }
        if (n == 0) return RH_OK;
        if (errno == EINTR) continue;
        LOG_DEBUG("[!] recv_all: failed after %zu bytes buffered (errno=%d)", out->len, errno);
        return RH_ERR_IO;
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
