#include "rawhttp_/io.h"

#include <errno.h>
#include <poll.h>

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

rh_err rh_recv_until_idle(rh_transport *t, rh_buf *out, int idle_timeout_ms)
{
    if (!t || !out) return RH_ERR_INVAL;

    int fd = t->get_fd ? t->get_fd(t) : -1;
    if (fd < 0)
    {
        /*
         * no fd accessor available - fall back to a single read attempt
         * rather than failing outright (shoundn't happen for either of
         * this project's own transports, both of which set get_fd)
         * */
        int eof = 0;
        return rh_recv_some(t, out, &eof);
    }

    for (;;)
    {
        struct pollfd pfd = {.fd = fd, .events = POLLIN, .revents = 0};
        int pr = poll(&pfd, 1, idle_timeout_ms);
        if (pr < 0)
        {
            if (errno == EINTR) continue;
            LOG_DEBUG("[!] recv_until_idle: poll() failed");
            return RH_ERR_IO;
        }
        if (pr == 0) return RH_OK; /* idle timeout elapsed - nothing more coming */

        int eof = 0;
        rh_err e = rh_recv_some(t, out, &eof);
        if (e != RH_OK) return e;
        if (eof) return RH_OK; /* peer closed - clean end */
        /* got some data - loop and poll again in case more is coming */
    }
}
