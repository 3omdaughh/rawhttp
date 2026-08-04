#include "rawhttp_/transport.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct
{
    int fd;
} rh_tcp_ctx;

static rh_err tcp_read(rh_transport *t, void *buf, size_t len, size_t *out_n)
{
    rh_tcp_ctx *ctx = (rh_tcp_ctx *)t->ctx;
    for (;;)
    {
        ssize_t n = recv(ctx->fd, buf, len, 0);
        if (n >= 0)
        {
            *out_n = (size_t)n;
            return RH_OK;
        }
        if (errno == EINTR) continue;
        return RH_ERR_IO;
    }
}

static rh_err tcp_write(rh_transport *t, const void *buf, size_t len, size_t *out_n)
{
    rh_tcp_ctx *ctx = (rh_tcp_ctx*)t->ctx;
    for (;;)
    {
        ssize_t n = send(ctx->fd, buf, len, MSG_NOSIGNAL);
        if (n >= 0)
        {
            *out_n = (size_t)n;
            return RH_OK;
        }
        if (errno == EINTR) continue;
        return RH_ERR_IO;
    }
}

static void tcp_close(rh_transport *t)
{
    rh_tcp_ctx *ctx = (rh_tcp_ctx *)t->ctx;
    if (ctx)
    {
        if (ctx->fd >= 0) close(ctx->fd);
        free(ctx);
    }
    t->ctx = NULL;
}

rh_err rh_transport_tcp_init(rh_transport *t, int fd)
{
    if (!t || fd < 0) return RH_ERR_INVAL;

    rh_tcp_ctx *ctx = malloc(sizeof(*ctx));
    if (!ctx) return RH_ERR_MEM;
    ctx->fd     = fd;
    t->ctx      = ctx;
    t->read     = tcp_read;
    t->write    = tcp_write;
    t->close    = tcp_close;
    return RH_OK;
}
