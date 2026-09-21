#define _GNU_SOURCE /* memmem */

#include "rawhttp_/socket.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* --- process-wide connection config (see socket.h) --- */

static int      g_timeout_ms = 0;
static int      g_proxy_set  = 0;
static char     g_proxy_host[256];
static uint16_t g_proxy_port = 0;

void rh_socket_set_default_timeout(int timeout_ms)
{
    g_timeout_ms = timeout_ms;
}

void rh_socket_set_proxy(const char *host, uint16_t port)
{
    if (!host)
    {
        g_proxy_set = 0;
        return;
    }
    snprintf(g_proxy_host, sizeof(g_proxy_host), "%s", host);
    g_proxy_port = port;
    g_proxy_set  = 1;
}

static rh_err set_blocking(int fd, int blocking)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return RH_ERR_IO;
    if (blocking) flags &= ~O_NONBLOCK;
    else          flags |= O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags) < 0 ? RH_ERR_IO : RH_OK;
}

/* recv()/send() timeout via SO_*TIMEO - also bounds SSL_read/SSL_write,
 * which sit on this same fd. No-op when g_timeout_ms <= 0. */
static void apply_io_timeouts(int fd)
{
    if (g_timeout_ms <= 0) return;
    struct timeval tv = {
        .tv_sec  = g_timeout_ms / 1000,
        .tv_usec = (g_timeout_ms % 1000) * 1000,
    };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/* connect() one candidate address, bounded by g_timeout_ms when > 0.
 * Returns RH_OK / RH_ERR_CONNECT / RH_ERR_TIMEOUT. */
static rh_err connect_one(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (g_timeout_ms <= 0)
        return connect(fd, addr, addrlen) == 0 ? RH_OK : RH_ERR_CONNECT;

    if (set_blocking(fd, 0) != RH_OK) return RH_ERR_CONNECT;

    int rc = connect(fd, addr, addrlen);
    if (rc == 0)
    {
        set_blocking(fd, 1);
        return RH_OK;
    }
    if (errno != EINPROGRESS) return RH_ERR_CONNECT;

    struct pollfd pfd = {.fd = fd, .events = POLLOUT, .revents = 0};
    for (;;)
    {
        int pr = poll(&pfd, 1, g_timeout_ms);
        if (pr < 0)
        {
            if (errno == EINTR) continue;
            return RH_ERR_CONNECT;
        }
        if (pr == 0) return RH_ERR_TIMEOUT;
        break;
    }

    int soerr = 0;
    socklen_t slen = sizeof(soerr);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) < 0 || soerr != 0)
        return RH_ERR_CONNECT;

    return set_blocking(fd, 1) == RH_OK ? RH_OK : RH_ERR_CONNECT;
}

/* getaddrinfo() + connect_one() over every candidate. Sets *out_fd on
 * success. RH_ERR_TIMEOUT is preserved (not masked as RH_ERR_CONNECT) when
 * the last meaningful failure was a timeout. */
static rh_err resolve_and_connect(const char *host, uint16_t port, int *out_fd)
{
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%u", port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *results = NULL;
    int gai_err = getaddrinfo(host, port_str, &hints, &results);
    if (gai_err != 0)
    {
        LOG_DEBUG("[!] getaddrinfo(%s:%u) failed: %s", host, port, gai_strerror(gai_err));
        return RH_ERR_DNS;
    }

    int fd = -1;
    rh_err last = RH_ERR_CONNECT;
    for (struct addrinfo *rp = results; rp != NULL; rp = rp->ai_next)
    {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        rh_err ce = connect_one(fd, rp->ai_addr, rp->ai_addrlen);
        if (ce == RH_OK) break;
        last = ce;
        close(fd);
        fd = -1;
    }

    freeaddrinfo(results);
    if (fd < 0)
    {
        LOG_DEBUG("[!] connect(%s,%u) failed on all candidate addresses", host, port);
        return last;
    }

    apply_io_timeouts(fd);
    *out_fd = fd;
    return RH_OK;
}

/* Blocking read into buf until it contains "\r\n\r\n" or the buffer fills.
 * recv() is already timeout-bounded by apply_io_timeouts(). */
static rh_err read_proxy_reply(int fd, char *buf, size_t cap, size_t *out_len)
{
    size_t len = 0;
    while (len < cap)
    {
        ssize_t n = recv(fd, buf + len, cap - len, 0);
        if (n > 0)
        {
            len += (size_t)n;
            if (len >= 4 && memmem(buf, len, "\r\n\r\n", 4)) break;
            continue;
        }
        if (n == 0) break; /* proxy closed */
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return RH_ERR_TIMEOUT;
        return RH_ERR_IO;
    }
    *out_len = len;
    return RH_OK;
}

/* HTTP CONNECT handshake toward `host:port` over an already-connected proxy
 * fd. Returns RH_OK only on a 2xx tunnel-established reply. */
static rh_err proxy_connect_handshake(int fd, const char *host, uint16_t port)
{
    char req[512];
    int rn = snprintf(req, sizeof(req),
                      "CONNECT %s:%u HTTP/1.1\r\nHost: %s:%u\r\n\r\n",
                      host, port, host, port);
    if (rn < 0 || (size_t)rn >= sizeof(req)) return RH_ERR_INVAL;

    size_t sent = 0;
    while (sent < (size_t)rn)
    {
        ssize_t n = send(fd, req + sent, (size_t)rn - sent, MSG_NOSIGNAL);
        if (n > 0) { sent += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return RH_ERR_TIMEOUT;
        return RH_ERR_IO;
    }

    char resp[1024];
    size_t rlen = 0;
    rh_err e = read_proxy_reply(fd, resp, sizeof(resp), &rlen);
    if (e != RH_OK) return e;

    /* status line: "HTTP/1.x NNN ..." - accept any 2xx */
    if (rlen < 12 || strncmp(resp, "HTTP/", 5) != 0)
    {
        LOG_DEBUG("[!] proxy CONNECT: no HTTP status line in reply");
        return RH_ERR_PARSE;
    }
    const char *sp = memchr(resp, ' ', rlen);
    if (!sp || (size_t)(sp - resp) + 2 >= rlen || sp[1] != '2')
    {
        LOG_DEBUG("[!] proxy CONNECT refused (non-2xx status)");
        return RH_ERR_CONNECT;
    }
    return RH_OK;
}

rh_err rh_tcp_connect(const char *host, uint16_t port, int *out_fd)
{
    if (!host || !out_fd) return RH_ERR_INVAL;

    if (!g_proxy_set)
        return resolve_and_connect(host, port, out_fd);

    /* proxy path: connect the proxy, tunnel to the real target */
    int fd = -1;
    rh_err e = resolve_and_connect(g_proxy_host, g_proxy_port, &fd);
    if (e != RH_OK)
    {
        LOG_DEBUG("[!] failed to reach proxy %s:%u", g_proxy_host, g_proxy_port);
        return e;
    }
    e = proxy_connect_handshake(fd, host, port);
    if (e != RH_OK)
    {
        close(fd);
        return e;
    }
    *out_fd = fd;
    return RH_OK;
}
