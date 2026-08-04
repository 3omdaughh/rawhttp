#include "rawhttp_/transport.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

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

// --- TLS backend --- 

typedef struct 
{
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    int fd;
} rh_tls_ctx;

static rh_err tls_read(rh_transport *t, void *buf, size_t len, size_t *out_n)
{
    rh_tls_ctx *ctx = (rh_tls_ctx *)t->ctx;
    int rlen = len > (size_t)INT_MAX ? INT_MAX : (int)len;

    for (;;)
    {
        int n = SSL_read(ctx->ssl, buf, rlen);
        if (n > 0)
        {
            *out_n = (size_t)n;
            return RH_OK;
        }
        int se = SSL_get_error(ctx->ssl, n);
        if (se == SSL_ERROR_ZERO_RETURN)
        {
            *out_n = 0; // peer sent close_notify - clean TLS_level EOF
            return RH_OK;
        }
        if (se == SSL_ERROR_WANT_READ || se == SSL_ERROR_WANT_WRITE) continue; // blocking socket - a renegotiation blip, just retry 
        if (se == SSL_ERROR_SYSCALL && n == 0)
        {
            /*
             * many real-world servers close the raw TCP connection without a close-notify
             * treat that as EOF too rather than a hard error, same as a plain socket's
             * recv() == 0
             */
            *out_n = 0;
            return RH_OK;
        }
        return RH_ERR_IO;
    }
}

static rh_err tls_write(rh_transport *t, const void *buf, size_t len, size_t *out_n)
{
    rh_tls_ctx *ctx = (rh_tls_ctx *)t->ctx;
    int wlen = len > (size_t)INT_MAX ? INT_MAX : (int)len;

    for (;;)
    {
        int n = SSL_write(ctx->ssl, buf, wlen);
        if (n > 0)
        {
            *out_n = (size_t)n;
            return RH_OK;
        }
        int se = SSL_get_error(ctx->ssl, n);
        if (se == SSL_ERROR_WANT_READ || se == SSL_ERROR_WANT_WRITE) continue;
        return RH_ERR_IO;
    }
}

static void tls_close(rh_transport *t)
{
    rh_tls_ctx *ctx = (rh_tls_ctx *)t->ctx;
    if (ctx)
    {
        if (ctx->ssl)
        {
            SSL_shutdown(ctx->ssl); // best-effort close_notify - ignore result
            SSL_free(ctx->ssl);
        }
        if (ctx->ssl_ctx) SSL_CTX_free(ctx->ssl_ctx);
        if (ctx->fd >= 0) close(ctx->fd);
        free(ctx);
    }
    t->ctx = NULL;
}

rh_err rh_transport_tls_init(rh_transport *t, int fd, const char *hostname, int insecure)
{
    if (!t || fd < 0 || !hostname) return RH_ERR_INVAL;

    rh_tls_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return RH_ERR_MEM;
    ctx->fd = fd;

    ctx->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx->ssl_ctx)
    {
        LOG_DEBUG("[!] SSL_CTX_new failed");
        goto fail;
    }

    if (!insecure)
    {
        SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_PEER, NULL);
        if (!SSL_CTX_set_default_verify_paths(ctx->ssl_ctx))
        {
            LOG_DEBUG("[!] failed to load default trust store");
            goto fail;
        }
    }

    /* 
     * insecure = 1 : leave verify mode at OpenSSL's default (SSL_VERIFY_NONE)
     * explicit empty branch so the "why no verification" is visible at the call site
     * not just an absence if code.
     * */

    ctx->ssl = SSL_new(ctx->ssl_ctx);
    if (!ctx->ssl)
    {
        LOG_DEBUG("[!] SSL_new failed");
        goto fail;
    }

    if (!SSL_set_fd(ctx->ssl, fd))
    {
        LOG_DEBUG("[!] SSL_set_fd failed");
        goto fail;
    }

    SSL_set_tlsext_host_name(ctx->ssl, hostname); // SNI
    
    if (!insecure && !SSL_set1_host(ctx->ssl, hostname))
    {
       /*
        * tells OpenSSL to check the cert's subject/SAN against
        * `hostname` during SSL_connect's verification - without this,
        * SSL_CTX_set_verify only checks the chain of trust, NOT that
        * the cert is actually for the host we're talking to. 
        * */
        LOG_DEBUG("[!] SSL_set1_host failed");
        goto fail;
    }

    int rc = SSL_connect(ctx->ssl);
    if (rc != 1)
    {
        LOG_DEBUG("[!] TLS handshake failed (SSL_connect rc=%d, SSL_get_error=%d)", rc,
                    SSL_get_error(ctx->ssl, rc));
        goto fail;
    }

    if (!insecure)
    {
        long vr = SSL_get_verify_result(ctx->ssl);
        if (vr != X509_V_OK)
        {
            LOG_DEBUG("[!] certificate verification failed: %s", X509_verify_cert_error_string(vr));
            goto fail;
        }
    }

    t->ctx      = ctx;
    t->read     = tls_read;
    t->write    = tls_write;
    t->close    = tls_close;
    return RH_OK;


fail:
    if (ctx->ssl) SSL_free(ctx->ssl);
    if (ctx->ssl_ctx) SSL_CTX_free(ctx->ssl_ctx);
    free(ctx);
    /* fd deliberately NOT closed here - same "only own fd on success"
     * contract as rh_transport_tcp_init. caller still owns it
     */
    return RH_ERR_TLS;
}
