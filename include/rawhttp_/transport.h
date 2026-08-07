#ifndef RAWHTTP_TRANSPORT_H
#define RAWHTTP_TRANSPORT_H

#include <stddef.h>
#include <time.h>

#include "rawhttp_/error.h"

typedef struct rh_transport rh_transport;

typedef rh_err (*rh_transport_read_fn)(rh_transport *t, void *buf, size_t len, size_t *out_n);
typedef rh_err (*rh_transport_write_fn)(rh_transport *t, const void *buf, size_t len, size_t *out_n);
typedef void (*rh_transport_close_fn)(rh_transport *t);
/*
 * Returns the underlying fd for poll()/select() - works for both plain TCP and TLS (TLS is layered on top of the same fd; a readable fd is
 * a good-enough signal for idle-detection purpose even though it doesn't guarantree a complete decrypted record is ready).
 * */
typedef int (*rh_transport_get_fd_fn)(rh_transport *t);

struct rh_transport
{
    void *ctx; /* opaque - a plain fd wrapper or an SSL/SSL_CTX pair for TLS */ 
    rh_transport_read_fn    read;
    rh_transport_write_fn   write;
    rh_transport_close_fn   close; /* release ctx and whatever it owns (fd, SSL objects) */
    rh_transport_get_fd_fn  get_fd;

    /*
     * set automatically (by tcp_read/tls_read) on the first successful read with n > 0
     * bytes, via CLOCK_MONOTONIC. This is the single source of truth for "time for first
     * byte" - it works identically for the normal request/response path, raw mode, and 
     * smuggle mode since all three ultimately read through the same transport read 
     * function. first_byte_recorded stays 0 if nothing was ever received (e.g. connect
     * succeeded but the peer sent nothing before closing or timing out)
     * */

    struct timespec first_byte_at;
    int first_byte_recorded;
};

/*
 * Warps an already-connected palin TCP fd. Takes ownership of fd ONLY on success - 
 * the transport's close() will close() it. On failure, fd is left untouched; the caller
 * still owns it and must close it.
 * */
rh_err rh_transport_tcp_init(rh_transport *t, int fd);

/*
 * Establishes TLS over and already-connected plain TCP fd. 
 * Same onwership contracte as rh_transport_tcp_init, takes ownership of fd only on 
 * success; on failure the caller still owns fd.
 *
 * `hostname` drives both SNI (the ClientHello's server_name extension) and certificate 
 * hostname verification.
 *
 * Certificate verification is ON by default (chain-of-trust via the system trust store,
 * plus hostname match against `hostname`). Pass insecure=1 to skip verification entirely
 * useful against lab/pentest tragets with self-signed certs, but deliberately and explicit
 * opt-in flag rather than something that can be silently disabled by a config default,
 * since this is exactly the kind of check a "helpful" library quietly skips and this 
 * project exist to not do that.
 *
 * Returns RH_ERR_TLS on any handshake or verification failure.
 * */
rh_err rh_transport_tls_init(rh_transport *t, int fd, const char *hostname, int insecure);

/*
 * Milliseconds elapsed from *a to *b (both CLOCK_MONOTONIC timestamps), as a double for
 * sub-millisecond precision in reporting.
 * */
double rh_timespec_diff_ms(const struct timespec *a, const struct timespec *b);

#endif /* RAWHTTP_TRANSPORT_H */
