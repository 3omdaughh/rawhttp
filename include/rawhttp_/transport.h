#ifndef RAWHTTP_TRANSPORT_H
#define RAWHTTP_TRANSPORT_H

#include <stddef.h>

#include "rawhttp_/error.h"

typedef struct rh_transport rh_transport;

typedef rh_err (*rh_transport_read_fn)(rh_transport *t, void *buf, size_t len, size_t *out_n);
typedef rh_err (*rh_transport_write_fn)(rh_transport *t, const void *buf, size_t len, size_t *out_n);
typedef void (*rh_transport_close_fn)(rh_transport *t);

struct rh_transport
{
    void *ctx; /* opaque - a plain fd wrapper or an SSL/SSL_CTX pair for TLS */ 
    rh_transprot_read_fn;
    rh_transprot_write_fn;
    rh_transprot_close_fn; /* release ctx and whatever it owns (fd, SSL objects) */
};

rh_err rh_transport_tcp_init(rh_transport *t, int fd);

rh_err rh_transport_tls_init(rh_transport *t, int fd, const char *hostname, int insecure);

#endif /* RAWHTTP_TRANSPORT_H */
