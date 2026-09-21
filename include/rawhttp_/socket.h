#ifndef RAWHTTP_SOCKET_H
#define RAWHTTP_SOCKET_H

#include <stdint.h>

#include "rawhttp_/error.h"


/*
 * Process-wide connection defaults, read by rh_tcp_connect(). Set once from
 * the CLI before any connect happens; after that they're read-only, which is
 * what makes them safe to share across the scan worker threads (T4.2) without
 * locking. Kept as global config rather than extra rh_tcp_connect() params so
 * every mode (normal/raw/smuggle/fuzz/scan) inherits timeouts and proxying
 * without threading the same two values through every call site.
 */

/*
 * Applies to connect(), recv() and send(). <= 0 (the default) means "no
 * timeout" - classic blocking behavior. A positive value bounds a hung
 * connect and any single read/write, surfacing as RH_ERR_TIMEOUT.
 */
void rh_socket_set_default_timeout(int timeout_ms);

/*
 * Routes every subsequent rh_tcp_connect() through an HTTP proxy via a
 * CONNECT tunnel (Burp/upstream). `host` NULL clears it. The real target
 * host:port is tunnelled, so TLS still terminates end-to-end at the target.
 */
void rh_socket_set_proxy(const char *host, uint16_t port);

/*
 * Resolves `host` via getaddrinfo() (AF_UNSPEC, SOCK_STREAM - tries IPv6
 * and IPv4) and connects to `port`, trying each returned address in turn
 * until one succeeds. Honors the timeout/proxy config above. On success,
 * *out_fd is a connected socket (caller owns it, close() when done) and
 * RH_OK is returned.
 *
 * Returns RH_ERR_DNS if resolution itself fails, RH_ERR_CONNECT if every
 * candidate address refused/failed, RH_ERR_TIMEOUT if a connect (or the
 * proxy CONNECT handshake) exceeded the configured timeout.
*/

rh_err rh_tcp_connect(const char *host, uint16_t port, int *out_fd);

#endif /* RAWHTTP_SOCKET_H */
