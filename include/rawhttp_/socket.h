#ifndef RAWHTTP_SOCKET_H
#define RAWHTTP_SOCKET_H

#include <stdint.h>

#include "rawhttp_/error.h"


/*
 * Resolves `host` via getaddrinfo() (AF_UNSPEC, SOCK_STREAM - tries IPv6
 * and IPv4) and connects to `port`, trying each returned address in turn
 * until one succeeds. On success, *out_fd is a connected socket (caller
 * owns it, close() when done) and RH_OK is returned.
 *
 * Returns RH_ERR_DNS if resolution itself fails, or RH_ERR_CONNECT if
 * resolution succeeded but every candidate address refused/failed to
 * connect.
*/

rh_err rh_tcp_connect(const char *host, uint16_t port, int *out_fd);o

#endif /* RAWHTTP_SOCKET_H */
