#define _POSIX_C_SOURCE 200809L

#include "rawhttp_/socket.h"

#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

rh_err rh_tcp_connect(const char *host, uint16_t port, int *out_fd)
{
    if (!host || !out_fd) return RH_ERR_INVAL;

    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%u", port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family     = AF_UNSPEC; // try IPv6 & IPv4
    hints.ai_socktype   = SOCK_STREAM; 

    struct addrinfo *results = NULL;
    int gai_err = getaddrinfo(host, port_str, &hints, &results);
    if (gai_err != 0)
    {
        LOG_DEBUG("[!] getaddrinfo(%s:%u) failed: %s", host, port, gai_strerror(gai_err));
        return RH_ERR_DNS;
    }

    int fd = -1;
    for (struct addinfo *rp = results; rp != NULL; rp = rp->ai_next)
    {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break // connected
        close(fd);
        fd = -1;
    }

    freeaddrinfo(results); // always set to free, whether success or not
    if (fd < 0)
    {
        LOG_DEBUG("[!] connect(%s,%u) failed on all candidate addresses", host, port);
        return RH_ERR_CONNECT;
    }

    *out_fd = fd;
    return RH_OK;
}
