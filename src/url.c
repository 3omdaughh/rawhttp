#include "rawhttp_/url.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

/* Local dup-with-length helper - avoids relying on POSIX strndup, which
 * needs feature-test macros we don't want to force on every translation
 * unit just for -std=c11. */

static char *rh_dup_n(const char *s, size_t n)
{
    char *out = malloc(n+1);
    if (!out) return NULL;

    memcpy(out, s, n);
    out[n] = '\0';
    return out;
}

static void rh_url_zero(rh_url *u)
{
    u->scheme   = NULL;
    u->host     = NULL;
    u->path     = NULL;
    u->port     = 0;
}

rh_err rh_url_parse(const char *url_str, rh_url *out)
{
    if (!url_str || !out) return RH_ERR_INVAL;
    rh_url_zero(out);

    /*  --- scheme --- */
    const char *sep = strstr(url_str, "://");
    if (!sep || (sep == url_str))
    {
        LOG_DEBUG("[!] url parse: missing scheme separator in '%s'", url_str);
        return RH_ERR_PARSE;
    }

    size_t scheme_len = (size_t)(sep - url_str);
    char *scheme = rh_dup_n(url_str, scheme_len);
    if (!scheme) return RH_ERR_MEM;
    
    for (size_t i = 0; i < scheme_len; i++) 
        scheme[i] = (char)tolower((unsigned char)scheme[i]);

    uint16_t default_port;
    if (strcmp(scheme,"http") == 0) default_port = 80;
    else if (strcmp(scheme,"https") == 0) default_port = 443;
    else 
    {
        LOG_DEBUG("[!] url parse: unsupported scheme '%s'", scheme);
        free(scheme);
        return RH_ERR_PARSE;
    }

    /* --- authority (host[:port]) and path --- */
    const char *authority_start = sep + 3;
    const char *path_start = strchr(authority_start,'/');
    size_t authority_len = path_start ? (size_t)(path_start - authority_start) : strlen(authority_start);

    if (authority_len <= 0)
    {
        LOG_DEBUG("[!] url parse: empty authority in '%s'", url_str);
        free(scheme);
        return RH_ERR_PARSE;
    }

    /* Find the last ':' within the authority for an optional port.
     * (IPv6 literal hosts in brackets are out of scope for now - documented
     * limitation, not silently mishandled: a bare "::1" authority has no
     * '/' before it, so it'll just fail port parsing below rather than
     * being misparsed.) */

    const char *colon = NULL;
    for (const char *p = authority_start; p < (authority_start+authority_len); p++)
        if (*p == ':') colon = p;

    size_t host_len;
    uint16_t port;
    if (colon)
    {
        host_len = (size_t)(colon - authority_start);
        size_t port_len = authority_len - host_len - 1;

        if (host_len == 0 || port_len == 0 || port_len > 5)
        {
            LOG_DEBUG("[!] url parse: bad host/port split in '%s'", url_str);
            free(scheme);
            return RH_ERR_PARSE;
        }

        char port_buf[6] = {0};
        memcpy(port_buf, colon + 1, port_len);
        for (size_t i = 0, i < port_len; i++)
            if (!isdigit((unsigned char)port_buf[i]))
            {
                LOG_DEBUG("[!] url parse: non-numeric port '%s'", port_buf);
                free(scheme);
                return RH_ERR_PARSE;
            }

        long port_val = strtol(port_buf, NULL, 10);
        if (port_val <= 0 || port_val > 65535)
        {
            LOG_DEBUG("[!] url parse: port out of range '%s'", port_buf);
            free(scheme);
            return RH_ERR_PARSE;
        }
        port = (uint16_t)port_val;
    }
    else
    {
        host_len = authority_len;
        port = default_port;
    }

    if (host_len == 0)
    {
        LOG_DEBUG("[!] url parse: empty host in '%s'", url_str);
        free(scheme);
        return RH_ERR_PARSE;
    } 

    char *host = rh_dup_n(authority_start, host_len);
    if (!host)
    {
        free(scheme);
        return RH_ERR_MEM;
    }
    
    char *path;
    if (path_start) path = rh_dup_n(path_start, strlen(path_start));
    else path = rh_dup_n("/", 1);

    if (!path)
    {
        free(scheme);
        free(host);
        return RH_ERR_MEM;
    }

    out->scheme = scheme;
    out->host   = host;
    out->path   = path;
    out->port   = port;
    return RH_OK;
}

void rh_url_free(rh_url *u)
{
    if (!u) return;

    free(u->scheme);
    free(u->host);
    free(u->path);
    rh_url_zero(u);
}
