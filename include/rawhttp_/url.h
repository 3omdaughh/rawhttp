#ifndef RAWHTTP_URL_H
#define RAWHTTP_URL_H

#include <stdint.h>
#include "rawhttp_/error.h"

/*
 * Parsed URL. Owns all its strings - always call rh_url_free() when done,
 * even on partial success paths that never happen (kept simple: parse
 * either fully succeeds and populates every field, or fails and leaves
 * *out safe to free/no-op).
 */

typedef struct 
{
    char *scheme;   /* URL scheme http or https, all lowercased */
    char *host;     /* hostname or IP literal */
    char *path;     /* path of the url */
    uint16_t port;
} rh_url;

/*
 * Parses url_str of the form scheme://host[:port][/path][?query].
 * No regex - hand-rolled scan for "://", then last ':' in the authority
 * for an optional port, then the first '/' for the path.
 *
 * Only "http" and "https" schemes are supported (matches this project's
 * scope). Missing path defaults to "/". Missing port defaults to 80
 * (http) or 443 (https).
 *
 * On success returns RH_OK and *out is fully populated (free with
 * rh_url_free). On failure returns RH_ERR_PARSE and *out is left zeroed.
 */

rh_err rh_url_parse(const char *url_str, rh_url *out);

/* Frees all strings owned by *u. Safe to call twice. */
void rh_url_free(rh_url *u);

#endif /* RAWHTTP_URL_H */
