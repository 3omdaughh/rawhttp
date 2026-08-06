#ifndef RAWHTTP_SMUGGLE_H
#define RAWHTTP_SMUGGLE_H

#include "rawhttp_/buf.h"
#include "rawhttp_/error.h"

typedef enum
{
    RH_SMUGGLE_CL_TE, /* front-end trusts Content-Length, back-end trusts Transfer-Encoding */
    RH_SMUGGLE_TE_CL, /* front-end trusts Transfer-Encoding, back-end trusts Transfer-Encoding */
    RH_SMUGGLE_CL_CL, /* front-end trusts Content-Length, back-end trusts Content-Length */
} rh_smuggle_technique;

/* Parses "cl.te" | "te.cl" | "cl.cl" case-insensitive. */

rh_err rh_smuggle_parse_technique(const char *name, rh_smuggle_technique *out);

/*
 * Builds a raw HTTP/1.1 POST request (into `out`, which this function rh_buf_init's) implementing this 
 * classic shape of the given desync technique - byte-for-byte matching PortSwigger's canonical CL.TE/TE.CL
 * examples when defaults are used (verified in tests).
 *
 * `host_header` and `path` fill the Host Header aand request line. `smuggle` is the raw bytes representing 
 * waht should be left dangling for the desync side to misinterpret as the start of the next request on the 
 * connection (e.g. "GET /404 HTTP/1.1\r\nX-Ignore: X" for a real PoC, or a short marker like "SMUGGLED" for 
 * a detectable-but-inert test). Must not be empty.
 *
 * cl1_override / cl2_override let the caller override the auto-computed Content-Length value(s) instead of
 * the "correct" one that lines up exactly with `smuggled` - this is what makes off-by-one and other boundary
 * -condition testing possible, per the project's "trust the caller completely" philosophy. Pass -1 for 
 *  either to use the auto computed value.
 *
 *  cl1_override applies  to: 
 *      - CL_TE / TE_CL: the request's single Content-Length header
 *      - CL_CL: the FIRST Content-Length header
 *  cl2_override applies only to CL_CL's SECOND Content-Length header (ignored for CL.TE/TE.CL).
 * */

rh_err rh_smuggle_build(rh_smuggle_technique technique, const char *host_header, const char *path,
                        const char *smuggled, long cl1_override, long cl2_override, rh_buf *out);

#endif /* RAWHTTP_SMUGGLE_H */
