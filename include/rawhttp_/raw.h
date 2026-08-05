#ifndef RAWHTTP_RAW_H
#define RAWHTTP_RAW_H

#include <stdint.h>

#include "rawhttp_/buf.h"
#include "rawhttp_/error.h"

/* 
 * Parses "host:port" (both parts required - raw mode has no scheme to imply a default port)
 * *host_out is heap-allocated, caller frees it
 * */

rh_err rh_raw_parse_target(const char *target, char **host_out, uint16_t *port_out);

/* 
 * Reads `path` verbatim into `out` (binary-safe - no text interpretation of any kind)
 * This is he whole point of raw mode : what's in the file is exactly what goes on the wire
 *
 * If `convert_crlf` is set, every lone '\n' not already preceded by '\r' is turned into 
 * "\r\n" - a convenience for writing payload files with a normal text editor, since editor
 * default to bare \n. Exisiting "\r\n" sequences are left untouched (never doubled).
 * Default (convert_crlf=0) is a true byte-for-byte pass through.
 * */

rh_err rh_raw_load_file(const char *path, int convert_crlf, rh_buf *out);

/*
 * Connects to host:port (TLS if use_tls is set, with the same insecure/verification 
 * semantics as the rest of the client), writes `payload` verbatim via rh_send_all, then
 * reads until the peer closes (or an error/timeout) and returns everything received in 
 * `response_out` (must be rh_buf_init'd by the caller... actually this function calls 
 * rh_buf_init on it - see .c for the exact contract).
 *
 * Deliberately does NOT attempt to parse the response as HTTP - a malformed or multi-response
 * byte stream (e.g. a smuggling payload where two requests were concatenated into `paylaod`)
 * is exactly what this mode exist ot observe raw, un-reinterpreted.
 * */

rh_err rh_raw_send_and_dump(const char *host, uint16_t port, int use_tls, int insecure, 
                            const rh_buf *payload, rh_buf *response_out);

#endif /* RAWHTTP_RAW_H */
