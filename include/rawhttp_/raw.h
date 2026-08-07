#ifndef RAWHTTP_RAW_H
#define RAWHTTP_RAW_H

#include <stdint.h>

#include "rawhttp_/buf.h"
#include "rawhttp_/error.h"
#include "rawhttp_/transport.h"

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
 * semantics as the rest of the client), writes `payload` verbatim via rh_send_all, then reads whatever comes back until
 * either the peer closes OR a short idle gap with no new data (see rh_recv_until_idle) - NOT a strict wait-for-EOF, since that
 * would hang forever against any server that keeps the connection open after responding (HTTP/1.1 keep-alive is the default).
 * Returns everything received in `response_out` (this function calls rh_buf_init on it).
 *
 * Deliberately does NOT attempt to parse the response as HTTP - a malformed or multi-response
 * byte stream (e.g. a smuggling payload where two requests were concatenated into `paylaod`)
 * is exactly what this mode exist ot observe raw, un-reinterpreted.
 *
 * `timing_out` is optional (pass NULL to skip) if given, filled in with TTFB/total timing measured from
 * just after connect. A response that's suspiciously used to detect a desync that causes the backend to 
 * hang waiting for more of a request that never comes.
 * */

rh_err rh_raw_send_and_dump(const char *host, uint16_t port, int use_tls, int insecure, 
                            const rh_buf *payload, rh_buf *response_out,
                            rh_timing *timing_out);

/*
 * sends `payloads[0..count]` back-to-back on ONE connection (no waiting for a response between
 * them, no reconnection), then does a single rh_recv_until_idle collecting everything the peer
 * sends back into `combined_resposne_out` (this function calls rh_buf_init on it).
 *
 * Deliberately does NOT wait for/parse a response after each payload before sending the next.
 * Two reasons: first, without a protocol-aware framing (which raw mode intentionally doesn't do)
 * there's no reliable way to know exactly when one response ends and the next begins, so waiting
 * on an idle timeout between sends risks racing against the peer's OWN read timeout and corrupting
 * the very sequencing this is meant to test.
 * Second, and more importantly: firing requests back-to-back without waiting is the actual 
 * mechanism smuggling confirmation needs - send a request that may desync the connection, then
 * immediately send a normal follow-up request, and see whether the combined raw response stream
 * looks wrong (extra/missing responses, a response that doesn't match the follow-up, an error page)
 * that mismatch is what proves a desync happen, and it's far more visible in a fast-fired pair than
 * a politely-spaced one.
 *
 * `timing_out` is optional (pass NULL to skip) - see rh_raw_send_and_dump. Measured from connect to the
 * first byte of ANY response in the combined stream, and to the end of the whole combined read.
 * */

rh_err rh_raw_send_sequence(const char *host, uint16_t port, int use_tls, int insecure, 
                    const rh_buf *payloads, size_t count, rh_buf *combined_response_out,
                    rh_timing *timing_out);

#endif /* RAWHTTP_RAW_H */
