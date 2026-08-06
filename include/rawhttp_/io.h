#ifndef RAWHTTP_IO_H
#define RAWHTTP_IO_H

#include <stddef.h>

#include "rawhttp_/buf.h"
#include "rawhttp_/error.h"
#include "rawhttp_/transport.h"

/*
 * loops t->write() until every byte in `data`/`len` is on the wire,
 * handling partial writes (the transport's write() may send fewer bytes than asked, same as a raw send() can).
 *
 * operations on a rh_transport instead of raw fd, so the exact same loop
 * works whether the transport underneath is a plain socket or TLS
 * */

rh_err rh_send_all(rh_transport *t, const void *data, size_t len);

/*
 * loops t-> read() into `out` (must alread be rh_buf_init'd)
 * until the peer closes (read() report EOF) or an unrecoverable error occurs.
 * Never assumes one read() call is the whole response - TCP is a byte 
 * stream, not a message stream, so this keeps reading and growing the buffer
 * until EOF
 */

rh_err rh_recv_all(rh_transport *t, rh_buf *out);

/* One t->read() call, append to `out`. unlike rh_recive_all this does not loop
 * until EOF - it returns after a single successful read so the called can check
 * its own framing condition after every call. This is what makes Content-Length/chunked reads work correctly on keep-alive connection, where the peer never closes.
 * On peer close, *out_eof is set to 1 and RH_OK is returned with no
 * bytes appended. On any read, *out_eof is 0.
 */
rh_err rh_recv_some(rh_transport *t, rh_buf *out, int *out_eof);

/*
 * Reads into `out` until EITHER the peer closes (clean EOF) OR no new
 * data arrives within `idle_timeout_ms` of the last read - whichever
 * comes first. Both outcomes return RH_OK; there's no way for the
 * caller to distinguish "peer closed" from "went quiet" from the
 * return value alone, which is fine for this function's purpose (raw/
 * smuggle mode dumping whatever came back).
 *
 * This exists because "read until EOF" (rh_recv_all) hangs forever
 * against any server that keeps the connection open after responding -
 * which is the HTTP/1.1 default (keep-alive), not an edge case. Uses
 * transport->get_fd() + poll() to detect the idle gap.
 */
rh_err rh_recv_until_idle(rh_transport *t, rh_buf *out, int idle_timeout_ms);

#endif /* RAWHTTP_IO_H */
