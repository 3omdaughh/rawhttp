#ifndef RAWHTTP_IO_H
#define RAWHTTP_IO_H

#include <stddef.h>

#include "rawhttp_/buf.h"
#include "rawhttp_/error.h"

/*
 * loops send() until every byte in `data`/`len` is on the wire,
 * handling partial writes and EINTR. Uses MSG_NOSIGNAL so a peer that
 * closes mid-write gives us RH_ERR_IO instead of killing the process
 * with SIGPIPE.
 */

rh_err rh_send_all(int fd, const void *data, size_t len);

/*
 * loops recv() into `out` (must already be rh_buf_init'd) until
 * the peer closes (recv returns 0) or an unrecoverable error occurs.
 * Never assumes one recv() call is the whole response - TCP is a byte
 * stream, not a message stream, so this keeps reading and growing the
 * buffer until EOF.
 */

rh_err rh_recv_all(int fd, rh_buf *out);

#endif /* RAWHTTP_IO_H */
