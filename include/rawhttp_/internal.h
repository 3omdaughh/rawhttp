#ifndef RAWHTTP_INTERNAL_H
#define RAWHTTP_INTERNAL_H

/*
 * Shared between response.c and chunked.c only. Not installed/exposed as
 * part of librawhttp's public API (that's everything under
 * include/rawhttp/ *except* this file, conceptually - kept here rather
 * than duplicated because header-line parsing has real correctness
 * subtleties (the colon-whitespace strictness in particular) that must
 * behave identically for both regular headers and chunked trailers.
 */

#include "rawhttp_/error.h"
#include "rawhttp_/response.h"

rh_err rh__headers_push(rh_response *out, char *name, char *value);

rh_err rh__parse_header_line(const char *line, size_t len, rh_response *out);

#endif /* RAWHTTP_INTERNAL_H */
