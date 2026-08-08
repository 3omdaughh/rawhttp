#include "rawhttp_/fuzz.h"

#include <string.h>

#define RH_FUZZ_LONG1_LEN 1000
#define RH_FUZZ_LONG2_LEN 10000

static char long1_buf[RH_FUZZ_LONG1_LEN];
static char long2_buf[RH_FUZZ_LONG2_LEN];
static int long_bufs_ready = 0;

static void ensure_long_bufs(void)
{
    if (!long_bufs_ready)
    {
        memset(long1_buf, 'A', sizeof(long1_buf));
        memset(long2_buf, 'A', sizeof(long2_buf));
        long_bufs_ready = 1;
    }
}

static const rh_fuzz_payload default_payloads[] = 
{
    {"empty", "", 0},
    {"long-1000-A", long1_buf, RH_FUZZ_LONG1_LEN},
    {"long-10000-A", long2_buf, RH_FUZZ_LONG2_LEN},
    {"crlf-injection", "\r\nX-Injected: true", sizeof("\r\nX-Injected: true") - 1},
    {"null-byte", "\x00", sizeof("\x00") - 1},
    {"control-chars", "\x01\x02\x03\x1b\x7f", sizeof("\x01\x02\x03\x1b\x7f") - 1},
    {"path-traversal", "../../../../../../etc/passwd", sizeof("../../../../../../etc/passwd") - 1},
    {"format-string", "%s%s%s%s%n", sizeof("%s%s%s%s%n") - 1},
    {"sql-quote", "' OR '1'='1", sizeof("' OR '1'='1") - 1},
    {"overlong-utf8-null", "\xc0\x80", sizeof("\xc0\x80") - 1},
    {"negative-number", "-1", sizeof("-1") - 1},
    {"huge-number", "99999999999999999999", sizeof("99999999999999999999")},
};

size_t rh_fuzz_default_payloads(const rh_fuzz_payload **out)
{
    ensure_long_bufs();
    *out = default_payloads;
    return sizeof(default_payloads) / sizeof(default_payloads[0]);
}

/*
 * Plain byte-substring search (not strstr - haystack/needle aren't necessarily NUL-terminated,
 * and the whole point of several default payloads is that they legitimately contain embedded
 * NULs). Returns the offset of the first match or -1
 * */

static long find_substr(const char *haystack, size_t haystack_len, const char *needle,
                size_t needle_len)
{
    if (needle_len == 0 || needle_len > haystack_len) return -1;
    for (size_t i = 0; i + needle_len <= haystack_len; i++)
        if (memcmp(haystack+i, needle, needle_len) == 0) return (long)i;
    return -1;
}

rh_err rh_fuzz_apply(const rh_buf *tmpl, const char *marker, const void *payload,
                size_t payload_len, rh_buf *out)
{
    if (!tmpl || !marker || !out || (!payload && payload_len > 0)) return RH_ERR_INVAL;
    size_t marker_len = strlen(marker);
    if (marker_len == 0) return RH_ERR_INVAL;

    rh_err e = rh_buf_init(out, tmpl->len);
    if (e != RH_OK) return e;

    size_t pos = 0;
    while (pos < tmpl->len)
    {
        long found = find_substr(tmpl->data + pos, tmpl->len - pos, marker, marker_len);
        if (found < 0)
        {
            e = rh_buf_append(out, tmpl->data + pos, tmpl->len - pos);
            if (e != RH_OK)
            {
                rh_buf_free(out);
                return e;
            }
            break;
        }

        size_t found_abs = pos+(size_t)found;
        e = rh_buf_append(out, tmpl->data + pos, found_abs - pos);
        if (e != RH_OK)
        {
            rh_buf_free(out);
            return e;
        }
        if (payload_len > 0)
        {
            e = rh_buf_append(out, payload, payload_len);
            if (e != RH_OK)
            {
                rh_buf_free(out);
                return e;
            }
        }
        pos = found_abs + marker_len;
    }

    return RH_OK;
}
