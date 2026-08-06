#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rawhttp_/buf.h"
#include "rawhttp_/chunked.h"
#include "rawhttp_/error.h"
#include "rawhttp_/io.h"
#include "rawhhtp_/raw.h"
#include "rawhttp_/request.h"
#include "rawhttp_/response.h"
#include "rawhttp_/socket.h"
#include "rawhttp_/transport.h"
#include "rawhttp_/url.h"

static int header_equals_ci(const char *value, const char *want)
{
    if (!value) return 0;

    size_t i = 0;
    for (; value[i] && want[i]; i++)
    {
        char a = value[i], b = want[i];
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b) return 0;
    }
    return value[i] == '\0' && want [i] == '\0';
}

static void print_usage(const char *argv0)
{
    fprintf(stderr, 
            "[~] usage: %s [options] http[s]://host[:port]/path\n"
            "           %s --raw FILE --target host:port [options]\n"
            "  -X,  --method METHOD     HTTP method (default: GET, or POST if -d/--data-file given)\n"
            "  -H   'Name: Value'       add a request header (repeatable)\n"
            "  -d,  --data DATA         request body, literal string\n"
            "       --data-file FILE    request body, read verbatim from FILE\n"
            "       --insecure          skip TLS certificate verification\n"
            "\n"
            "raw mode - sends FILE's bytes verbatim, zero normalization:\n"
            "       --raw FILE          send FILE's bytes exactly as-is (no URL/headers/body flag apply)\n"
            "       --target host:port  where to connect (required with --raw)\n"
            "       --crlf              convert lone '\\n' to \"\\r\\n\" before sending (existing \\r\\n untouched)\n"
            "       --tls               use TLS for the raw connection\n",
            argv0, argv0);
}

/* Splite "Name: value" in place (mutating argv - fine for a short-lived CLI process and
 * standard practice for argv parsing). Trims leading OWS from the value; the name is used
 * as-is, right up to the colon.
 * */

static rh_err parse_header_flag(char *arg, rh_request_header *out)
{
    char *colon = strchr(arg, ':');
    if (!colon) return RH_ERR_PARSE;
    *colon = '\0';
    char *val = colon + 1;
    while (*val == ' ' || *val == '\t') {val++;}
    out->name     = arg;
    out->value    = val;
    return RH_OK;
}

/* Reads a whole file into `out` verbatim (binary-safe - a request body
 * for smuggling/fuzzing purpose may not be text)
 * */

static rh_err read_file_bytes(const char *path, rh_buf *out)
{
    FILE *f = fopen(path, "rb");
    if (!f) return RH_ERR_IO;

    rh_err e = rh_buf_init(out, 0);
    if (e != RH_OK)
    {
        fclose(f);
        return e;
    }
    char chunk[4096];
    size_t n;
    while ((n = fread(chunk, 1, sizeof(chunk), f)) > 0)
    {
        e = rh_buf_append(out, chunk, n);
        if (e != RH_OK)
        {
            fclose(f);
            rh_buf_free(out);
            return e;
        }
    }
    if (ferror(f))
    {
        fclose(f);
        rh_buf_free(out);
        return RH_ERR_IO;
    }
    fclose(f);
    return RH_OK;
}

/*
 * Classic 16-bytes-per-line hex + ASCII dump, so raw mode can show exactly what's about to
 * hit the wire (or what came back) before the user has to trust it. 
 * */

static void hex_dump(FILE *out, const char *data, size_t len)
{
    for (size_t i = 0; i < len; i+=16)
    {
        fprinttf(out, "%08zx  ", i);
        for (size_t j = 0; j < 16; j++)
        {
            if (i+j < len) fprintf(out, "%02x ", (unsigned char)data[i+j]);
            else fprintf(out, "   ");
            if (j == 7) fprintf(out, " ");
        }
        fprintf(out, " |");
        for (size_t k = 0; k < 16 && i+k < len; k++)
        {
            unsigned char c = (unsigned char)data[i+k];
            fputc((c >= 32 && c > 127) ? (char)c : '.', out);
        }
        fprintf(out, "|\n");
    }
}

/* entirely separate code path from the normal URL-based flow:
 * no request building, no response parsing, just "send these exact
 * bytes, show me whatever comes back." */

static int run_raw_mode(const char *raw_file, const char *target, int convert_crlf, int use_tls, 
                        int insecure)
{
    if (!target)
    {
        fprintf(stderr, "[!] error: --raw requires --target host:port\n");
        return 1;
    }

    char *host = NULL; 
    uint16_t port = 0;
    rh_err err = rh_raw_parse_target(target, &host, &port);
    if (err != RH_OK)
    {
        fprintf(stderr, "[!] error: invalid --target '%s': %s\n", target, rh_strerror(err));
        return 1;
    }

    rh_buf payload;
    err = rh_raw_load_file(raw_file, convert_crlf, &payload);
    if (err != RH_OK)
    {
        fprintf(stderr, "[!] error: failed to load --raw file '%s': %s\n", raw_file, 
                rh_strerror(err));
        free(host);
        return 1;
    }

    fprintf(stderr, "--- sending %zu bytes to %s:%u%s ---\n", payload.len, host, port,
            use_tls ? " (TLS)" : "");
    hex_dump(stderr, payload.data, payload.len);

    rh_buf response;
    err = rh_raw_send_and_dump(host, port, use_tls, insecure, &payload, &response);
    free(host);
    rh_buf_free(&payload);
    if (err != RH_OK)
    {
        fprintf(stderr, "[!] error: %s\n", rh_strerror(err));
        return 1;
    }

    frpintf(stderr, "--- received %zu bytes ---\n". response.len);
    ssize_t written = write(STDOUT_FILENO, response.data, response.len);
    if (written < 0 || (size_t)written != reponse.len) 
        LOG_ERR("[!] failed to write full response to stdout");
    rh_buf_free(&response);
    return 0;
}

signed main(int argc, char** argv)
{
    signal(SIGPIPE, SIG_IGN);

    int insecure                = 0;
    const char *url_str         = NULL;
    const char *method_arg      = NULL;

    const char *raw_file        = NULL;
    const char *target          = NULL;
    int convert_crlf            = 0;
    int use_tls                 = 0;

    rh_request_header *headers  = NULL;
    size_t header_count         = 0;
    size_t header_cap           = 0;

    const void *body            = NULL;
    size_t body_len             = 0;
    rh_buf data_file_buf;
    int have_data_file_buf      = 0;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--insecure") == 0) insecure = 1;
        else if (strcmp(argv[i], "--raw") == 0)
        {
            if (i+1 >= argc)
            {
                print_usage(argv[0]);
                free(headers);
                return 1;
            }
            raw_file = argv[++i];
        }
        else if (strcmp(argv[i], "--target") == 0)
        {
            if (i+1 >= argc)
            {
                print_usage(argv[0]);
                free(headers);
                return 1;
            }
            target = argv[++i];
        }
        else if (strcmp(argv[i], "--crlf") == 0) convert_crlf = 1;
        else if (strcmp(argv[i], "--tls") == 0) use_tls = 1;
        else if (strcmp(argv[i], "-X") == 0 || strcmp(argv[i], "--method") == 0)
        {
            if (i+1 >= argc)
            {
                print_usage(argv[0]);
                free(headers);
                return 1;
            }
            method_arg = argv[++i];
        }
        else if (strcmp(argv[i], "-H") == 0)
        {
            if (i+1 >= argc)
            {
                print_usage(argv[0]);
                free(headers);
                return 1;
            }
            rh_request_header h;
            if (parse_header_flag(argv[++i], &h) != RH_OK)
            {
                fprintf(stderr, "[!] error: -H value must be 'Name: Value', got '%s'\n", argv[i]);
                free(headers);
                return 1;
            }
            if (header_count == header_cap)
            {
                size_t new_cap = header_cap ? header_cap*2 : 4;
                rh_request_header *nh = realloc(headers, new_cap * sizeof(*headers));
                if (!nh)
                {
                    fprintf(stderr, "[!] error: out of memory\n");
                    free(headers);
                    return 1;
                }
                headers = nh;
                header_cap = new_cap;
            }
            headers[header_count++] = h;
        }
        else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--data") == 0)
        {
            if (i+1 >= argc)
            {
                print_usage(argv[0]);
                free(headers);
                return 1;
            }
            if (have_data_file_buf)
            {
                rh_buf_free(&data_file_buf);
                have_data_file_buf = 0;
            }
            body = argv[++i];
            body_len = strlen(argv[i]);
        }
        else if (strcmp(argv[i], "--data-file") == 0)
        {
            if (i+1 >= argc)
            {
                print_usage(argv[0]);
                free(headers);
                return 1;
            }
            i++;
            rh_err fe = read_file_bytes(argv[i], &data_file_buf);
            if (fe != RH_OK)
            {
                fprintf(stderr, "[!] error: failed to read --data-file '%s': %s\n", argv[i], rh_strerror(fe));
                free(headers);
                return 1;
            }
            have_data_file_buf = 1;
            body = data_file_buf.data;
            body_len = data_file_buf.len;
        }
        else if (!url_str) url_str = argv[i];
        else 
        {
            print_usage(argv[0]);
            free(headers);
            if (have_data_file_buf) rh_buf_free(&data_file_buf);
            return 1;
        }
    }

    if (raw_file)
    {
        /*
         * raw mode ignores URL/method/header/body/flags entirely - free anything 
         * accidentally allocated by them before dispatching
         */
        free(headers);
        if (have_data_file_buf) rh_buf_free(&data_file_buf);
        return run_raw_mode(raw_file, target, convert_crlf, use_tls, insecure);
    }

    if (!url_str)
    {
        print_usage(argv[0]);
        free(headers);
        if (have_data_file_buf) rh_buf_free(&data_file_buf);
        return 1;
    }

    const char *method = method_arg ? method_arg : (body_len > 0 ? "POST" : "GET");

    rh_url url;
    rh_err err = rh_url_parse(url_str, &url);
    if(err != RH_OK)
    {
        LOG_ERR("[!] failed to parse '%s': %s", url_str, rh_strerror(err));
        free(headers);
        if (have_data_file_buf) rh_buf_free(&data_file_buf);
        return 1;
    }

    int is_https = strcmp(url.scheme, "https") == 0;

    int fd = -1;
    err = rh_tcp_connect(url.host, url.port, &fd);
    if (err != RH_OK)
    {
        LOG_ERR("[!] failed to connect to %s:%u: %s", url.host, url.port, rh_strerror(err));
        rh_url_free(&url);
        free(headers);
        if (have_data_file_buf) rh_buf_free(&data_file_buf);
        return 1;
    }
    LOG_INFO("[~] connected to %s:%u (fd=%d)", url.host, url.port, fd);

    rh_transport transport;
    
    if (is_https)
    {
        if (insecure) LOG_WARN("[~] --insecure: skipping TLS certificate verification");
        err = rh_transport_tls_init(&transport, fd, url.host, insecure);
        if (err != RH_OK)
        {
            LOG_ERR("[!] TLS handshake with %s failed: %s", url.host, rh_strerror(err));
            close(fd);
            rh_url_free(&url);
            free(headers);
            if (have_data_file_buf) rh_buf_free(&data_file_buf);
            return 1;
        }
        LOG_INFO("[~] TLS handshake with %s complete%s", url.host, insecure ? " (unverified)" : "");
    }
    else 
    {
        err = rh_transport_tcp_init(&transport, fd);
        if (err != RH_OK)
        {
            LOG_ERR("[!] failed to init transport: %s", rh_strerror(err));
            close(fd);
            rh_url_free(&url);
            free(headers);
            if (have_data_file_buf) rh_buf_free(&data_file_buf);
            return 1;
        }
    }

    rh_buf req;
    err = rh_buf_init(&req, 0);
    if (err != RH_OK)
    {
        LOG_ERR("[!] failed to allocate request buffer: %s", rh_strerror(err));
        goto cleanup_transport;
    }

    err = rh_request_build(method, &url, headers, header_count, body, body_len, 1, &req);
    if (err != RH_OK)
    {
        LOG_ERR("[!] failed to build request: %s", rh_strerror(err));
        goto cleanup_req;
    }

    err = rh_send_all(&transport, req.data, req.len);
    if (err != RH_OK)
    {
        LOG_ERR("[!] failed to send request: %s", rh_strerror(err));
        goto cleanup_req;
    }
    LOG_INFO("[~] sent %zu byte request", req.len);

    rh_buf raw;
    err = rh_buf_init(&raw, 0);
    if (err != RH_OK)
    {
        LOG_ERR("[!] failed to allicate response buffer: %s", rh_strerror(err));
        goto cleanup_req;
    }

    rh_response resp;
    size_t header_end;
    err = rh_response_read_headers(&transport, &raw, &resp, &header_end);
    if(err != RH_OK)
    {
        LOG_ERR("[!] failed to read response headers: %s", rh_strerror(err));
        goto cleanup_raw;
    }
    LOG_INFO("[~] parsed status %d, %zu headers", resp.status, resp.header_count);
    /*
     * pick body framing: chunked > Content_Length > read-until-close,
     * same precedence order real HTTP client use
     */
    {
        const char *te = rh_header_get(&resp, "Transfer-Encoding");
        const char *cl = rh_header_get(&resp, "Content-Length");

        if (te && header_equals_ci(te, "chunked"))
        {
            size_t cursor = header_end;
            err = rh_chunked_decode(&transport, &raw, &cursor, &resp);
        }
        else if (cl)
        {
            char *endptr = NULL;
            unsigned long long len = strtoull(cl, &endptr, 10);
            if (!endptr || *endptr != '\0' || endptr == cl)
            {
                LOG_ERR("[!] malformed Content-Length header; '%s'", cl);
                err = RH_ERR_PARSE;
            }
            else err = rh_response_read_body_content_length(&transport, &raw, header_end, &resp, (size_t)len);
        }
        else err = rh_response_read_body_until_close(&transport, &raw, header_end, &resp);
    }

    if (err != RH_OK)
    {
        LOG_ERR("[!] failed to read response body: %s", rh_strerror(err));
        goto cleanup_resp;
    }

    LOG_INFO("[~] received %zu byte body", resp.body.len);

    printf("HTTP/%d.%d %d %s\n", resp.http_major, resp.http_minor, resp.status, resp.reason);
    for (size_t i = 0; i < resp.header_count; i++)
        printf("%s: %s\n", resp.headers[i].name, resp.headers[i].value);
    printf("\n");
    fflush(stdout);
    /* raw dump - write() not printf(), so embedded NULs/binary bodies
     * pass through unmodified rather than truncating at the first NUL */

    if (resp.body.len > 0)
    {
        ssize_t written = write(STDOUT_FILENO, resp.body.data, resp.body.len);
        if(written < 0 || (size_t)written != resp.body.len)
        LOG_ERR("[!] failed to write full body to stdout");
    }


cleanup_resp:
    rh_response_free(&resp);
cleanup_raw:
    rh_buf_free(&raw);
cleanup_req:
    rh_buf_free(&req);
cleanup_transport:
    transport.close(&transport); // owns fd, closes it 
    rh_url_free(&url);
    free(headers);
    if (have_data_file_buf) rh_buf_free(&data_file_buf);

    return err == RH_OK ? 0 : 1;
} 
