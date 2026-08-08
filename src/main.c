#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rawhttp_/buf.h"
#include "rawhttp_/chunked.h"
#include "rawhttp_/error.h"
#include "rawhttp_/fuzz.h"
#include "rawhttp_/io.h"
#include "rawhhtp_/raw.h"
#include "rawhttp_/request.h"
#include "rawhttp_/response.h"
#include "rawhttp_/smuggle.h"
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
            "       --timing            report TTFB/total time (all modes - a suspiciously slow\n)"
            "                           TTFB can signal a backend hanging on a desynced request.\n"
            "                           In --raw/--smuggle mode, 'total' includes the fixed idle-\n"
            "                           timeout wait for a possible delayed second response, so\n"
            "                           TTFB is the more reliable signal there; in normal mode,\n"
            "                           'total' reflects genuine response completion.\n"
            "\n"
            "raw mode - sends FILE's bytes verbatim, zero normalization:\n"
            "       --raw FILE          send FILE's bytes exactly as-is (no URL/headers/body flag apply)\n"
            "       --raw2 FILE         optional second payload, sent immediately after on the SAME connection\n"
            "       --target host:port  where to connect (required with --raw)\n"
            "       --crlf              convert lone '\\n' to \"\\r\\n\" before sending (existing \\r\\n untouched)\n"
            "       --tls               use TLS for the raw connection\n"
            "\n"
            "smuggling helper - generates and sends a CL.TE/TE.CL/CL.CL payload:\n"
            "       --smuggle TECH      cl.te | te.cl | cl.cl\n"
            "       --target host:port  where to connect (required with --smuggle\n)"
            "       --path PATH         request path (default: /)\n"
            "       --smuggle-host H    Host header value (default: the --target host)\n"
            "       --smuggled TEST     bytes left dangling for the desynced side (default: SMUGGLED)\n"
            "       --cl1 N             override the first Content-Length value\n"
            "       --cl2 N             override CL.CL's second Content-Length value\n"
            "       --probe             send a plain follow-up GET on the same connection after the \n"
            "                           payload - a wrong-looking response to it is what actually\n"
            "                           confirms a desync happend\n"
            "\n"
            "fuzzing - replays a mutation corpus against a template, diffs vs baseline:\n"
            "       --fuzz FILE         raw request template containing a marker to mutate\n"
            "       --target host:port  where to connect (required with --fuzz)\n"
            "       --marker STR        text in FILE to replace with each payload (default: FUZZ)\n"
            "                           (built-in corpus: long strings, controls chars, CRLF\n"
            "                           injection, path traversal, and a few other primitives)\n"
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

/* 
 * entirely separate code path from the normal URL-based flow:
 * no request building, no response parsing, just "send these exact
 * bytes, show me whatever comes back." */

/*
 * Shared by run_raw_mode and run_smuggle_mode: sends either one payload 
 * (rh_raw_send_and_dump) or two back-to-back on one connection
 * (rh_raw_send_sequence) then prints whatever comes back
 * */

static int send_and_report(const char *host, uint16_t port, int use_tls, int insecure, 
                    const rh_buf *payload1, const rh_buf *payload2, int show_timing)
{
    rh_buf response;
    rh_timing timing;
    rh_err err;
    if (payload2)
    {
        rh_buf payloads[2];
        payloads[0] = *payload1;
        payloads[1] = *payload2;
        err = rh_raw_send_sequence(host, port, use_tls, insecure, payloads, 2, &response, &timing);
    }
    else err = rh_raw_send_and_dump(host, port, use_tls, insecure, payload1, &response, &timing);

    if (err != RH_OK)
    {
        fprintf(stderr, "[!] error: %s\n", rh_strerror(err));
        return 1;
    }

    if (show_timing)
    {
        if (timing.ttfb_ms < 0.0)
            fprintf(stderr, "--- [~] timing: no response received ---\n");
        else 
            fprintf(stderr, "--- [~] timing: TTFB=%.1fms total=%.1fms ---\n", timing.ttfb_ms,
                    timing.total_ms);
    }

    fprintf(stderr, "--- received %zu bytes ---\n", response.len);
    ssize_t written = wrtie(STDOUT_FILENO, response.data, response.len);
    if (written < 0 || (size_t)written != response.len)
        LOG_ERR("[!] failed to write full response to stdout");
    rh_buf_free(&response);
    return 0;
}

/*
 * Builds a plain unambiguous GET request to use as the "probe" second request in --smuggle
 * --probe: a distinctive path makes it easy to recognize in the combained response whether
 *  it got a normal reply or something that looks like a desynced/mismatched one instead
 * */

static rh_err build_probe_request(const char *host_header, rh_buf *out)
{
    rh_err e = rh_buf_init(out, 0);
    if (e != RH_OK) return e;

    static const char prefix[] = "GET /rawhttp-probe HTTP/1.1\r\nHost: ";
    static const char suffix[] = "\r\nConnection: close\r\n\r\n";

    e = rh_buf_append(out, prefix, sizeof(prefix)-1);
    if (e  != RH_OK)
    {
        rh_buf_free(out);
        return e;
    }
    e = rh_buf_append(out, host_header, strlen(host_header));
    if (e  != RH_OK)
    {
        rh_buf_free(out);
        return e;
    }
    e = rh_buf_append(out, suffix, sizeof(suffix)-1);
    if (e  != RH_OK)
    {
        rh_buf_free(out);
        return e;
    }

    return RH_OK;
}

static int run_raw_mode(const char *raw_file, const char *raw_file2, const char *target,
                int convert_crlf, int use_tls, int insecure, int show_timing)
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

    rh_buf payload2;
    int have_payload2 = 0;
    if (raw_file2)
    {
        err = rh_raw_load_file(raw_file2, convert_crlf, &payload2);
        if (err != RH_OK)
        {
            fprintf(stderr, "[!] error: failed to load --raw2 file '%s': %s\n", rawfile2, 
                    rh_strerror(err));
            free(host);
            rh_buf_free(&payload);
            return 1;
        }
        have_payload2 = 1;
    }

    fprintf(stderr, "--- sending %zu bytes to %s:%u%s ---\n", payload.len, host, port,
            use_tls ? " (TLS)" : "");
    hex_dump(stderr, payload.data, payload.len);
    if (have_payload2)
    {
        fprintf(stderr, "--- then %zu more bytes (--raw), same connection ---\n", payload2.len);
        hex_dump(stderr, payload2.data, payload2.len);
    }

    int rc = send_and_report(host, port, use_tls, insecure, &payload, have_payload2 ? &payload2
                    : NULL, show_timing);
    free(host);
    rh_buf_free(&payload);
    if (have_payload2) rh_buf_free(&payload2);
    return rc;
}

/*
 * builds a CL.TE/TE.CL/CL.CL payload then sends it exactly like raw mode does
 * (same connect/sned/dump-response infrastructure - the only difference from
 * --raw is where the bytes come from).
 * --probe optionally fires a plain follow-up GET on the same connection right
 *  after, which is the actual confirmation technique - a mismatched/wrong-looking
 *  response to the probe is what proves the desync, not anything visible in the 
 *  smuggling payload's own response.
 * */

static int run_smuggle_mode(const char *technique_name, const char *target,
                    const char *path, const char *smuggle_host, const char *smuggled,
                    long cl1, long cl2, int probe, int use_tls, int insecure, int show_timing)
{
    if (!target)
    {
        fprintf(stderr, "[!] error: --smuggle requires --target host:port\n");
        return 1;
    }

    rh_smuggle_technique technique;
    rh_err err = rh_smuggle_parse_technique(technique_name, &technique);
    if (err != RH_OK)
    {
        fprintf(stderr, "[!] error: unknown --smuggle technique '%s' (want cl.te, te.cl, cl.cl)\n", technique_name);
        return 1;
    }

    char *host                  = NULL;
    uint16_t port               = 0;
    err                         = rh_raw_parse_target(target, &host, &port);
    if (err != RH_OK)
    {
        fprintf(stderr, "[!] error: invalid --target '%s': %s\n", target, rh_strerror(err));
        return 1;
    }

    const char *host_header = smuggle_host ? smuggle_host : host;

    rh_buf payload;
    err = rh_smuggle_build(technique, host_header, path, smuggled, cl1, cl2, &payload);
    if (err != RH_OK)
    {
        fprintf(stderr, "[!] failed to build smuggling payload: %s\n", rh_strerror(err));
        free(host);
        return 1;
    }
    
    rh_buf probe_req;
    int have_probe = 0;
    if (probe)
    {
        err = build_probe_request(host_header, &probe_req);
        if (err != RH_OK)
        {
            fprintf(stderr, "[!] error: failed to build probe request: %s\n", rh_strerror(err));
            free(host);
            rh_buf_free(&payload);
            return 1;
        }
        have_probe = 1;
    }

    fprintf(stderr, "--- %s payload, sending %zu bytes to %s:%u%s ---\n", technique_name,
            payload.len, host, port, use_tls ? " (TLS)" : "");
    hex_dump(stderr, payload.data, payload_len);
    if (have_probe)
    {
        fprintf(stderr, "--- then a probe request, same connection ---\n");
        hex_dump(stderr, probe_req.data, probe_request.len);
    }

    int rc = send_and_report(host, port, use_tls, insecure, &payload, have_probe ? &probe_req : NULL, show_timing);
    free(host);
    rh_buf_free(&payload);
    if (have_probe) rh_buf_free(&probe_req);

    return rc;
}

/*
 * Best-effort peek at a raw response's status code, for fuzz-report purposes only - NOT the
 * real parser (resoponse.c), and deliberately so: this needs to tolerate garbage/partial
 * /non-HTTP responses without erroring, since that's exactly what a fuzzed request migth 
 * provoke. Returns -1 if it doesn't look like a status line at all.
 * */

static int peek_status_code(const rh_buf *reponse)
{
    if (response->len < 12 || strncmp(response->data, "HTTP/", 5) != 0) return -1;
    size_t i = 5;
    while (i < response->len && reponse->data[i] != ' ') 
    {
        i++;
    }
    i++; // skip the space
    
    if (i + 3 > response->len) return -1;
    if (!isdigit((unsigned char)response->data[i]) || !isdigit((unsigned char)response->data[i+1])
            || !isdigit((unsigned char)response->data[i+2])) return -1;
    return (response->data[i]-'0')*100 + (response->data[i+1]-'0')*10 + (response->data[i+2]-'0');
}

/* replays the built-in mutation corups against `tmpl` (with `marker` substituted each time),
 * comparing every result to a baseline (the template with marker replaced by a neutral value)
 * and flagging anything thata looks different: status code, response length (beyond a 10%
 * or 50 byte toleraance), or TTFB (beyond 3x baseline + 200ms). These thersholds are heuristics
 * for catching a human's attention, not a verdict - the raw numbers are printed for every 
 * mutation so the user can judge for themselves.
 * */

static int run_fuzz_mode(const char *fuzz_file, const char *target, const char *marker,
                    int convert_crlf, int use_tls, int insecure)
{
    if (!target)
    {
        fprintf(stderr, "[!] error: --fuzz requires --target host:port\n");
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

    rh_buf tmpl;
    err = rh_raw_load_file(fuzz_file, convert_crlf, &tmpl);
    if (err != RH_OK)
    {
        fprintf(stderr, "[!] error: failed to load --fuzz file '%s': %s\n", fuzz_file,
                rh_strerror(err));
        free(host);
        return 1;
    }

    rh_buf baseline_req; 
    err = rh_fuzz_apply(&tmpl, marker, "baseline", 8, &baseline_req);
    if (err != RH_OK)
    {
        fprintf(stderr, "[!] error: failed to build baseline request: %s\n", rh_strerror(err));
        free(host);
        rh_buf_free(&tmpl);
        return 1;
    }

    rh_buf baseline_resp;
    rh_timing baseline_timing;
    rh_err baseline_err = 
        rh_raw_send_and_dump(host, port, use_tls, insecure, &baseline_req, &baseline_resp,
                &baseline_timing);
    int baseline_status = baseline_err == RH_OK ? peek_status_code(&baseline_resp) : -1;
    size_t baseline_len = baseline_err == RH_OK ? baseline_resp.len : 0;
    double baseline_ttfb = baseline_err == RH_OK ? baseline_timing.ttfb_ms : -1.0;

    fprintf(stderr, "=== baseline (marker replaced with a neutral placeholder) ===\n");
    if (baseline_err != RH_OK)
    {
        fprintf(stderr, "baseline request failed: %s - mutations will still run, but every\n"
                "comparison against this baseline is meaningless. Fix connectivity\n"
                "first.\n", rh_strerror(baseline_err));
    }
    else 
    {
        fprintf(stderr, "status=%d len=%zu TTFB=%.1fms total=%.1fms\n\n", baseline_status,
                baseline_len, baseline_timing.ttfb_ms, baseline_timing.total_ms);
    }
    if (baseline_err == RH_OK) rh_buf_free(&baseline_resp);
    rh_buf_free(&baseline_req);

    const rh_fuzz_payload *payloads = NULL;
    size_t payload_count = rh_fuzz_default_payloads(&payloads);
    fprintf(stderr, "%-20s %8s %10s %10s %10s  %s\n", "MUTATION", "STATUS", "LEN", "TTFB(ms)",
            "TOTAL(ms)", "FLAGS");

    size_t anomaly_count = 0;
    for (size_t i = 0; i < payload_count; i++)
    {
        rh_buf mutated;
        err = rh_fuzz_apply(&tmpl, marker, payloads[i].data, payloads[i].len, &mutated);
        if (err != RH_OK)
        {
            fprintf(stderr, "%-20s ([!] failed to build mutated request: %s)\n", payloads[i].label,
                    rh_strerror(err));
            continue;
        }

        rh_buf resp;
        rh_timing timing;
        rh_err send_err = 
            rh_raw_send_and_dump(host, port, use_tls, insecure, &mutated, &resp, &timing);
        int status              = send_err == RH_OK ? peek_status_code(&resp) : -1;
        size_t len              = send_err == RH_OK ? resp.len : 0;
        double ttfb             = send_err == RH_OK ? timing.ttfb_ms : -1.0;
        double total            = send_err == RH_OK ? timing.total_ms : -1.0;
        
        int status_differs      = send_err == RH_OK && status != baseline_status;
        long len_diff           = (long)len - (long)baseline_len;
        size_t len_threshold    = baseline_len / 10 > 50 ? baseline_len / 10 : 50;
        int len_differs         = send_err == RH_OK && (size_t)(len_diff < 0 ? -len_diff : len_diff)
            > len_threshold;
        int timing_anomaly      = send_err == RH_OK && baseline_err == RH_OK && ttfb > baseline_ttfb
            *3.0 +200.0;
        int is_anomaly          = send_err != RH_OK || status_differs || len_differs || timing_anomaly;
        
        char flags[80];
        flags[0] = '\0';
        if (send_err != RH_OK) strcat(flags, "[send-failed]");
        if (status_differs) strcat(flags, "[status]");
        if (len_differs) strcat(flags, "[length]");
        if (timing_anomaly) strcat(flags, "[timing]");
        
        if (send_err == RH_OK) 
        {
            fprintf(stderr, "%-20s %8d %10zu %10.1f %10.1f  %s\n", payloads[i].label, status, len,
                    ttfb, total, flags);
        }
        else 
        {
            fprintf(stderr, "%-20s %8s %10s %10s %10s  %s(%s)\n", payloads[i].label, "-", "-",
                    "-", "-", flags, rh_strerror(send_err));
        }

        if (is_anomaly) anomaly_count++;
        if (send_err == RH_OK) rh_buf_free(&resp);
        rh_buf_free(&mutated);
    }

    fprintf(stderr, "\n%zu/%zu mutations flagged (differ from baseline in status, length, or timing)\n",
            anomaly_count, payload_count);
    free(host);
    rh_buf_free(&tmpl);
    return 0;
}

signed main(int argc, char** argv)
{
    signal(SIGPIPE, SIG_IGN);

    int insecure                        = 0;
    const char *url_str                 = NULL;
    const char *method_arg              = NULL;

    const char *raw_file                = NULL;
    const char *raw_file2               = NULL;
    const char *target                  = NULL;
    int convert_crlf                    = 0;
    int use_tls                         = 0;

    const char *smuggle_technique       = NULL;
    const char *smuggle_parh            = "/";
    const char *smuggle_host            = NULL;
    const char *smuggled                = "SMUGGLED";
    long cl1                            = -1;
    long cl2                            = -1;
    int probe                           = 0;
    int show_timing                     = 0;

    rh_request_header *headers          = NULL;
    size_t header_count                 = 0;
    size_t header_cap                   = 0;

    const void *body                    = NULL;
    size_t body_len                     = 0;
    rh_buf data_file_buf;
    int have_data_file_buf              = 0;

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
        else if (strcmp(argv[i], "--raw2") == 0)
        {
            if (i+1 >= argc)
            {
                print_usage(argv[0]);
                free(headers);
                return 1;
            }
            raw_file2 = argv[++i];
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
        else if (strcmp(argv[i], "--smuggle") == 0)
        {
            if (i+1 >= argc)
            {
                print_usage(argv0);
                free(headers);
                return 1;
            }
            smuggle_technique = argv[++i];
        }
        else if (strcmp(argv[i], "--path") == 0)
        {
            if (i+1 >= argc)
            {
                print_usage(argv[0]);
                free(headers);
                return 1;
            }
            smuggle_path = argv[++i];
        }
        else if (strcmp(argv[i], "--smuggle-host") == 0)
        {
            if (i+1 >= argc)
            {
                print_usage(argv[0]);
                free(headers);
                return 1;
            }
            smuggle_host = argv[++i];
        }
        else if (strcmp(argv[i], "--smuggled") == 0)
        {
            if (i+1 >= argc)
            {
                print_usage(argv[0]);
                free(headers);
                return 1;
            }
            smuggled = argv[++i];
        }
        else if (strcmp(argv[i], "--cl1") == 0)
        {
            if (i+1 >= argc)
            {
                print_usage(argv[0]);
                free(headers);
                return 1;
            }
            cl1 = strtol(argv[++i], NULL, 10);
        }
        else if (strcmp(argv[i], "--cl2") == 0)
        {
            if (i+1 >= argc)
            {
                print_usage(argv[0]);
                free(headers);
                return 1;
            }
            cl2 = strtol(argv[++i], NULL, 10);
        }
        else if (strcmp(argv[i], "--probe") == 0) probe = 1;
        else if (strcmp(argv[i], "--timing") == 0) show_timing = 1;
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

    if (raw_file && smuggle_technique)
    {
        fprintf(stderr, "[!] error: --raw and --smuggle are mutually exclusive\n");
        free(headers);
        if (have_data_file_buf) rh_buf_free(&data_file_buf);
        return 1;
    }

    if (raw_file)
    {
        /*
         * raw mode ignores URL/method/header/body/flags entirely - free anything 
         * accidentally allocated by them before dispatching
         */
        free(headers);
        if (have_data_file_buf) rh_buf_free(&data_file_buf);
        return run_raw_mode(raw_file, raw_file2, target, convert_crlf, use_tls, insecure, show_timing);
    }

    if (smuggle_technique)
    {
        free(headers);
        if (have_data_file_buf) rh_buf_free(&data_file_buf);
        return run_smuggle_mode(smuggle_target, target, smuggle_path, smuggle_host,
                smuggled, cl1, cl2, probe, use_tls, insecure, show_timing);
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
    struct timespec t_connect;
    clock_gettime(CLOCK_MONOTONIC, &t_connect);

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

    if (show_timing)
    {
        struct timespec t_end;
        clock_gettime(CLOCK_MONOTONIC, &t_end);
        if (transport.first_byte_recorded)
        {
            double ttfb_ms = rh_timespec_diff_ms(&t_connect, &transport.first_byte_at);
            double total_ms = rh_timespec_diff_ms(&t_connect, &t_end);
            fprintf(stderr, "--- [~] timing: TTFB=%.1fms total=%.1fms ---\n", ttfb_ms, total_ms);
        }
        else fprintf(stderr, "--- [~] timing: no response received ---\n");
    }

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
