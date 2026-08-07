#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "rawhttp/raw.h"

/* --- rh_raw_parse_target --- */

static void test_parse_target(void) {
    char *host = NULL;
    uint16_t port = 0;

    assert(rh_raw_parse_target("127.0.0.1:8080", &host, &port) == RH_OK);
    assert(strcmp(host, "127.0.0.1") == 0 && port == 8080);
    free(host);

    assert(rh_raw_parse_target("example.com:443", &host, &port) == RH_OK);
    assert(strcmp(host, "example.com") == 0 && port == 443);
    free(host);

    /* malformed inputs -> RH_ERR_PARSE, never a crash */
    assert(rh_raw_parse_target("no-port-here", &host, &port) == RH_ERR_PARSE);
    assert(rh_raw_parse_target(":8080", &host, &port) == RH_ERR_PARSE); /* empty host */
    assert(rh_raw_parse_target("host:", &host, &port) == RH_ERR_PARSE); /* empty port */
    assert(rh_raw_parse_target("host:abc", &host, &port) == RH_ERR_PARSE); /* non-numeric */
    assert(rh_raw_parse_target("host:999999", &host, &port) == RH_ERR_PARSE); /* out of range */

    printf("test_parse_target passed\n");
}

/* --- rh_raw_load_file --- */

static char *write_temp_file(const char *content, size_t len) {
    char *path = strdup("/tmp/rawhttp_raw_test_XXXXXX");
    int fd = mkstemp(path);
    assert(fd >= 0);
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, content + off, len - off);
        assert(n > 0);
        off += (size_t)n;
    }
    close(fd);
    return path;
}

static void test_load_file_passthrough(void) {
    /* deliberately weird bytes: existing CRLF, a lone LF, a NUL, and a
     * CR not followed by LF (all things a "helpful" library might
     * mangle - this mode must not touch ANY of it without --crlf) */
    const char payload[] = "GET / HTTP/1.1\r\nHost: x\r\n\nX-Weird\x00:\ry\r\n\r\n";
    size_t len = sizeof(payload) - 1;
    char *path = write_temp_file(payload, len);

    rh_buf out;
    rh_err e = rh_raw_load_file(path, /*convert_crlf=*/0, &out);
    printf("test_load_file_passthrough: %s, %zu bytes\n", rh_strerror(e), out.len);
    assert(e == RH_OK);
    assert(out.len == len);
    assert(memcmp(out.data, payload, len) == 0); /* byte-for-byte, no exceptions */

    rh_buf_free(&out);
    unlink(path);
    free(path);
    printf("test_load_file_passthrough passed\n");
}

static void test_load_file_crlf_convert(void) {
    /* mix of: existing \r\n (must stay exactly one \r\n, not become
     * \r\r\n), and lone \n (must become \r\n) */
    const char input[] = "line1\r\nline2\nline3\n";
    char *path = write_temp_file(input, sizeof(input) - 1);

    rh_buf out;
    rh_err e = rh_raw_load_file(path, /*convert_crlf=*/1, &out);
    assert(e == RH_OK);

    const char *expected = "line1\r\nline2\r\nline3\r\n";
    printf("test_load_file_crlf_convert: got %.*s\n", (int)out.len, out.data);
    assert(out.len == strlen(expected));
    assert(memcmp(out.data, expected, out.len) == 0);

    rh_buf_free(&out);
    unlink(path);
    free(path);
    printf("test_load_file_crlf_convert passed\n");
}

static void test_load_file_missing(void) {
    rh_buf out;
    rh_err e = rh_raw_load_file("/tmp/rawhttp_this_file_does_not_exist_at_all", 0, &out);
    printf("test_load_file_missing: %s\n", rh_strerror(e));
    assert(e == RH_ERR_IO);
    printf("test_load_file_missing passed\n");
}

/* --- rh_raw_send_and_dump: real TCP round trip, verifying the SERVER
 * actually receives byte-for-byte what we intended to send --- */

#define CANNED_RESPONSE "RAW-ECHO-OK\r\n"

/* Minimal TCP listener in a forked child: binds to an ephemeral port on
 * 127.0.0.1, sends the chosen port back to the parent over a pipe,
 * accepts one connection, reads until EOF, writes what it received (so
 * the PARENT can compare) into a second fixed-size report plus the
 * canned response, then exits. */
static void run_echo_server(int port_pipe_fd, int report_pipe_fd) {
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    assert(lfd >= 0);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0; /* let the OS pick a free port */
    assert(bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    assert(listen(lfd, 1) == 0);

    socklen_t alen = sizeof(addr);
    assert(getsockname(lfd, (struct sockaddr *)&addr, &alen) == 0);
    uint16_t port = ntohs(addr.sin_port);
    ssize_t wn = write(port_pipe_fd, &port, sizeof(port));
    assert(wn == (ssize_t)sizeof(port));
    close(port_pipe_fd);

    int cfd = accept(lfd, NULL, NULL);
    assert(cfd >= 0);
    close(lfd);

    char buf[8192];
    size_t total = 0;
    for (;;) {
        struct pollfd pfd = {.fd = cfd, .events = POLLIN};
        int pr = poll(&pfd, 1, 200); /* 200ms idle timeout - "no more data coming" */
        if (pr <= 0) {
            break; /* timeout or error: treat as end of what the client sent */
        }
        ssize_t n = read(cfd, buf + total, sizeof(buf) - total);
        if (n <= 0) {
            break;
        }
        total += (size_t)n;
        if (total >= sizeof(buf)) {
            break;
        }
    }

    /* report exactly what we received, length-prefixed, to the parent */
    uint32_t rlen = (uint32_t)total;
    wn = write(report_pipe_fd, &rlen, sizeof(rlen));
    assert(wn == (ssize_t)sizeof(rlen));
    if (total > 0) {
        wn = write(report_pipe_fd, buf, total);
        assert(wn == (ssize_t)total);
    }
    close(report_pipe_fd);

    send(cfd, CANNED_RESPONSE, strlen(CANNED_RESPONSE), 0);
    close(cfd);
    _exit(0);
}

static void test_send_and_dump_byte_exact(void) {
    int port_pipe[2], report_pipe[2];
    assert(pipe(port_pipe) == 0);
    assert(pipe(report_pipe) == 0);

    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        close(port_pipe[0]);
        close(report_pipe[0]);
        run_echo_server(port_pipe[1], report_pipe[1]);
    }
    close(port_pipe[1]);
    close(report_pipe[1]);

    uint16_t port = 0;
    ssize_t n = read(port_pipe[0], &port, sizeof(port));
    assert(n == (ssize_t)sizeof(port));
    close(port_pipe[0]);

    /* deliberately smuggling-shaped payload: conflicting-looking headers,
     * embedded CRLF-ish bytes in odd places - this is exactly the kind
     * of thing a "helpful" HTTP library would refuse to send verbatim */
    const char payload_str[] =
        "POST / HTTP/1.1\r\n"
        "Host: target\r\n"
        "Content-Length: 13\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "SMUGGLED";
    rh_buf payload;
    assert(rh_buf_init(&payload, 0) == RH_OK);
    assert(rh_buf_append(&payload, payload_str, sizeof(payload_str) - 1) == RH_OK);

    rh_buf response;
    rh_timing timing;
    rh_err e = rh_raw_send_and_dump("127.0.0.1", port, /*use_tls=*/0, /*insecure=*/0, &payload,
                                     &response, &timing);
    printf("test_send_and_dump_byte_exact: rh_raw_send_and_dump -> %s\n", rh_strerror(e));
    assert(e == RH_OK);
    printf("  timing: TTFB=%.2fms total=%.2fms\n", timing.ttfb_ms, timing.total_ms);
    assert(timing.ttfb_ms >= 0.0);      /* a response WAS received */
    assert(timing.total_ms >= timing.ttfb_ms); /* total can't finish before it started */

    /* what the SERVER actually saw must match our payload exactly */
    uint32_t server_saw_len = 0;
    n = read(report_pipe[0], &server_saw_len, sizeof(server_saw_len));
    assert(n == (ssize_t)sizeof(server_saw_len));
    char server_saw[8192];
    assert(server_saw_len <= sizeof(server_saw));
    size_t got = 0;
    while (got < server_saw_len) {
        n = read(report_pipe[0], server_saw + got, server_saw_len - got);
        assert(n > 0);
        got += (size_t)n;
    }
    close(report_pipe[0]);

    printf("  payload sent:   %zu bytes\n", payload.len);
    printf("  server received: %u bytes\n", server_saw_len);
    assert(server_saw_len == payload.len);
    assert(memcmp(server_saw, payload.data, payload.len) == 0);

    /* and what WE got back must match the canned response exactly */
    assert(response.len == strlen(CANNED_RESPONSE));
    assert(memcmp(response.data, CANNED_RESPONSE, response.len) == 0);

    rh_buf_free(&payload);
    rh_buf_free(&response);

    int status = 0;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    printf("test_send_and_dump_byte_exact passed (wire bytes == file bytes, confirmed server-side)\n");
}

/* --- rh_raw_send_sequence: two requests fired back-to-back on ONE
 * connection - the actual mechanism T3.3/smuggling confirmation needs.
 * Reuses run_echo_server: since payloads are sent with no waiting in
 * between, the server sees them as one continuous byte stream, same
 * as test_send_and_dump_byte_exact but built from two separate
 * rh_send_all calls instead of one buffer - which is exactly the
 * point being verified (multiple sends, one ordered stream, one
 * connection). */
static void test_send_sequence_one_connection(void) {
    int port_pipe[2], report_pipe[2];
    assert(pipe(port_pipe) == 0);
    assert(pipe(report_pipe) == 0);

    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        close(port_pipe[0]);
        close(report_pipe[0]);
        run_echo_server(port_pipe[1], report_pipe[1]);
    }
    close(port_pipe[1]);
    close(report_pipe[1]);

    uint16_t port = 0;
    ssize_t n = read(port_pipe[0], &port, sizeof(port));
    assert(n == (ssize_t)sizeof(port));
    close(port_pipe[0]);

    rh_buf payloads[2];
    assert(rh_buf_init(&payloads[0], 0) == RH_OK);
    assert(rh_buf_append(&payloads[0], "FIRST-REQUEST", 13) == RH_OK);
    assert(rh_buf_init(&payloads[1], 0) == RH_OK);
    assert(rh_buf_append(&payloads[1], "SECOND-REQUEST", 14) == RH_OK);

    rh_buf response;
    rh_timing timing;
    rh_err e = rh_raw_send_sequence("127.0.0.1", port, /*use_tls=*/0, /*insecure=*/0, payloads, 2,
                                     &response, &timing);
    printf("test_send_sequence_one_connection: rh_raw_send_sequence -> %s\n", rh_strerror(e));
    assert(e == RH_OK);
    printf("  timing: TTFB=%.2fms total=%.2fms\n", timing.ttfb_ms, timing.total_ms);
    assert(timing.ttfb_ms >= 0.0);
    assert(timing.total_ms >= timing.ttfb_ms);

    /* server independently confirms it saw BOTH payloads, concatenated
     * in order, over ONE accepted connection (it only calls accept()
     * once - had the client reconnected between sends, this whole
     * test would hang instead of completing, since nothing would be
     * listening for a second connection attempt) */
    uint32_t seen_len = 0;
    n = read(report_pipe[0], &seen_len, sizeof(seen_len));
    assert(n == (ssize_t)sizeof(seen_len));
    char seen[8192];
    assert(seen_len <= sizeof(seen));
    size_t got = 0;
    while (got < seen_len) {
        n = read(report_pipe[0], seen + got, seen_len - got);
        assert(n > 0);
        got += (size_t)n;
    }
    close(report_pipe[0]);

    printf("  server saw %u bytes (expected %zu)\n", seen_len, payloads[0].len + payloads[1].len);
    assert(seen_len == payloads[0].len + payloads[1].len);
    assert(memcmp(seen, payloads[0].data, payloads[0].len) == 0);
    assert(memcmp(seen + payloads[0].len, payloads[1].data, payloads[1].len) == 0);

    assert(response.len == strlen(CANNED_RESPONSE));
    assert(memcmp(response.data, CANNED_RESPONSE, response.len) == 0);

    rh_buf_free(&payloads[0]);
    rh_buf_free(&payloads[1]);
    rh_buf_free(&response);

    int status = 0;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    printf("test_send_sequence_one_connection passed (both payloads, one connection, in order)\n");
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IONBF, 0);

    test_parse_target();
    test_load_file_passthrough();
    test_load_file_crlf_convert();
    test_load_file_missing();
    test_send_and_dump_byte_exact();
    test_send_sequence_one_connection();

    printf("all T3.1/T3.3 raw mode checks passed\n");
    return 0;
}

